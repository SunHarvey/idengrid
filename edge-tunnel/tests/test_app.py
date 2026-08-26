import asyncio
import base64
import hashlib
import hmac
import json
import time

import pytest
from aiohttp import ClientResponseError, WSMsgType
from aiohttp.test_utils import TestClient, TestServer
from edge_tunnel.app import RESOURCE_PROVIDER, CachedPublicIPv4, Settings, create_app
from edge_tunnel.resources import LinuxResourceProvider, WindowsResourceProvider
from edge_tunnel.targets import ResolvedTarget


def make_ticket(secret: bytes, *, jti="ticket-1", host="example.com", port=443):
    now = int(time.time())
    payload = {
        "v": 1,
        "node": "edge-sg01",
        "store": "store-42",
        "host": host,
        "port": port,
        "iat": now,
        "exp": now + 30,
        "jti": jti,
    }
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
        )
        .rstrip(b"=")
        .decode()
    )
    signature = (
        base64.urlsafe_b64encode(hmac.new(secret, encoded.encode(), hashlib.sha256).digest())
        .rstrip(b"=")
        .decode()
    )
    return f"{encoded}.{signature}"


class Policy:
    def __init__(self):
        self.calls = []

    def resolve(self, host, port):
        self.calls.append((host, port))
        return ResolvedTarget(host, port, "93.184.216.34", 2)


@pytest.mark.asyncio
async def test_public_ipv4_is_cached_for_a_short_ttl_and_refresh_failure_is_not_stale():
    now = 100.0
    answers = iter(["8.8.8.8", OSError("lookup unavailable")])
    calls = 0

    async def fetch():
        nonlocal calls
        calls += 1
        answer = next(answers)
        if isinstance(answer, Exception):
            raise answer
        return answer

    provider = CachedPublicIPv4(fetch, ttl_seconds=60, clock=lambda: now)

    assert await provider() == "8.8.8.8"
    assert await provider() == "8.8.8.8"
    assert calls == 1
    now = 161.0
    with pytest.raises(OSError, match="lookup unavailable"):
        await provider()
    assert calls == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("answer", ["10.0.0.1", "2001:4860:4860::8888", "not-an-ip"])
async def test_public_ipv4_provider_rejects_non_global_or_non_ipv4_answers(answer):
    async def fetch():
        return answer

    provider = CachedPublicIPv4(fetch)

    with pytest.raises(ValueError, match="global IPv4"):
        await provider()


def test_linux_resource_provider_parses_proc_and_statvfs_bytes():
    proc = {
        "/proc/loadavg": "0.42 0.20 0.10 1/100 99\n",
        "/proc/meminfo": "MemTotal: 4194304 kB\nMemAvailable: 3145728 kB\n",
        "/proc/uptime": "12345.67 456.00\n",
    }

    class Vfs:
        f_frsize = 4096
        f_blocks = 25_000_000
        f_bavail = 20_000_000

    provider = LinuxResourceProvider(read_text=lambda path: proc[path], statvfs=lambda path: Vfs())

    assert provider() == {
        "load_1m": 0.42,
        "memory_total_bytes": 4_294_967_296,
        "memory_available_bytes": 3_221_225_472,
        "disk_total_bytes": 102_400_000_000,
        "disk_free_bytes": 81_920_000_000,
        "uptime_seconds": 12_345.67,
    }


@pytest.fixture
def settings():
    return Settings(
        node_id="edge-sg01",
        ticket_secret=b"s" * 32,
        max_connections=2,
        max_frame_bytes=1024,
        max_bytes_per_connection=4096,
        idle_timeout=2,
        max_connection_seconds=5,
        connect_timeout=1,
        ticket_max_ttl=60,
    )


def test_create_app_automatically_selects_platform_resource_provider(settings, monkeypatch):
    selected = WindowsResourceProvider(psutil_module=object())
    monkeypatch.setattr("edge_tunnel.app.create_resource_provider", lambda: selected)

    app = create_app(settings)

    assert app[RESOURCE_PROVIDER] is selected


@pytest.mark.asyncio
async def test_health_and_status_expose_only_nonsecret_operational_data(settings):
    async def public_ipv4():
        return "198.51.100.20"

    def resources():
        return {
            "load_1m": 0.25,
            "memory_total_bytes": 4_294_967_296,
            "memory_available_bytes": 3_221_225_472,
            "disk_total_bytes": 107_374_182_400,
            "disk_free_bytes": 85_899_345_920,
            "uptime_seconds": 12_345.5,
        }

    app = create_app(settings, public_ipv4_provider=public_ipv4, resource_provider=resources)
    async with TestClient(TestServer(app)) as client:
        health = await (await client.get("/healthz")).json()
        status = await (await client.get("/status")).json()

    assert health == {"status": "ok", "node": "edge-sg01"}
    assert status == {
        "node": "edge-sg01",
        "active_connections": 0,
        "max_connections": 2,
        "accepted_connections": 0,
        "denied_connections": 0,
        "public_ipv4": "198.51.100.20",
        "load_1m": 0.25,
        "memory_total_bytes": 4_294_967_296,
        "memory_available_bytes": 3_221_225_472,
        "disk_total_bytes": 107_374_182_400,
        "disk_free_bytes": 85_899_345_920,
        "uptime_seconds": 12_345.5,
        "agent_version": "1.0.0",
    }
    assert "secret" not in json.dumps(status).lower()


@pytest.mark.asyncio
async def test_status_fails_when_public_ipv4_refresh_fails(settings):
    async def failed_lookup():
        raise TimeoutError("external details must not escape")

    app = create_app(
        settings,
        public_ipv4_provider=failed_lookup,
        resource_provider=dict,
    )
    async with TestClient(TestServer(app)) as client:
        response = await client.get("/status")
        body = await response.text()

    assert response.status == 503
    assert body == "status unavailable"


@pytest.mark.asyncio
async def test_status_fails_closed_when_resource_collection_fails(settings):
    async def public_ipv4():
        return "198.51.100.20"

    def failed_resources():
        raise OSError("sensitive local detail")

    app = create_app(
        settings,
        public_ipv4_provider=public_ipv4,
        resource_provider=failed_resources,
    )
    async with TestClient(TestServer(app)) as client:
        response = await client.get("/status")
        body = await response.text()

    assert response.status == 503
    assert body == "status unavailable"


@pytest.mark.asyncio
async def test_tunnel_requires_bearer_capability_before_dns_or_connect(settings):
    policy = Policy()
    app = create_app(settings, policy=policy)
    async with TestClient(TestServer(app)) as client:
        response = await client.get("/v1/tunnel")

    assert response.status == 401
    assert policy.calls == []


@pytest.mark.asyncio
async def test_authenticated_websocket_relays_binary_to_vetted_numeric_target(settings):
    policy = Policy()
    received = bytearray()

    async def echo(reader, writer):
        data = await reader.read(1024)
        received.extend(data)
        writer.write(b"reply:" + data)
        await writer.drain()
        writer.close()
        await writer.wait_closed()

    server = await asyncio.start_server(echo, "127.0.0.1", 0)
    actual_port = server.sockets[0].getsockname()[1]
    connector_calls = []

    async def connector(address, port, family):
        connector_calls.append((address, port, family))
        return await asyncio.open_connection("127.0.0.1", actual_port)

    app = create_app(settings, policy=policy, connector=connector)
    token = make_ticket(settings.ticket_secret)
    try:
        async with TestClient(TestServer(app)) as client:
            ws = await client.ws_connect("/v1/tunnel", headers={"Authorization": f"Bearer {token}"})
            await ws.send_bytes(b"hello")
            message = await ws.receive(timeout=2)
            await ws.close()
    finally:
        server.close()
        await server.wait_closed()

    assert message.type == WSMsgType.BINARY
    assert message.data == b"reply:hello"
    assert received == b"hello"
    assert policy.calls == [("example.com", 443)]
    assert connector_calls == [("93.184.216.34", 443, 2)]


@pytest.mark.asyncio
async def test_ticket_is_one_use_and_cannot_open_a_different_target(settings):
    policy = Policy()

    async def connector(*_):
        return asyncio.StreamReader(), NullWriter()

    app = create_app(settings, policy=policy, connector=connector)
    token = make_ticket(settings.ticket_secret, host="example.com", port=80)
    async with TestClient(TestServer(app)) as client:
        ws = await client.ws_connect("/v1/tunnel", headers={"Authorization": f"Bearer {token}"})
        await ws.close()
        with pytest.raises(ClientResponseError) as error:
            await client.ws_connect("/v1/tunnel", headers={"Authorization": f"Bearer {token}"})

    assert error.value.status == 401
    assert policy.calls == [("example.com", 80)]


class NullWriter:
    def write(self, _data):
        pass

    async def drain(self):
        pass

    def close(self):
        pass

    async def wait_closed(self):
        pass
