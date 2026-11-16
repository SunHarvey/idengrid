"""Offline capacity lifecycle regressions against the real tunnel/relay/runtime.

Only the WebSocket transport, target policy, and TCP streams are substituted; no
external DNS, service, or production credentials are used.
"""

import asyncio
import base64
import hashlib
import hmac
import json
import threading
import time
from types import SimpleNamespace

import pytest
from aiohttp import WSMsgType, web
from edge_tunnel import app as edge
from edge_tunnel.config import Settings
from edge_tunnel.targets import ResolvedTarget


class Writer:
    def __init__(self, *, close_error=False, wait_error=False, wait_gate=None):
        self.close_error = close_error
        self.wait_error = wait_error
        self.wait_gate = wait_gate
        self.wait_entered = asyncio.Event()
        self.close_calls = 0
        self.wait_calls = 0

    def write(self, data):
        pass

    async def drain(self):
        pass

    def close(self):
        self.close_calls += 1
        if self.close_error:
            raise ConnectionResetError("synthetic close reset")

    async def wait_closed(self):
        self.wait_calls += 1
        self.wait_entered.set()
        if self.wait_gate is not None:
            await self.wait_gate.wait()
        if self.wait_error:
            raise ConnectionResetError("synthetic wait reset")


class Reader:
    def __init__(self, *, gate=None, chunks=()):
        self.gate = gate
        self.chunks = iter(chunks)
        self.entered = asyncio.Event()

    async def read(self, size):
        self.entered.set()
        if self.gate is not None:
            await self.gate.wait()
        return next(self.chunks, b"")


class WS:
    def __init__(self, *, receive_gate=None, prepare_error=False, send_error=False):
        self.receive_gate = receive_gate
        self.prepare_error = prepare_error
        self.send_error = send_error
        self.receive_entered = asyncio.Event()

    async def prepare(self, request):
        if self.prepare_error:
            raise OSError("synthetic websocket preparation failure")
        return self

    async def receive(self):
        self.receive_entered.set()
        if self.receive_gate is not None:
            await self.receive_gate.wait()
        return SimpleNamespace(type=WSMsgType.CLOSE)

    async def send_bytes(self, data):
        if self.send_error:
            raise OSError("synthetic relay send failure")

    async def close(self, **kwargs):
        pass


class Policy:
    def __init__(self, started=None, gate=None):
        self.started = started
        self.gate = gate

    def resolve(self, host, port):
        if self.started is not None:
            self.started.set()
        if self.gate is not None and not self.gate.wait(3):
            raise TimeoutError("test DNS gate never opened")
        return ResolvedTarget(host, port, "127.0.0.1", 2)


@pytest.fixture
def harness(monkeypatch):
    secret = b"only-local-test-secret-32-bytes-long"
    settings = Settings(
        node_id="local-only",
        ticket_secret=secret,
        max_connections=1,
        max_frame_bytes=1024,
        max_bytes_per_connection=4096,
        idle_timeout=2,
        max_connection_seconds=3,
        connect_timeout=1,
    )
    state = SimpleNamespace(writer=Writer(), reader=Reader(), ws=WS(), calls=0, serial=0)

    async def connector(address, port, family):
        assert (address, port, family) == ("127.0.0.1", 443, 2)
        state.calls += 1
        return state.reader, state.writer

    async def no_public_network():
        raise AssertionError("external provider called")

    state.app = edge.create_app(
        settings,
        policy=Policy(),
        connector=connector,
        public_ipv4_provider=no_public_network,
        resource_provider=dict,
    )
    state.runtime = state.app[edge.RUNTIME]
    state.releases = 0
    original_release = state.runtime.release

    def counted_release():
        state.releases += 1
        original_release()

    monkeypatch.setattr(state.runtime, "release", counted_release)
    monkeypatch.setattr(edge.web, "WebSocketResponse", lambda **kwargs: state.ws)

    def request():
        state.serial += 1
        now = int(time.time())
        payload = {
            "v": 1,
            "node": settings.node_id,
            "store": "local-store",
            "host": "dummy.invalid",
            "port": 443,
            "iat": now,
            "exp": now + 30,
            "jti": f"local-{state.serial}",
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
        signature = hmac.new(secret, encoded.encode("ascii"), hashlib.sha256).digest()
        token = encoded + "." + base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        return SimpleNamespace(app=state.app, headers={"Authorization": f"Bearer {token}"})

    state.invoke = lambda: edge.tunnel(request())
    return state


def assert_released_once(harness):
    assert harness.runtime.active == 0
    assert harness.releases == 1


def test_release_without_acquisition_cannot_make_capacity_negative():
    runtime = edge.Runtime(max_connections=1)
    with pytest.raises(RuntimeError, match="release without acquisition"):
        runtime.release()
    assert runtime.active == 0


@pytest.mark.asyncio
async def test_normal_relay_releases_one_acquired_slot(harness):
    await asyncio.wait_for(harness.invoke(), 2)
    assert_released_once(harness)
    assert harness.runtime.accepted == 1
    assert harness.writer.close_calls >= 1
    assert harness.writer.wait_calls >= 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["close_error", "wait_error"])
async def test_relay_writer_cleanup_error_releases_one_acquired_slot(harness, failure):
    setattr(harness.writer, failure, True)
    try:
        await asyncio.wait_for(harness.invoke(), 2)
    except ConnectionResetError:
        pass  # Cleanup may propagate its own error, but must never strand capacity.
    assert_released_once(harness)
    assert harness.runtime.accepted == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["close_error", "wait_error"])
async def test_outer_cleanup_error_preserves_original_failure_and_releases(harness, failure):
    setattr(harness.writer, failure, True)
    harness.ws.prepare_error = True
    with pytest.raises(web.HTTPBadGateway) as error:
        await asyncio.wait_for(harness.invoke(), 2)
    assert error.value.text == "target connection failed"
    assert_released_once(harness)
    assert harness.runtime.denied == 1
    assert harness.runtime.accepted == 0


@pytest.mark.asyncio
async def test_relay_send_failure_and_wait_reset_preserve_original_failure(harness):
    harness.ws.receive_gate = asyncio.Event()
    harness.ws.send_error = True
    harness.reader = Reader(chunks=[b"local-data"])
    harness.writer.wait_error = True
    with pytest.raises(web.HTTPBadGateway) as error:
        await asyncio.wait_for(harness.invoke(), 2)
    assert error.value.text == "target connection failed"
    assert_released_once(harness)
    assert harness.runtime.accepted == 1
    assert harness.runtime.denied == 1


@pytest.mark.asyncio
async def test_cancel_during_outer_cleanup_releases_one_acquired_slot(harness):
    harness.ws.prepare_error = True
    harness.writer.wait_gate = asyncio.Event()
    task = asyncio.create_task(harness.invoke())
    try:
        await asyncio.wait_for(harness.writer.wait_entered.wait(), 2)
        assert harness.runtime.active == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert_released_once(harness)
    finally:
        harness.writer.wait_gate.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_non_finishing_outer_wait_closed_does_not_hold_capacity_forever(harness):
    harness.ws.prepare_error = True
    harness.writer.wait_gate = asyncio.Event()  # Never opened until teardown.
    task = asyncio.create_task(harness.invoke())
    try:
        await asyncio.wait_for(harness.writer.wait_entered.wait(), 2)
        assert harness.runtime.active == 1  # Pending close is not itself a leak.
        with pytest.raises(web.HTTPBadGateway) as error:
            await asyncio.wait_for(task, 2)
        assert error.value.text == "target connection failed"
        assert_released_once(harness)
    finally:
        harness.writer.wait_gate.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["close", "timeout", "cancel"])
async def test_failed_or_stalled_close_aborts_real_tcp_transport_before_releasing(harness, failure):
    peer_closed = asyncio.Event()
    peer_finished = asyncio.Event()
    wait_entered = asyncio.Event()
    wait_finished = asyncio.Event()

    async def peer(reader, writer):
        try:
            await reader.read()
            peer_closed.set()
        finally:
            writer.close()
            await writer.wait_closed()
            peer_finished.set()

    server = await asyncio.start_server(peer, "127.0.0.1", 0)
    tcp_writer = None
    try:
        _, tcp_writer = await asyncio.open_connection(*server.sockets[0].getsockname())
        real_writer = tcp_writer

        class BrokenClose:
            transport = real_writer.transport

            def close(self):
                if failure == "close":
                    raise ConnectionResetError("synthetic close failure")
                # A faulty close that returns without shutting down the socket.

            async def wait_closed(self):
                wait_entered.set()
                try:
                    await real_writer.wait_closed()
                finally:
                    wait_finished.set()

        harness.writer = BrokenClose()
        harness.ws.prepare_error = True
        if failure == "cancel":
            task = asyncio.create_task(harness.invoke())
            await asyncio.wait_for(wait_entered.wait(), 2)
            assert harness.runtime.active == 1
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
        else:
            with pytest.raises(web.HTTPBadGateway):
                await asyncio.wait_for(harness.invoke(), 3)
        assert tcp_writer.transport.is_closing(), "capacity freed while TCP transport is open"
        await asyncio.wait_for(peer_closed.wait(), 1)
        await asyncio.wait_for(wait_finished.wait(), 1)
        assert_released_once(harness)
    finally:
        if tcp_writer is not None:
            tcp_writer.transport.abort()
            await asyncio.wait_for(peer_finished.wait(), 1)
        server.close()
        await server.wait_closed()


@pytest.mark.asyncio
async def test_non_finishing_relay_wait_closed_does_not_hold_capacity_forever(harness):
    harness.writer.wait_gate = asyncio.Event()  # The relay completes; only close stalls.
    task = asyncio.create_task(harness.invoke())
    try:
        await asyncio.wait_for(harness.writer.wait_entered.wait(), 2)
        assert harness.runtime.active == 1
        _, pending = await asyncio.wait((task,), timeout=3)
        assert not pending, "relay cleanup never completed its bounded close"
        task.result()
        assert_released_once(harness)
        assert harness.runtime.accepted == 1
    finally:
        harness.writer.wait_gate.set()
        if not task.done():
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_next_tunnel_is_admitted_after_faulty_cleanup(harness):
    harness.ws.prepare_error = True
    harness.writer.wait_error = True
    with pytest.raises((ConnectionResetError, web.HTTPBadGateway)):
        await asyncio.wait_for(harness.invoke(), 2)
    # Admission, not the cleanup exception shape, is the assertion below.
    harness.ws = WS()
    harness.writer = Writer()
    await asyncio.wait_for(harness.invoke(), 2)
    assert harness.runtime.active == 0
    assert harness.releases == 2
    assert harness.runtime.accepted == 1
    assert harness.calls == 2


@pytest.mark.asyncio
async def test_denial_before_acquisition_never_releases_or_goes_negative(harness):
    harness.runtime.max_connections = 0
    with pytest.raises(web.HTTPServiceUnavailable) as error:
        await asyncio.wait_for(harness.invoke(), 2)
    assert error.value.text == "connection capacity reached"
    assert harness.runtime.active == 0
    assert harness.releases == 0
    assert harness.runtime.accepted == 0
    assert harness.calls == 0


@pytest.mark.asyncio
async def test_concurrent_request_cannot_enter_during_a_live_relay(harness):
    harness.ws.receive_gate = asyncio.Event()
    harness.reader.gate = asyncio.Event()
    first = asyncio.create_task(harness.invoke())
    try:
        await asyncio.wait_for(harness.ws.receive_entered.wait(), 2)
        await asyncio.wait_for(harness.reader.entered.wait(), 2)
        assert harness.runtime.active == 1
        with pytest.raises(web.HTTPServiceUnavailable) as error:
            await asyncio.wait_for(harness.invoke(), 2)
        assert error.value.text == "connection capacity reached"
        assert harness.runtime.active == 1
        assert harness.releases == 0
        assert harness.calls == 1
    finally:
        harness.ws.receive_gate.set()
        harness.reader.gate.set()
        await asyncio.wait_for(first, 2)
    assert_released_once(harness)
    assert harness.runtime.accepted == 1


@pytest.mark.asyncio
async def test_cancel_during_relay_releases_slot_control(harness):
    harness.ws.receive_gate = asyncio.Event()
    harness.reader.gate = asyncio.Event()
    task = asyncio.create_task(harness.invoke())
    try:
        await asyncio.wait_for(harness.ws.receive_entered.wait(), 2)
        await asyncio.wait_for(harness.reader.entered.wait(), 2)
        assert harness.runtime.active == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert_released_once(harness)
    finally:
        harness.ws.receive_gate.set()
        harness.reader.gate.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_dns_thread_pending_then_releases_control(harness):
    started, gate = threading.Event(), threading.Event()
    harness.app[edge.POLICY] = Policy(started, gate)
    task = asyncio.create_task(harness.invoke())
    try:
        assert await asyncio.wait_for(asyncio.to_thread(started.wait, 2), 2.5)
        assert not task.done()
        assert harness.runtime.active == 1
    finally:
        gate.set()
    await asyncio.wait_for(task, 2)
    assert_released_once(harness)


@pytest.mark.asyncio
async def test_dns_thread_cancel_releases_while_worker_unwinds_control(harness):
    started, gate = threading.Event(), threading.Event()
    harness.app[edge.POLICY] = Policy(started, gate)
    task = asyncio.create_task(harness.invoke())
    try:
        assert await asyncio.wait_for(asyncio.to_thread(started.wait, 2), 2.5)
        assert harness.runtime.active == 1
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert_released_once(harness)
    finally:
        gate.set()
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
