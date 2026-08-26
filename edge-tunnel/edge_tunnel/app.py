from __future__ import annotations

import asyncio
import ipaddress
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aiohttp import ClientSession, ClientTimeout, WSMsgType, web

from .targets import PublicTargetPolicy, TargetDenied
from .tickets import Ticket, TicketError, TicketVerifier


@dataclass(frozen=True)
class Settings:
    node_id: str
    ticket_secret: bytes
    max_connections: int = 64
    max_frame_bytes: int = 1_048_576
    max_bytes_per_connection: int = 67_108_864
    idle_timeout: float = 60.0
    max_connection_seconds: float = 600.0
    connect_timeout: float = 10.0
    ticket_max_ttl: int = 60

    @classmethod
    def from_env(cls) -> Settings:
        secret = os.environ.get("EDGE_TICKET_SECRET", "").encode()
        node = os.environ.get("EDGE_NODE_ID", "")
        if (
            not node
            or len(node) > 64
            or any(
                char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
                for char in node
            )
        ):
            raise RuntimeError("EDGE_NODE_ID is missing or unsafe")
        if len(secret) < 32:
            raise RuntimeError("EDGE_TICKET_SECRET must be at least 32 bytes")
        try:
            settings = cls(
                node_id=node,
                ticket_secret=secret,
                max_connections=int(os.getenv("EDGE_MAX_CONNECTIONS", "64")),
                max_frame_bytes=int(os.getenv("EDGE_MAX_FRAME_BYTES", "1048576")),
                max_bytes_per_connection=int(os.getenv("EDGE_MAX_BYTES", "67108864")),
                idle_timeout=float(os.getenv("EDGE_IDLE_TIMEOUT", "60")),
                max_connection_seconds=float(os.getenv("EDGE_MAX_DURATION", "600")),
                connect_timeout=float(os.getenv("EDGE_CONNECT_TIMEOUT", "10")),
                ticket_max_ttl=int(os.getenv("EDGE_TICKET_MAX_TTL", "60")),
            )
        except ValueError as exc:
            raise RuntimeError("invalid edge configuration value") from exc
        limits = (
            settings.max_connections,
            settings.max_frame_bytes,
            settings.max_bytes_per_connection,
            settings.idle_timeout,
            settings.max_connection_seconds,
            settings.connect_timeout,
            settings.ticket_max_ttl,
        )
        if any(value <= 0 for value in limits) or settings.ticket_max_ttl > 300:
            raise RuntimeError("invalid edge configuration limit")
        return settings


@dataclass
class Runtime:
    max_connections: int
    active: int = 0
    accepted: int = 0
    denied: int = 0

    def acquire(self) -> bool:
        if self.active >= self.max_connections:
            return False
        self.active += 1
        return True

    def release(self) -> None:
        self.active -= 1


class ReplayCache:
    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._expires: dict[str, int] = {}
        self._clock = clock

    def claim(self, ticket: Ticket) -> bool:
        now = int(self._clock())
        self._expires = {key: exp for key, exp in self._expires.items() if exp > now}
        if ticket.jti in self._expires:
            return False
        self._expires[ticket.jti] = ticket.expires_at
        return True


Connector = Callable[[str, int, int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]
PublicIPv4Provider = Callable[[], Awaitable[str]]
ResourceProvider = Callable[[], dict[str, int | float]]
SETTINGS = web.AppKey("settings", Settings)
RUNTIME = web.AppKey("runtime", Runtime)
VERIFIER = web.AppKey("verifier", TicketVerifier)
POLICY = web.AppKey("policy", PublicTargetPolicy)
REPLAYS = web.AppKey("replays", ReplayCache)
CONNECTOR = web.AppKey("connector", Connector)
PUBLIC_IPV4_PROVIDER = web.AppKey("public_ipv4_provider", PublicIPv4Provider)
RESOURCE_PROVIDER = web.AppKey("resource_provider", ResourceProvider)


class CachedPublicIPv4:
    def __init__(
        self,
        fetch: PublicIPv4Provider,
        *,
        ttl_seconds: float = 60,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._fetch = fetch
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._value: str | None = None
        self._expires_at = 0.0

    async def __call__(self) -> str:
        now = self._clock()
        if self._value is not None and now < self._expires_at:
            return self._value
        value = (await self._fetch()).strip()
        try:
            address = ipaddress.ip_address(value)
        except ValueError as exc:
            raise ValueError("public IP lookup did not return a global IPv4 address") from exc
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_global:
            raise ValueError("public IP lookup did not return a global IPv4 address")
        value = str(address)
        self._value = value
        self._expires_at = now + self._ttl_seconds
        return value


class LinuxResourceProvider:
    def __init__(
        self,
        *,
        read_text: Callable[[str], str] | None = None,
        statvfs: Callable[[str], Any] = os.statvfs,
    ) -> None:
        self._read_text = read_text or (lambda path: Path(path).read_text())
        self._statvfs = statvfs

    def __call__(self) -> dict[str, int | float]:
        memory = {}
        for line in self._read_text("/proc/meminfo").splitlines():
            key, value = line.split(":", 1)
            memory[key] = int(value.split()[0]) * 1024
        filesystem = self._statvfs("/")
        return {
            "load_1m": float(self._read_text("/proc/loadavg").split()[0]),
            "memory_total_bytes": memory["MemTotal"],
            "memory_available_bytes": memory["MemAvailable"],
            "disk_total_bytes": filesystem.f_frsize * filesystem.f_blocks,
            "disk_free_bytes": filesystem.f_frsize * filesystem.f_bavail,
            "uptime_seconds": float(self._read_text("/proc/uptime").split()[0]),
        }


async def _default_connector(address: str, port: int, family: int):
    return await asyncio.open_connection(address, port, family=family)


async def _fetch_public_ipv4() -> str:
    timeout = ClientTimeout(total=3.0, connect=2.0, sock_read=2.0)
    async with (
        ClientSession(timeout=timeout) as client,
        client.get("https://api.ipify.org") as response,
    ):
        response.raise_for_status()
        body = await response.content.read(65)
        if len(body) > 64:
            raise ValueError("public IP lookup response is too large")
        return body.decode("ascii")


async def health(request: web.Request) -> web.Response:
    return web.json_response({"status": "ok", "node": request.app[SETTINGS].node_id})


async def status(request: web.Request) -> web.Response:
    runtime = request.app[RUNTIME]
    try:
        public_ipv4 = await request.app[PUBLIC_IPV4_PROVIDER]()
        resources = request.app[RESOURCE_PROVIDER]()
    except Exception as exc:
        raise web.HTTPServiceUnavailable(text="status unavailable") from exc
    return web.json_response(
        {
            "node": request.app[SETTINGS].node_id,
            "active_connections": runtime.active,
            "max_connections": runtime.max_connections,
            "accepted_connections": runtime.accepted,
            "denied_connections": runtime.denied,
            "public_ipv4": public_ipv4,
            **resources,
            "agent_version": "1.0.0",
        }
    )


def _bearer(request: web.Request) -> str:
    value = request.headers.get("Authorization", "")
    if not value.startswith("Bearer ") or not value[7:]:
        raise TicketError("missing bearer ticket")
    return value[7:]


async def _relay(
    ws: web.WebSocketResponse,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: Settings,
) -> None:
    transferred = 0

    def account(size: int) -> None:
        nonlocal transferred
        transferred += size
        if transferred > settings.max_bytes_per_connection:
            raise ValueError("connection byte limit exceeded")

    async def websocket_to_tcp() -> None:
        while True:
            message = await asyncio.wait_for(ws.receive(), settings.idle_timeout)
            if message.type == WSMsgType.BINARY:
                account(len(message.data))
                writer.write(message.data)
                await writer.drain()
            elif message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR):
                return
            else:
                await ws.close(code=1003, message=b"binary frames only")
                return

    async def tcp_to_websocket() -> None:
        while True:
            data = await asyncio.wait_for(
                reader.read(settings.max_frame_bytes), settings.idle_timeout
            )
            if not data:
                return
            account(len(data))
            await ws.send_bytes(data)

    tasks = {
        asyncio.create_task(websocket_to_tcp()),
        asyncio.create_task(tcp_to_websocket()),
    }
    try:
        done, pending = await asyncio.wait(
            tasks,
            timeout=settings.max_connection_seconds,
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in done:
            task.result()
        for task in pending:
            task.cancel()
    except (TimeoutError, ValueError):
        await ws.close(code=1008, message=b"tunnel limit reached")
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        writer.close()
        await writer.wait_closed()


async def tunnel(request: web.Request) -> web.StreamResponse:
    runtime = request.app[RUNTIME]
    acquired = False
    writer: asyncio.StreamWriter | None = None
    try:
        ticket = request.app[VERIFIER].verify(_bearer(request))
        if not request.app[REPLAYS].claim(ticket):
            raise TicketError("ticket already used")
        if not runtime.acquire():
            raise web.HTTPServiceUnavailable(text="connection capacity reached")
        acquired = True
        target = await asyncio.to_thread(request.app[POLICY].resolve, ticket.host, ticket.port)
        reader, writer = await asyncio.wait_for(
            request.app[CONNECTOR](target.address, target.port, target.family),
            request.app[SETTINGS].connect_timeout,
        )
        ws = web.WebSocketResponse(max_msg_size=request.app[SETTINGS].max_frame_bytes)
        await ws.prepare(request)
        runtime.accepted += 1
        await _relay(ws, reader, writer, request.app[SETTINGS])
        writer = None
        return ws
    except TicketError as exc:
        runtime.denied += 1
        raise web.HTTPUnauthorized(text="invalid capability ticket") from exc
    except TargetDenied as exc:
        runtime.denied += 1
        raise web.HTTPForbidden(text="target denied") from exc
    except (TimeoutError, OSError) as exc:
        runtime.denied += 1
        raise web.HTTPBadGateway(text="target connection failed") from exc
    finally:
        if writer is not None:
            writer.close()
            await writer.wait_closed()
        if acquired:
            runtime.release()


def create_app(
    settings: Settings,
    *,
    policy: PublicTargetPolicy | None = None,
    connector: Connector | None = None,
    public_ipv4_provider: PublicIPv4Provider | None = None,
    resource_provider: ResourceProvider | None = None,
) -> web.Application:
    app = web.Application(client_max_size=settings.max_frame_bytes)
    app[SETTINGS] = settings
    app[RUNTIME] = Runtime(settings.max_connections)
    app[VERIFIER] = TicketVerifier(
        settings.ticket_secret,
        settings.node_id,
        max_ttl=settings.ticket_max_ttl,
    )
    app[POLICY] = policy or PublicTargetPolicy()
    app[REPLAYS] = ReplayCache()
    app[CONNECTOR] = connector or _default_connector
    app[PUBLIC_IPV4_PROVIDER] = public_ipv4_provider or CachedPublicIPv4(_fetch_public_ipv4)
    app[RESOURCE_PROVIDER] = resource_provider or LinuxResourceProvider()
    app.router.add_get("/healthz", health)
    app.router.add_get("/status", status)
    app.router.add_get("/v1/tunnel", tunnel)
    return app
