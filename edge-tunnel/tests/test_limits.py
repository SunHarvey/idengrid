import asyncio

import pytest
from aiohttp import ClientResponseError, WSMsgType
from aiohttp.test_utils import TestClient, TestServer
from edge_tunnel.app import Settings, create_app
from test_app import NullWriter, Policy, make_ticket


def limited_settings(**changes):
    values = {
        "node_id": "edge-sg01",
        "ticket_secret": b"s" * 32,
        "max_connections": 1,
        "max_frame_bytes": 8,
        "max_bytes_per_connection": 5,
        "idle_timeout": 2,
        "max_connection_seconds": 5,
        "connect_timeout": 1,
        "ticket_max_ttl": 60,
    }
    values.update(changes)
    return Settings(**values)


async def hanging_connector(*_):
    return asyncio.StreamReader(), NullWriter()


@pytest.mark.asyncio
async def test_rejects_connection_immediately_when_concurrency_limit_is_reached():
    settings = limited_settings()
    app = create_app(settings, policy=Policy(), connector=hanging_connector)
    async with TestClient(TestServer(app)) as client:
        first = await client.ws_connect(
            "/v1/tunnel",
            headers={"Authorization": f"Bearer {make_ticket(settings.ticket_secret, jti='one')}"},
        )
        with pytest.raises(ClientResponseError) as error:
            await client.ws_connect(
                "/v1/tunnel",
                headers={
                    "Authorization": f"Bearer {make_ticket(settings.ticket_secret, jti='two')}"
                },
            )
        await first.close()

    assert error.value.status == 503


@pytest.mark.asyncio
async def test_closes_tunnel_when_aggregate_byte_limit_is_exceeded():
    settings = limited_settings(max_frame_bytes=8, max_bytes_per_connection=5)
    app = create_app(settings, policy=Policy(), connector=hanging_connector)
    async with TestClient(TestServer(app)) as client:
        ws = await client.ws_connect(
            "/v1/tunnel",
            headers={"Authorization": f"Bearer {make_ticket(settings.ticket_secret)}"},
        )
        await ws.send_bytes(b"123456")
        message = await ws.receive(timeout=2)

    assert message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED)
    assert ws.close_code == 1008


@pytest.mark.asyncio
async def test_rejects_websocket_frame_larger_than_configured_limit():
    settings = limited_settings(max_frame_bytes=4, max_bytes_per_connection=100)
    app = create_app(settings, policy=Policy(), connector=hanging_connector)
    async with TestClient(TestServer(app)) as client:
        ws = await client.ws_connect(
            "/v1/tunnel",
            headers={"Authorization": f"Bearer {make_ticket(settings.ticket_secret)}"},
        )
        await ws.send_bytes(b"12345")
        message = await ws.receive(timeout=2)

    assert message.type in (WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR)
    assert ws.closed
