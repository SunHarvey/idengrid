import asyncio
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

import httpx
from fastapi.testclient import TestClient
from sqlalchemy import create_engine as sqlalchemy_create_engine
from websockets.sync.server import serve

from cloudbrowser.app import create_app
from cloudbrowser.runner import FakeBrowserRunner, RunnerSession


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_https_mode_sets_secure_viewer_cookie(tmp_path: Path):
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'secure.db'}",
        secret_key="secure-test-key-that-is-at-least-32-characters",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        secure_cookies=True,
        cloud_video_enabled=True,
    )
    with TestClient(app, base_url="https://cloud.example.test") as client:
        admin = login(client, "admin", "Admin-password-123")
        created = client.post(
            "/api/admin/users",
            headers=auth(admin),
            json={"username": "member-a", "password": "Member-password-123"},
        ).json()
        assert created["id"]
        member = login(client, "member-a", "Member-password-123")
        session = client.post("/api/sessions/start", headers=auth(member)).json()
        ticket = client.get(f"/api/sessions/{session['id']}/ticket", headers=auth(member)).json()[
            "ticket"
        ]
        response = client.post(
            f"/api/sessions/{session['id']}/viewer-session",
            headers=auth(member),
            json={"ticket": ticket},
        )

    cookie = response.headers["set-cookie"].lower()
    assert "secure" in cookie
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert "max-age=28800" in cookie


def test_admin_lists_all_sessions_without_exposing_runner_endpoints(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    for username in ("member-a", "member-b"):
        client.post(
            "/api/admin/users",
            headers=auth(admin),
            json={"username": username, "password": "Member-password-123"},
        )
        member = login(client, username, "Member-password-123")
        client.post("/api/sessions/start", headers=auth(member))

    response = client.get("/api/admin/sessions", headers=auth(admin))

    assert response.status_code == 200
    sessions = response.json()
    assert {item["username"] for item in sessions} == {"member-a", "member-b"}
    assert all(item["status"] == "running" for item in sessions)
    assert all("endpoint" not in item for item in sessions)


def test_member_cannot_list_admin_sessions(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "member-a", "password": "Member-password-123"},
    )
    member = login(client, "member-a", "Member-password-123")

    assert client.get("/api/admin/sessions", headers=auth(member)).status_code == 403


def test_concurrent_viewer_assets_do_not_exhaust_database_pool(tmp_path: Path, monkeypatch):
    class SlowAssetHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            time.sleep(0.2)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"asset")

        def log_message(self, format, *args):
            return

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), SlowAssetHandler)
    Thread(target=upstream.serve_forever, daemon=True).start()

    class HttpRunner(FakeBrowserRunner):
        def start(self, session_id: str, profile_key: str, egress_profile: dict):
            result = RunnerSession(endpoint=f"http://127.0.0.1:{upstream.server_port}")
            self._sessions[session_id] = result
            return result

    def one_connection_engine(*args, **kwargs):
        return sqlalchemy_create_engine(
            *args, **kwargs, pool_size=1, max_overflow=0, pool_timeout=0.05
        )

    monkeypatch.setattr("cloudbrowser.app.create_engine", one_connection_engine)
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'pool.db'}",
        secret_key="pool-test-key-that-is-at-least-32-characters",
        runner=HttpRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        cloud_video_enabled=True,
    )

    async def exercise():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            admin = (
                await client.post(
                    "/api/login", json={"username": "admin", "password": "Admin-password-123"}
                )
            ).json()["access_token"]
            session = (await client.post("/api/sessions/start", headers=auth(admin))).json()
            ticket = (
                await client.get(f"/api/sessions/{session['id']}/ticket", headers=auth(admin))
            ).json()["ticket"]
            await client.post(
                f"/api/sessions/{session['id']}/viewer-session",
                headers=auth(admin),
                json={"ticket": ticket},
            )
            responses = await asyncio.gather(
                client.get(f"/viewer/{session['id']}/one.js"),
                client.get(f"/viewer/{session['id']}/two.js"),
            )
            return responses

    try:
        responses = asyncio.run(exercise())
    finally:
        upstream.shutdown()

    assert [response.status_code for response in responses] == [200, 200]
    assert [response.content for response in responses] == [b"asset", b"asset"]


def test_viewer_proxy_forwards_text_websocket_on_arbitrary_selkies_path(tmp_path: Path):
    def echo(upstream):
        upstream.send(f"ack:{upstream.recv()}")

    ws_server = serve(echo, "127.0.0.1", 0)
    Thread(target=ws_server.serve_forever, daemon=True).start()
    port = ws_server.socket.getsockname()[1]

    class WsRunner(FakeBrowserRunner):
        def start(self, session_id: str, profile_key: str, egress_profile: dict):
            result = RunnerSession(endpoint=f"http://127.0.0.1:{port}")
            self._sessions[session_id] = result
            return result

    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'ws.db'}",
        secret_key="websocket-test-key-that-is-at-least-32-characters",
        runner=WsRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        public_origin="https://cloud.example.test",
        cloud_video_enabled=True,
    )
    try:
        with TestClient(app, base_url="https://cloud.example.test") as client:
            token = login(client, "admin", "Admin-password-123")
            session = client.post("/api/sessions/start", headers=auth(token)).json()
            ticket = client.get(
                f"/api/sessions/{session['id']}/ticket", headers=auth(token)
            ).json()["ticket"]
            viewer_session = client.post(
                f"/api/sessions/{session['id']}/viewer-session",
                headers=auth(token),
                json={"ticket": ticket},
            )
            grant = viewer_session.cookies[f"cb_viewer_{session['id']}"]
            with client.websocket_connect(
                f"/viewer/{session['id']}/api/webrtc/signaling/",
                headers={
                    "origin": "https://cloud.example.test",
                    "cookie": f"cb_viewer_{session['id']}={grant}",
                },
            ) as viewer:
                viewer.send_text("hello")
                assert viewer.receive_text() == "ack:hello"
    finally:
        ws_server.shutdown()
