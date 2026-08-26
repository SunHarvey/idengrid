from __future__ import annotations

from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from cloudbrowser.app import create_app
from cloudbrowser.runner import FakeBrowserRunner


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_cloud_video_routes_fail_closed_by_default_without_runner_calls(tmp_path):
    runner = FakeBrowserRunner()
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'disabled-video.db'}",
        secret_key="disabled-video-test-secret-long-enough",
        runner=runner,
        bootstrap_admin=("admin", "Admin-password-123"),
    )
    with TestClient(app) as client:
        token = client.post(
            "/api/login", json={"username": "admin", "password": "Admin-password-123"}
        ).json()["access_token"]
        headers = auth(token)
        responses = [
            client.post("/api/sessions/start", headers=headers),
            client.get("/api/sessions/missing", headers=headers),
            client.get("/api/sessions/missing/ticket", headers=headers),
            client.post(
                "/api/sessions/missing/viewer-session",
                headers=headers,
                json={"ticket": "not-a-ticket"},
            ),
            client.get("/viewer/missing/"),
            client.get("/api/admin/sessions", headers=headers),
            client.post("/api/admin/sessions/missing/force-stop", headers=headers),
        ]
        assert [response.status_code for response in responses] == [410] * len(responses)
        assert all(response.json()["detail"] == "Cloud video is disabled" for response in responses)
        try:
            with client.websocket_connect("/viewer/missing/api/webrtc/signaling/"):
                raise AssertionError("disabled viewer websocket connected")
        except WebSocketDisconnect as exc:
            assert exc.code == 4410

    assert runner._sessions == {}


def test_workspace_has_no_cloud_video_launch_or_viewer_controls(system):
    client, _ = system
    page = client.get("/")

    assert page.status_code == 200
    assert "/api/sessions/start" not in page.text
    assert "/viewer/" not in page.text
    assert "WebRTC" not in page.text
    assert 'id="startButton"' not in page.text
    assert 'id="viewer"' not in page.text
    assert 'id="localStoreDashboard"' not in page.text
    assert 'id="adminDashboard"' in page.text
    assert 'id="memberNotice"' in page.text
    assert "api('/api/stores')" not in page.text
