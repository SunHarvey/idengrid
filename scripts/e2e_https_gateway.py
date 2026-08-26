from __future__ import annotations

import os
import re
import uuid

import httpx

BASE_URL = os.getenv("E2E_BASE_URL", "https://localhost:8443")
VERIFY_TLS = os.getenv("E2E_VERIFY_TLS", "false").lower() in {"1", "true", "yes"}
ADMIN_USERNAME = os.getenv("E2E_ADMIN_USERNAME", "https-admin")
ADMIN_PASSWORD = os.getenv("E2E_ADMIN_PASSWORD", "HTTPS-Admin-password-123")
MEMBER_USERNAME = os.getenv("E2E_MEMBER_USERNAME", f"https-member-{uuid.uuid4().hex[:8]}")
MEMBER_PASSWORD = os.getenv("E2E_MEMBER_PASSWORD", "HTTPS-Member-password-123")


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def login(client: httpx.Client, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    response.raise_for_status()
    return response.json()["access_token"]


session_id: str | None = None
admin: str | None = None
member_id: int | None = None
with httpx.Client(base_url=BASE_URL, verify=VERIFY_TLS, timeout=180) as client:
    try:
        health = client.get("/healthz")
        health.raise_for_status()
        assert health.json() == {"status": "ok"}

        admin = login(client, ADMIN_USERNAME, ADMIN_PASSWORD)
        created = client.post(
            "/api/admin/users",
            headers=auth(admin),
            json={"username": MEMBER_USERNAME, "password": MEMBER_PASSWORD},
        )
        created.raise_for_status()
        member_id = created.json()["id"]
        member = login(client, MEMBER_USERNAME, MEMBER_PASSWORD)

        started = client.post("/api/sessions/start", headers=auth(member))
        started.raise_for_status()
        session_id = started.json()["id"]
        ticket = client.get(f"/api/sessions/{session_id}/ticket", headers=auth(member))
        ticket.raise_for_status()
        established = client.post(
            f"/api/sessions/{session_id}/viewer-session",
            headers=auth(member),
            json={"ticket": ticket.json()["ticket"]},
        )
        established.raise_for_status()
        set_cookie = established.headers["set-cookie"].lower()
        assert all(
            marker in set_cookie
            for marker in ("secure", "httponly", "samesite=strict", "max-age=28800")
        )

        viewer = client.get(f"/viewer/{session_id}/")
        viewer.raise_for_status()
        assert '<div id="app"></div>' in viewer.text
        assert '<div id="root"></div>' in viewer.text
        asset_match = re.search(r'src="(\./assets/[^"]+\.js)"', viewer.text)
        assert asset_match
        asset = client.get(f"/viewer/{session_id}/{asset_match.group(1)[2:]}")
        asset.raise_for_status()
        assert "javascript" in asset.headers.get("content-type", "")

        status_response = client.get(f"/viewer/{session_id}/api/status")
        status_response.raise_for_status()
        assert status_response.json()["current_mode"] == "webrtc"

        switched = client.post(f"/viewer/{session_id}/api/switch", json={"mode": "websockets"})
        switched.raise_for_status()
        switched_status = client.get(f"/viewer/{session_id}/api/status")
        switched_status.raise_for_status()
        assert switched_status.json()["current_mode"] == "websockets"

        sessions = client.get("/api/admin/sessions", headers=auth(admin))
        sessions.raise_for_status()
        listed = next(item for item in sessions.json() if item["id"] == session_id)
        assert listed["username"] == MEMBER_USERNAME and listed["status"] == "running"

        print(f"https_status={health.status_code}")
        print("secure_viewer_grant=true")
        print(f"selkies_page_bytes={len(viewer.content)} asset_bytes={len(asset.content)}")
        print("transport_modes=webrtc,websockets")
        print(f"admin_session={listed['username']}:{listed['status']}")
        print("https_selkies_gateway_e2e=PASS")
    finally:
        if session_id and admin:
            client.post(f"/api/admin/sessions/{session_id}/force-stop", headers=auth(admin))
        if member_id and admin:
            client.post(f"/api/admin/users/{member_id}/disable", headers=auth(admin))
