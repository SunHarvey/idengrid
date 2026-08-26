import tempfile
from pathlib import Path

from fastapi.testclient import TestClient

from cloudbrowser.app import create_app
from cloudbrowser.runner import PodmanBrowserRunner

runtime = Path(tempfile.mkdtemp(prefix="runtime-api-e2e-", dir="/data"))
runner = PodmanBrowserRunner(runtime)
app = create_app(
    database_url=f"sqlite:///{runtime / 'e2e.db'}",
    secret_key="e2e-secret-key-that-is-at-least-32-characters",
    runner=runner,
    bootstrap_admin=("e2e-admin", "E2E-Admin-password-123"),
)


def login(client, username, password):
    response = client.post("/api/login", json={"username": username, "password": password})
    response.raise_for_status()
    return response.json()["access_token"]


def headers(token):
    return {"Authorization": f"Bearer {token}"}


started = []
with TestClient(app) as client:
    admin = login(client, "e2e-admin", "E2E-Admin-password-123")
    members = []
    for username in ("e2e-a", "e2e-b"):
        created = client.post(
            "/api/admin/users",
            headers=headers(admin),
            json={"username": username, "password": "E2E-Member-password-123"},
        )
        created.raise_for_status()
        members.append(created.json())
    tokens = [login(client, name, "E2E-Member-password-123") for name in ("e2e-a", "e2e-b")]
    sessions = []
    for token in tokens:
        response = client.post("/api/sessions/start", headers=headers(token))
        response.raise_for_status()
        sessions.append(response.json())
        started.append(response.json()["id"])
    assert sessions[0]["id"] != sessions[1]["id"]
    assert sessions[0]["profile_key"] != sessions[1]["profile_key"]
    forbidden = client.get(f"/api/sessions/{sessions[1]['id']}", headers=headers(tokens[0]))
    assert forbidden.status_code == 404
    ips = [client.get("/api/diagnostics/egress", headers=headers(t)).json()["ip"] for t in tokens]
    assert len(set(ips)) == 1

    ticket = client.get(
        f"/api/sessions/{sessions[0]['id']}/ticket", headers=headers(tokens[0])
    ).json()["ticket"]
    established = client.post(
        f"/api/sessions/{sessions[0]['id']}/viewer-session",
        headers=headers(tokens[0]),
        json={"ticket": ticket},
    )
    established.raise_for_status()
    viewer = client.get(f"/viewer/{sessions[0]['id']}/")
    assert viewer.status_code == 200 and '<div id="root"></div>' in viewer.text
    transport = client.get(f"/viewer/{sessions[0]['id']}/api/status")
    transport.raise_for_status()
    assert transport.json()["current_mode"] == "webrtc"

    disabled = client.post(f"/api/admin/users/{members[1]['id']}/disable", headers=headers(admin))
    disabled.raise_for_status()
    assert client.get("/api/me", headers=headers(tokens[1])).status_code == 401
    forced = client.post(
        f"/api/admin/sessions/{sessions[0]['id']}/force-stop", headers=headers(admin)
    )
    forced.raise_for_status()
    print(f"sessions={[s['id'] for s in sessions]}")
    print(f"egress_ips={ips}")
    print(f"viewer_bytes={len(viewer.content)} transport=webrtc")
    print("real_api_e2e=PASS")
