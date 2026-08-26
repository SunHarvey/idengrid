from fastapi.testclient import TestClient


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_member(client: TestClient, admin: str, username: str) -> dict:
    response = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": username, "password": "Member-password-123"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_admin_creates_two_members_and_each_starts_an_isolated_session(system):
    client, runner = system
    admin = login(client, "admin", "Admin-password-123")
    create_member(client, admin, "member-a")
    create_member(client, admin, "member-b")
    a = login(client, "member-a", "Member-password-123")
    b = login(client, "member-b", "Member-password-123")

    a_session = client.post("/api/sessions/start", headers=auth(a)).json()
    b_session = client.post("/api/sessions/start", headers=auth(b)).json()

    assert a_session["status"] == b_session["status"] == "running"
    assert a_session["id"] != b_session["id"]
    assert runner.profile_for(a_session["id"]) != runner.profile_for(b_session["id"])
    assert client.get("/api/diagnostics/egress", headers=auth(a)).json()["ip"] == "203.0.113.10"
    assert client.get("/api/diagnostics/egress", headers=auth(b)).json()["ip"] == "203.0.113.10"


def test_member_cannot_read_or_stop_another_members_session(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    create_member(client, admin, "member-a")
    create_member(client, admin, "member-b")
    a = login(client, "member-a", "Member-password-123")
    b = login(client, "member-b", "Member-password-123")
    b_session = client.post("/api/sessions/start", headers=auth(b)).json()

    assert client.get(f"/api/sessions/{b_session['id']}", headers=auth(a)).status_code == 404
    assert client.post(f"/api/sessions/{b_session['id']}/stop", headers=auth(a)).status_code == 404


def test_profile_state_survives_stop_and_restart(system):
    client, runner = system
    admin = login(client, "admin", "Admin-password-123")
    user = create_member(client, admin, "member-a")
    token = login(client, "member-a", "Member-password-123")
    first = client.post("/api/sessions/start", headers=auth(token)).json()
    runner.write_profile_marker(first["id"], "login-state", "present")

    assert client.post(f"/api/sessions/{first['id']}/stop", headers=auth(token)).status_code == 200
    second = client.post("/api/sessions/start", headers=auth(token)).json()

    assert second["profile_key"] == f"user-{user['id']}"
    assert runner.read_profile_marker(second["id"], "login-state") == "present"


def test_disabling_member_stops_session_and_revokes_existing_token(system):
    client, runner = system
    admin = login(client, "admin", "Admin-password-123")
    user = create_member(client, admin, "member-a")
    token = login(client, "member-a", "Member-password-123")
    session = client.post("/api/sessions/start", headers=auth(token)).json()

    response = client.post(f"/api/admin/users/{user['id']}/disable", headers=auth(admin))

    assert response.status_code == 200
    assert runner.status(session["id"]) == "stopped"
    assert client.get("/api/me", headers=auth(token)).status_code == 401
    assert (
        client.post(
            "/api/login", json={"username": "member-a", "password": "Member-password-123"}
        ).status_code
        == 401
    )


def test_admin_can_force_stop_and_audit_log_omits_secrets(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    create_member(client, admin, "member-a")
    token = login(client, "member-a", "Member-password-123")
    session = client.post("/api/sessions/start", headers=auth(token)).json()

    stopped = client.post(f"/api/admin/sessions/{session['id']}/force-stop", headers=auth(admin))
    events = client.get("/api/admin/audit", headers=auth(admin)).json()

    assert stopped.status_code == 200
    assert any(event["event_type"] == "session.force_stopped" for event in events)
    serialized = str(events).lower()
    assert "member-password-123" not in serialized
    assert "cookie" not in serialized
