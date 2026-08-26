from fastapi.testclient import TestClient

from cloudbrowser.browser_control import CDPBrowserControl, normalize_address_input


def test_real_control_creates_new_target_without_launching_another_chromium(monkeypatch) -> None:
    def unexpected_launch(_url: str) -> None:
        raise AssertionError("must not launch a second Chromium process")

    control = CDPBrowserControl("http://127.0.0.1:9223", unexpected_launch)
    calls = []
    target_checks = 0

    def browser_commands(commands):
        calls.extend(commands)
        return [{"targetId": "B" * 32}]

    monkeypatch.setattr(control, "_browser_commands", browser_commands)

    def targets():
        nonlocal target_checks
        target_checks += 1
        if target_checks == 1:
            return []
        return [{"id": "B" * 32}]

    monkeypatch.setattr(control, "_targets", targets)
    monkeypatch.setattr(
        control,
        "activate",
        lambda target_id: {"tabs": [{"target_id": target_id}], "active_target_id": target_id},
    )

    state = control.new_tab("https://example.org/")

    assert calls == [("Target.createTarget", {"url": "https://example.org/", "background": False})]
    assert target_checks == 2
    assert state["active_target_id"] == "B" * 32


def test_kiosk_target_activation_does_not_resize_the_fullscreen_window(monkeypatch) -> None:
    control = CDPBrowserControl("http://127.0.0.1:9223", lambda _: None)
    target_id = "C" * 32
    requests = []
    monkeypatch.setattr(control, "_target", lambda value: {"id": value})
    monkeypatch.setattr(control, "_request", lambda path: requests.append(path))
    monkeypatch.setattr(
        control,
        "_maximize",
        lambda _value: (_ for _ in ()).throw(AssertionError("kiosk is already fullscreen")),
    )
    monkeypatch.setattr(
        control,
        "state",
        lambda: {"tabs": [{"target_id": target_id}], "active_target_id": target_id},
    )

    state = control.activate(target_id)

    assert requests == [f"/json/activate/{target_id}"]
    assert state["active_target_id"] == target_id


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_address_input_accepts_public_host_with_port() -> None:
    assert normalize_address_input("example.com:8443/path") == "https://example.com:8443/path"


def create_member(client: TestClient, admin: str, username: str) -> str:
    response = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": username, "password": "Member-password-123"},
    )
    assert response.status_code == 201, response.text
    return login(client, username, "Member-password-123")


def test_browser_controls_require_authentication_and_ownership(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member_a = create_member(client, admin, "member-a")
    member_b = create_member(client, admin, "member-b")
    session = client.post("/api/sessions/start", headers=auth(member_a)).json()
    path = f"/api/sessions/{session['id']}/browser/tabs"

    assert client.get(path).status_code == 401
    assert client.get(path, headers=auth(member_b)).status_code == 404
    assert client.get(path, headers=auth(member_a)).status_code == 200


def test_browser_controls_reject_stopped_session(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-a")
    session = client.post("/api/sessions/start", headers=auth(member)).json()
    client.post(f"/api/sessions/{session['id']}/stop", headers=auth(member))

    response = client.get(f"/api/sessions/{session['id']}/browser/tabs", headers=auth(member))

    assert response.status_code == 409


def test_address_bar_navigates_cloud_tab_and_reports_real_state(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-a")
    session = client.post("/api/sessions/start", headers=auth(member)).json()
    base = f"/api/sessions/{session['id']}/browser"
    initial = client.get(f"{base}/tabs", headers=auth(member)).json()
    target_id = initial["active_target_id"]

    navigated = client.post(
        f"{base}/tabs/{target_id}/navigate",
        headers=auth(member),
        json={"input": "example.org/docs"},
    )

    assert navigated.status_code == 200, navigated.text
    tab = navigated.json()["tabs"][0]
    assert tab["url"] == "https://example.org/docs"
    assert tab["title"] == "example.org"
    assert tab["loading"] is False
    assert tab["can_go_back"] is True


def test_address_bar_turns_plain_text_into_search_and_blocks_unsafe_urls(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-a")
    session = client.post("/api/sessions/start", headers=auth(member)).json()
    base = f"/api/sessions/{session['id']}/browser"
    target_id = client.get(f"{base}/tabs", headers=auth(member)).json()["active_target_id"]

    searched = client.post(
        f"{base}/tabs/{target_id}/navigate",
        headers=auth(member),
        json={"input": "cloud browser test"},
    )
    assert searched.status_code == 200
    assert searched.json()["tabs"][0]["url"].startswith(
        "https://www.google.com/search?q=cloud+browser+test"
    )

    for value in (
        "http://127.0.0.1:8000",
        "http://169.254.169.254/latest/meta-data",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "chrome://settings",
    ):
        response = client.post(
            f"{base}/tabs/{target_id}/navigate",
            headers=auth(member),
            json={"input": value},
        )
        assert response.status_code == 422, value


def test_local_tabs_support_new_activate_history_reload_and_close(system):
    client, runner = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-a")
    session = client.post("/api/sessions/start", headers=auth(member)).json()
    base = f"/api/sessions/{session['id']}/browser"
    first = client.get(f"{base}/tabs", headers=auth(member)).json()["active_target_id"]

    created = client.post(
        f"{base}/tabs", headers=auth(member), json={"input": "https://example.org"}
    )
    second = created.json()["active_target_id"]
    assert second != first
    assert len(created.json()["tabs"]) == 2

    activated = client.post(f"{base}/tabs/{first}/activate", headers=auth(member))
    assert activated.json()["active_target_id"] == first

    client.post(
        f"{base}/tabs/{first}/navigate",
        headers=auth(member),
        json={"input": "https://example.com/next"},
    )
    backed = client.post(f"{base}/tabs/{first}/back", headers=auth(member))
    assert backed.json()["tabs"][0]["url"] == "https://example.com"
    forwarded = client.post(f"{base}/tabs/{first}/forward", headers=auth(member))
    assert forwarded.json()["tabs"][0]["url"] == "https://example.com/next"
    reloaded = client.post(f"{base}/tabs/{first}/reload", headers=auth(member))
    assert reloaded.status_code == 200
    assert runner.reload_count(first) == 1

    closed = client.delete(f"{base}/tabs/{second}", headers=auth(member))
    assert closed.status_code == 200
    assert len(closed.json()["tabs"]) == 1
    assert closed.json()["active_target_id"] == first


def test_last_tab_cannot_be_closed(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-a")
    session = client.post("/api/sessions/start", headers=auth(member)).json()
    base = f"/api/sessions/{session['id']}/browser"
    target_id = client.get(f"{base}/tabs", headers=auth(member)).json()["active_target_id"]

    response = client.delete(f"{base}/tabs/{target_id}", headers=auth(member))

    assert response.status_code == 409
