from __future__ import annotations

from fastapi.testclient import TestClient


def login(
    client: TestClient,
    username: str,
    password: str,
    *,
    user_agent: str = "audit-test-agent",
) -> str:
    response = client.post(
        "/api/login",
        json={"username": username, "password": password},
        headers={"user-agent": user_agent},
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_audit_has_time_username_source_ip_and_user_agent(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123", user_agent="Hermes-Audit-E2E")
    client.post(
        "/api/login",
        json={"username": "missing-user", "password": "not-the-password"},
        headers={"user-agent": "Failed-Login-Agent"},
    )

    succeeded = client.get(
        "/api/admin/audit?event_type=login.succeeded", headers=auth(admin)
    ).json()[0]
    failed = client.get("/api/admin/audit?event_type=login.failed", headers=auth(admin)).json()[0]

    assert succeeded["event_label"] == "用户登录成功"
    assert succeeded["actor_username"] == "admin"
    assert succeeded["target_name"] == "admin"
    assert succeeded["details"]["source_ip"] == "testclient"
    assert succeeded["details"]["user_agent"] == "Hermes-Audit-E2E"
    assert succeeded["created_at"].endswith("+00:00")
    assert failed["event_label"] == "用户登录失败"
    assert failed["actor_username"] is None
    assert failed["target_name"] == "missing-user"
    assert failed["details"]["source_ip"] == "testclient"
    assert failed["details"]["user_agent"] == "Failed-Login-Agent"


def test_admin_operation_audit_resolves_actor_and_target_names(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    created = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "audit-target", "password": "Member-password-123"},
    )
    assert created.status_code == 201

    event = client.get(
        "/api/admin/audit?event_type=workspace.user_assigned", headers=auth(admin)
    ).json()[0]

    assert event["event_label"] == "管理员创建用户"
    assert event["actor_username"] == "admin"
    assert event["target_name"] == "audit-target"


def test_store_domain_access_audit_is_deduplicated_for_five_minutes(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    connection = client.post(
        "/api/stores/1/connect",
        headers=auth(admin),
        json={"device_id": "audit-device"},
    )
    assert connection.status_code == 201, connection.text

    for _ in range(2):
        response = client.post(
            "/api/stores/1/tickets",
            headers=auth(admin),
            json={"host": "8.8.8.8", "port": 443},
        )
        assert response.status_code == 201, response.text

    events = client.get(
        "/api/admin/audit?event_type=web.domain_accessed", headers=auth(admin)
    ).json()
    assert len(events) == 1
    event = events[0]
    assert event["event_label"] == "店铺访问域名"
    assert event["actor_username"] == "admin"
    assert event["target_name"] == "Store 01"
    assert event["details"] == {
        "domain": "8.8.8.8",
        "port": 443,
        "device_id": "audit-device",
        "node": "sg-browser",
    }


def test_audit_api_defaults_to_fifteen_and_supports_offset_pagination(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    for index in range(20):
        client.post(
            "/api/login",
            json={"username": f"missing-{index}", "password": "not-the-password"},
        )

    first = client.get("/api/admin/audit?event_type=login.failed", headers=auth(admin))
    second = client.get("/api/admin/audit?event_type=login.failed&offset=15", headers=auth(admin))

    assert first.status_code == 200
    assert second.status_code == 200
    assert len(first.json()) == 15
    assert len(second.json()) == 5
    assert {item["id"] for item in first.json()}.isdisjoint({item["id"] for item in second.json()})
    assert first.json()[0]["id"] > first.json()[-1]["id"]
    assert client.get("/api/admin/audit?offset=-1", headers=auth(admin)).status_code == 422
