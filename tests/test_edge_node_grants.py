from __future__ import annotations

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


def test_admin_replaces_and_lists_member_edge_node_grants_with_audit(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-grants")
    nodes = client.get("/api/admin/edge-nodes", headers=auth(admin)).json()
    url = f"/api/admin/users/{member['id']}/edge-nodes"

    assert client.get(url, headers=auth(admin)).json() == {"node_ids": []}
    replaced = client.put(
        url,
        headers=auth(admin),
        json={"node_ids": [nodes[1]["id"], nodes[0]["id"], nodes[1]["id"]]},
    )

    assert replaced.status_code == 200, replaced.text
    assert replaced.json() == {"node_ids": [nodes[0]["id"], nodes[1]["id"]]}
    assert client.get(url, headers=auth(admin)).json() == replaced.json()
    audit = client.get("/api/admin/audit", headers=auth(admin)).json()
    event = next(item for item in audit if item["event_type"] == "user.edge_nodes_replaced")
    assert event["target_id"] == str(member["id"])
    assert event["details"] == {"node_ids": [nodes[0]["id"], nodes[1]["id"]]}
    assert "secret" not in str(event).lower()


def test_grant_replace_rejects_unknown_nodes_without_changing_existing_grants(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-invalid")
    node_id = client.get("/api/admin/edge-nodes", headers=auth(admin)).json()[0]["id"]
    url = f"/api/admin/users/{member['id']}/edge-nodes"
    client.put(url, headers=auth(admin), json={"node_ids": [node_id]})

    response = client.put(url, headers=auth(admin), json={"node_ids": [node_id, 999999]})

    assert response.status_code == 422
    assert client.get(url, headers=auth(admin)).json() == {"node_ids": [node_id]}


def test_node_grants_control_visibility_and_use_immediately_while_admin_has_implicit_access(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-use")
    member_token = login(client, "member-use", "Member-password-123")
    nodes = client.get("/api/admin/edge-nodes", headers=auth(admin)).json()
    stores = client.get("/api/admin/stores", headers=auth(admin)).json()
    first_node = nodes[0]
    first_store = next(store for store in stores if store["edge_node_id"] == first_node["id"])
    grant_url = f"/api/admin/users/{member['id']}/edge-nodes"

    assert client.get("/api/stores", headers=auth(member_token)).json() == []
    assert (
        client.post(
            f"/api/stores/{first_store['id']}/connect", headers=auth(member_token)
        ).status_code
        == 404
    )

    client.put(grant_url, headers=auth(admin), json={"node_ids": [first_node["id"]]})
    visible = client.get("/api/stores", headers=auth(member_token)).json()
    assert [store["id"] for store in visible] == [first_store["id"]]
    connection = client.post(
        f"/api/stores/{first_store['id']}/connect",
        headers=auth(member_token),
        json={"device_id": "member-device"},
    )
    assert connection.status_code == 201, connection.text

    client.put(grant_url, headers=auth(admin), json={"node_ids": []})
    assert client.get("/api/stores", headers=auth(member_token)).json() == []
    for suffix, body in (
        ("heartbeat", {"lease_id": connection.json()["lease_id"], "device_id": "member-device"}),
        ("tickets", {"host": "8.8.8.8", "port": 443}),
        (
            "disconnect",
            {"lease_id": connection.json()["lease_id"], "device_id": "member-device"},
        ),
    ):
        response = client.post(
            f"/api/stores/{first_store['id']}/{suffix}",
            headers=auth(member_token),
            json=body,
        )
        assert response.status_code == 404

    assert {store["id"] for store in client.get("/api/stores", headers=auth(admin)).json()} == {
        store["id"] for store in stores
    }


def test_authorized_user_cannot_hijack_another_users_active_lease(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    first = create_member(client, admin, "lease-first")
    second = create_member(client, admin, "lease-second")
    node = client.get("/api/admin/edge-nodes", headers=auth(admin)).json()[0]
    store = next(
        item
        for item in client.get("/api/admin/stores", headers=auth(admin)).json()
        if item["edge_node_id"] == node["id"]
    )
    for member in (first, second):
        client.put(
            f"/api/admin/users/{member['id']}/edge-nodes",
            headers=auth(admin),
            json={"node_ids": [node["id"]]},
        )
    first_token = login(client, "lease-first", "Member-password-123")
    second_token = login(client, "lease-second", "Member-password-123")
    lease = client.post(
        f"/api/stores/{store['id']}/connect",
        headers=auth(first_token),
        json={"device_id": "first-device"},
    ).json()

    assert (
        client.post(
            f"/api/stores/{store['id']}/heartbeat",
            headers=auth(second_token),
            json={"lease_id": lease["lease_id"], "device_id": "first-device"},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/stores/{store['id']}/tickets",
            headers=auth(second_token),
            json={"host": "8.8.8.8", "port": 443},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/stores/{store['id']}/disconnect",
            headers=auth(second_token),
            json={"lease_id": lease["lease_id"], "device_id": "first-device"},
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/stores/{store['id']}/heartbeat",
            headers=auth(first_token),
            json={"lease_id": lease["lease_id"], "device_id": "first-device"},
        ).status_code
        == 200
    )


def test_admin_lists_members_for_node_permission_ui_without_password_data(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "member-list")

    response = client.get("/api/admin/users", headers=auth(admin))

    assert response.status_code == 200
    assert response.json() == [
        {
            "id": member["id"],
            "username": "member-list",
            "role": "member",
            "enabled": True,
        }
    ]
    assert "password" not in response.text.lower()


def test_admin_deletes_member_and_revokes_account_grants_and_tokens(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "delete-me")
    node = client.get("/api/admin/edge-nodes", headers=auth(admin)).json()[0]
    client.put(
        f"/api/admin/users/{member['id']}/edge-nodes",
        headers=auth(admin),
        json={"node_ids": [node["id"]]},
    )
    token = login(client, "delete-me", "Member-password-123")

    deleted = client.delete(f"/api/admin/users/{member['id']}", headers=auth(admin))

    assert deleted.status_code == 204
    assert client.get("/api/me", headers=auth(token)).status_code == 401
    assert (
        client.post(
            "/api/login",
            json={"username": "delete-me", "password": "Member-password-123"},
        ).status_code
        == 401
    )
    assert member["id"] not in {
        item["id"] for item in client.get("/api/admin/users", headers=auth(admin)).json()
    }
    assert (
        client.get(f"/api/admin/users/{member['id']}/edge-nodes", headers=auth(admin)).status_code
        == 404
    )
    assert client.delete(f"/api/admin/users/{member['id']}", headers=auth(admin)).status_code == 404
    recreated = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "delete-me", "password": "Member-password-456"},
    )
    assert recreated.status_code == 201
    event = next(
        item
        for item in client.get("/api/admin/audit", headers=auth(admin)).json()
        if item["event_type"] == "user.deleted"
    )
    assert event["target_id"] == str(member["id"])
    assert event["details"]["username"] == "delete-me"
    assert "password" not in str(event).lower()


def test_admin_changes_member_password_with_sixteen_character_minimum(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    member = create_member(client, admin, "password-user")
    old_token = login(client, "password-user", "Member-password-123")
    url = f"/api/admin/users/{member['id']}/password"

    short = client.put(url, headers=auth(admin), json={"password": "too-short-123"})

    assert short.status_code == 422
    assert client.get("/api/me", headers=auth(old_token)).status_code == 200

    changed = client.put(
        url,
        headers=auth(admin),
        json={"password": "New-member-password-456"},
    )

    assert changed.status_code == 200
    assert changed.json() == {"id": member["id"], "password_changed": True}
    assert client.get("/api/me", headers=auth(old_token)).status_code == 401
    assert (
        client.post(
            "/api/login",
            json={"username": "password-user", "password": "Member-password-123"},
        ).status_code
        == 401
    )
    assert login(client, "password-user", "New-member-password-456")
    event = next(
        item
        for item in client.get("/api/admin/audit", headers=auth(admin)).json()
        if item["event_type"] == "user.password_changed"
    )
    assert event["target_id"] == str(member["id"])
    assert event["details"] == {"tokens_revoked": True}
    assert "New-member-password-456" not in str(event)
