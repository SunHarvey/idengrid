from __future__ import annotations

import csv
import io
import json

from fastapi.testclient import TestClient


def login(client: TestClient, username: str = "admin", password: str = "Admin-password-123") -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_admin_store_includes_safe_active_lease_and_force_disconnect_audits(system):
    client, _ = system
    token = login(client)
    store = client.get("/api/admin/stores", headers=auth(token)).json()[0]
    connected = client.post(
        f"/api/stores/{store['id']}/connect",
        headers=auth(token),
        json={"device_id": "admin-laptop"},
    )
    assert connected.status_code == 201

    listed = client.get("/api/admin/stores", headers=auth(token))
    assert listed.status_code == 200
    current = listed.json()[0]["active_lease"]
    assert current == {
        "id": connected.json()["lease_id"],
        "username": "admin",
        "device_id": "admin-laptop",
        "last_heartbeat_at": current["last_heartbeat_at"],
        "expires_at": current["expires_at"],
    }
    assert current["last_heartbeat_at"]
    assert current["expires_at"]
    assert "token" not in listed.text.lower()
    assert "secret" not in listed.text.lower()

    released = client.post(f"/api/admin/stores/{store['id']}/force-disconnect", headers=auth(token))
    assert released.status_code == 200
    assert released.json() == {"lease_id": current["id"], "status": "disconnected"}
    assert (
        client.post(
            f"/api/admin/stores/{store['id']}/force-disconnect", headers=auth(token)
        ).status_code
        == 409
    )
    assert client.get("/api/admin/stores", headers=auth(token)).json()[0]["active_lease"] is None

    event = client.get(
        "/api/admin/audit?event_type=managed_store.force_disconnected", headers=auth(token)
    ).json()[0]
    assert event["actor_user_id"] is not None
    assert event["target_type"] == "managed_store"
    assert event["target_id"] == str(store["id"])
    assert event["details"] == {
        "lease_id": current["id"],
        "username": "admin",
        "device_id": "admin-laptop",
    }
    assert "secret" not in json.dumps(event).lower()


def test_store_patch_rejects_rebind_during_active_lease_but_allows_safe_fields(system):
    client, _ = system
    token = login(client)
    stores = client.get("/api/admin/stores", headers=auth(token)).json()
    store = stores[0]
    connected = client.post(
        f"/api/stores/{store['id']}/connect",
        headers=auth(token),
        json={"device_id": "bound-device"},
    )
    assert connected.status_code == 201

    rejected = client.patch(
        f"/api/admin/stores/{store['id']}",
        headers=auth(token),
        json={"edge_node_id": stores[1]["edge_node_id"]},
    )
    assert rejected.status_code == 409
    renamed = client.patch(
        f"/api/admin/stores/{store['id']}",
        headers=auth(token),
        json={"label": "Renamed safely", "enabled": False},
    )
    assert renamed.status_code == 200
    assert renamed.json()["label"] == "Renamed safely"
    assert renamed.json()["enabled"] is False
    assert renamed.json()["edge_node_id"] == store["edge_node_id"]

    event = client.get(
        "/api/admin/audit?event_type=managed_store.updated&limit=1", headers=auth(token)
    ).json()[0]
    assert event["details"] == {"changed_fields": ["enabled", "label"]}


def test_node_validation_maintenance_transitions_and_write_only_secret(system):
    client, _ = system
    token = login(client)
    base = {
        "name": "managed-edge",
        "endpoint": "https://managed-edge.example",
        "shared_secret": "initial-secret-never-return",
        "expected_public_ipv4": "8.8.8.8",
    }
    for bad_ip in ["10.0.0.1", "2001:4860:4860::8888", "not-an-ip"]:
        response = client.post(
            "/api/admin/edge-nodes",
            headers=auth(token),
            json={**base, "expected_public_ipv4": bad_ip},
        )
        assert response.status_code == 422
    assert (
        client.post(
            "/api/admin/edge-nodes",
            headers=auth(token),
            json={**base, "endpoint": "http://managed-edge.example"},
        ).status_code
        == 422
    )
    credential_endpoint = client.post(
        "/api/admin/edge-nodes",
        headers=auth(token),
        json={**base, "endpoint": "https://user:password@managed-edge.example"},
    )
    assert credential_endpoint.status_code == 422
    assert "password" not in credential_endpoint.text.lower()

    created = client.post("/api/admin/edge-nodes", headers=auth(token), json=base)
    assert created.status_code == 201, created.text
    node = created.json()
    assert node["maintenance_mode"] is False
    assert "secret" not in created.text.lower()

    maintenance = client.patch(
        f"/api/admin/edge-nodes/{node['id']}",
        headers=auth(token),
        json={"maintenance_mode": True, "shared_secret": "rotated-secret-never-return"},
    )
    assert maintenance.status_code == 200
    assert maintenance.json()["health_status"] == "maintenance"
    assert maintenance.json()["maintenance_mode"] is True
    assert "secret" not in maintenance.text.lower()
    assert client.post(
        "/api/stores/1/connect", headers=auth(token), json={"device_id": "maintenance-test"}
    ).status_code in {201, 503}  # unrelated seeded node remains governed by its own health

    resumed = client.patch(
        f"/api/admin/edge-nodes/{node['id']}",
        headers=auth(token),
        json={"maintenance_mode": False},
    )
    assert resumed.status_code == 200
    assert resumed.json()["health_status"] == "unknown"
    disabled = client.patch(
        f"/api/admin/edge-nodes/{node['id']}", headers=auth(token), json={"enabled": False}
    )
    assert disabled.json()["health_status"] == "disabled"
    reenabled = client.patch(
        f"/api/admin/edge-nodes/{node['id']}", headers=auth(token), json={"enabled": True}
    )
    assert reenabled.json()["health_status"] == "unknown"

    assert (
        client.patch(
            f"/api/admin/edge-nodes/{node['id']}",
            headers=auth(token),
            json={"expected_public_ipv4": "127.0.0.1"},
        ).status_code
        == 422
    )
    assert (
        client.patch(
            f"/api/admin/edge-nodes/{node['id']}",
            headers=auth(token),
            json={"endpoint": "javascript:https://managed-edge.example"},
        ).status_code
        == 422
    )


def test_audit_filters_csv_export_authorization_and_formula_safety(system):
    client, _ = system
    admin = login(client)
    member = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "audit-member", "password": "Member-password-123"},
    ).json()
    member_token = login(client, "audit-member", "Member-password-123")
    client.post("/api/login", json={"username": "=2+2", "password": "wrong-password"})

    filters = (
        f"event_type=workspace.user_assigned&actor_user_id=1&target_type=user"
        f"&target_id={member['id']}&limit=1"
    )
    response = client.get(f"/api/admin/audit?{filters}", headers=auth(admin))
    assert response.status_code == 200
    assert len(response.json()) == 1
    assert response.json()[0]["event_type"] == "workspace.user_assigned"
    assert response.json()[0]["target_id"] == str(member["id"])
    assert client.get("/api/admin/audit?limit=0", headers=auth(admin)).status_code == 422
    assert client.get("/api/admin/audit?limit=501", headers=auth(admin)).status_code == 422
    assert client.get("/api/admin/audit", headers=auth(member_token)).status_code == 403

    exported = client.get(
        "/api/admin/audit.csv?event_type=login.failed&target_id=%3D2%2B2&limit=10",
        headers=auth(admin),
    )
    assert exported.status_code == 200
    assert exported.headers["content-type"].startswith("text/csv")
    assert "attachment" in exported.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(exported.text)))
    assert len(rows) == 1
    assert rows[0]["target_id"] == "'=2+2"
    assert client.get("/api/admin/audit.csv", headers=auth(member_token)).status_code == 403


def test_store_and_node_crud_conflicts_are_controlled_and_never_leak_secrets(system):
    client, _ = system
    token = login(client)
    headers = auth(token)
    nodes = client.get("/api/admin/edge-nodes", headers=headers).json()
    stores = client.get("/api/admin/stores", headers=headers).json()

    duplicate_endpoint = client.post(
        "/api/admin/edge-nodes",
        headers=headers,
        json={
            "name": "different-name",
            "endpoint": nodes[0]["endpoint"],
            "shared_secret": "duplicate-endpoint-secret",
            "expected_public_ipv4": "8.8.4.4",
        },
    )
    assert duplicate_endpoint.status_code == 409
    assert "secret" not in duplicate_endpoint.text.lower()
    duplicate_node_name = client.patch(
        f"/api/admin/edge-nodes/{nodes[1]['id']}",
        headers=headers,
        json={"name": nodes[0]["name"]},
    )
    assert duplicate_node_name.status_code == 409
    assert (
        client.delete(f"/api/admin/edge-nodes/{nodes[0]['id']}", headers=headers).status_code == 409
    )

    duplicate_store = client.post(
        "/api/admin/stores",
        headers=headers,
        json={"label": stores[0]["label"], "edge_node_id": nodes[0]["id"]},
    )
    assert duplicate_store.status_code == 409
    duplicate_store_update = client.patch(
        f"/api/admin/stores/{stores[1]['id']}",
        headers=headers,
        json={"label": stores[0]["label"]},
    )
    assert duplicate_store_update.status_code == 409
    assert "secret" not in client.get("/api/admin/edge-nodes", headers=headers).text.lower()
    assert "secret" not in client.get("/api/admin/stores", headers=headers).text.lower()
