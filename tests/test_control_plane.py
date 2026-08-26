from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import select

from cloudbrowser.app import create_app
from cloudbrowser.models import ManagedStore
from cloudbrowser.runner import FakeBrowserRunner
from tests.example_topology import EXAMPLE_TOPOLOGY


def login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_pilot_store_seed_runs_once_and_does_not_recreate_renamed_stores(tmp_path: Path):
    database_url = f"sqlite:///{tmp_path / 'store-seed.db'}"
    app = create_app(
        database_url=database_url,
        secret_key="store-seed-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
    )
    renamed = ["主控节点", "新加坡01", "香港01"]
    with app.state.db() as db:
        stores = db.scalars(select(ManagedStore).order_by(ManagedStore.id)).all()
        for store, label in zip(stores, renamed, strict=True):
            store.label = label
        db.commit()

    restarted = create_app(
        database_url=database_url,
        secret_key="store-seed-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
    )

    with restarted.state.db() as db:
        stores = db.scalars(select(ManagedStore).order_by(ManagedStore.id)).all()
        assert [store.label for store in stores] == renamed


def test_admin_lists_seeded_pilot_nodes_and_stores_without_secrets(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")

    nodes_response = client.get("/api/admin/edge-nodes", headers=auth(admin))
    stores_response = client.get("/api/admin/stores", headers=auth(admin))

    assert nodes_response.status_code == 200
    assert stores_response.status_code == 200
    nodes = nodes_response.json()
    stores = stores_response.json()
    assert [(node["name"], node["endpoint"]) for node in nodes] == [
        ("sg-browser", "https://control-edge.example.com"),
        ("edge-sg01", "https://edge-sg.example.com"),
        ("edge-hk01", "https://edge-hk.example.com"),
    ]
    assert [store["label"] for store in stores] == ["Store 01", "Store 02", "Store 03"]
    assert [store["edge_node_name"] for store in stores] == [
        "sg-browser",
        "edge-sg01",
        "edge-hk01",
    ]
    health_fields = {
        "health_status",
        "last_seen_at",
        "latency_ms",
        "active_connections",
        "max_connections",
        "accepted_connections",
        "denied_connections",
        "expected_public_ipv4",
        "actual_public_ipv4",
        "load_1m",
        "memory_total_bytes",
        "memory_available_bytes",
        "disk_total_bytes",
        "disk_free_bytes",
        "uptime_seconds",
        "agent_version",
        "last_error",
    }
    assert health_fields <= nodes[0].keys()
    assert health_fields <= stores[0].keys()
    assert nodes[0]["health_status"] == "online"
    assert stores[0]["health_status"] == "online"
    assert stores[0]["active_connections"] == 0
    assert [node["expected_public_ipv4"] for node in nodes] == [
        "192.0.2.10",
        "198.51.100.20",
        "203.0.113.30",
    ]
    assert stores[0]["expected_egress_ips"] == ["192.0.2.10"]
    assert all(store["owner_user_id"] is not None for store in stores)
    assert "shared_secret" not in nodes_response.text
    assert "shared_secret" not in stores_response.text


def test_admin_crud_edge_nodes_and_capabilities_without_returning_secret(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")

    created = client.post(
        "/api/admin/edge-nodes",
        headers=auth(admin),
        json={
            "name": "edge-test",
            "endpoint": "https://edge-test.example.test",
            "shared_secret": "node-secret-never-return-this-value",
            "expected_public_ipv4": "8.8.8.8",
        },
    )
    assert created.status_code == 201
    node = created.json()
    assert node["name"] == "edge-test"
    assert node["expected_public_ipv4"] == "8.8.8.8"
    assert "shared_secret" not in created.text

    capability = client.post(
        f"/api/admin/edge-nodes/{node['id']}/capabilities",
        headers=auth(admin),
        json={"name": "browser", "config": {"max_sessions": 2}},
    )
    assert capability.status_code == 201
    capability_id = capability.json()["id"]
    changed_capability = client.patch(
        f"/api/admin/edge-capabilities/{capability_id}",
        headers=auth(admin),
        json={"name": "browser", "config": {"max_sessions": 3}},
    )
    assert changed_capability.status_code == 200
    assert client.get(
        f"/api/admin/edge-nodes/{node['id']}/capabilities", headers=auth(admin)
    ).json() == [
        {
            "id": capability_id,
            "edge_node_id": node["id"],
            "name": "browser",
            "config": {"max_sessions": 3},
        }
    ]

    updated = client.patch(
        f"/api/admin/edge-nodes/{node['id']}",
        headers=auth(admin),
        json={"enabled": False, "shared_secret": "rotated-secret-never-return-this-value"},
    )
    assert updated.status_code == 200
    assert updated.json()["enabled"] is False
    assert "secret" not in updated.text

    assert (
        client.delete(
            f"/api/admin/edge-capabilities/{capability_id}", headers=auth(admin)
        ).status_code
        == 204
    )
    assert (
        client.delete(f"/api/admin/edge-nodes/{node['id']}", headers=auth(admin)).status_code == 204
    )


def test_admin_crud_stores_and_members_cannot_access_admin_control_plane(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    user = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "owner-a", "password": "Member-password-123"},
    ).json()
    nodes = client.get("/api/admin/edge-nodes", headers=auth(admin)).json()

    created = client.post(
        "/api/admin/stores",
        headers=auth(admin),
        json={
            "label": "Store 04",
            "owner_user_id": user["id"],
            "edge_node_id": nodes[0]["id"],
        },
    )
    assert created.status_code == 201
    store = created.json()
    assert store["label"] == "Store 04"

    updated = client.patch(
        f"/api/admin/stores/{store['id']}",
        headers=auth(admin),
        json={"edge_node_id": nodes[1]["id"], "enabled": False},
    )
    assert updated.status_code == 200
    assert updated.json()["edge_node_name"] == "edge-sg01"
    assert updated.json()["enabled"] is False

    member = login(client, "owner-a", "Member-password-123")
    assert client.get("/api/admin/stores", headers=auth(member)).status_code == 403
    assert client.delete(f"/api/admin/stores/{store['id']}", headers=auth(admin)).status_code == 204


def test_member_lists_connects_and_disconnects_granted_node_stores_with_exclusive_leases(system):
    client, _ = system
    admin = login(client, "admin", "Admin-password-123")
    owner = client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "owner-a", "password": "Member-password-123"},
    ).json()
    client.post(
        "/api/admin/users",
        headers=auth(admin),
        json={"username": "owner-b", "password": "Member-password-123"},
    )
    stores = client.get("/api/admin/stores", headers=auth(admin)).json()
    for store in stores[:2]:
        response = client.patch(
            f"/api/admin/stores/{store['id']}",
            headers=auth(admin),
            json={"owner_user_id": owner["id"]},
        )
        assert response.status_code == 200
    client.put(
        f"/api/admin/users/{owner['id']}/edge-nodes",
        headers=auth(admin),
        json={"node_ids": [store["edge_node_id"] for store in stores[:2]]},
    )

    owner_token = login(client, "owner-a", "Member-password-123")
    other_token = login(client, "owner-b", "Member-password-123")
    owned = client.get("/api/stores", headers=auth(owner_token))
    assert owned.status_code == 200
    assert [item["label"] for item in owned.json()] == ["Store 01", "Store 02"]
    assert owned.json()[0]["health_status"] == "online"
    assert owned.json()[0]["latency_ms"] is None
    assert owned.json()[0]["max_connections"] == 0
    assert (
        client.post(f"/api/stores/{stores[0]['id']}/connect", headers=auth(other_token)).status_code
        == 404
    )

    first = client.post(f"/api/stores/{stores[0]['id']}/connect", headers=auth(owner_token))
    second = client.post(f"/api/stores/{stores[1]['id']}/connect", headers=auth(owner_token))
    assert first.status_code == 201
    assert second.status_code == 201
    assert (
        client.post(f"/api/stores/{stores[0]['id']}/connect", headers=auth(owner_token)).status_code
        == 201
    )
    leases = client.get("/api/admin/store-leases", headers=auth(admin))
    assert leases.status_code == 200
    assert len(leases.json()) == 2
    assert {item["store_id"] for item in leases.json()} == {
        stores[0]["id"],
        stores[1]["id"],
    }
    assert "ticket" not in leases.text
    assert "secret" not in leases.text

    connection = first.json()
    assert connection["edge_endpoint"] == "https://control-edge.example.com"
    assert connection["expires_in"] == 8 * 60 * 60
    assert connection["status"] == "active"
    assert connection["created_at"]
    assert connection["expires_at"]
    assert "ticket" not in connection
    assert "shared_secret" not in first.text
    assert "secret" not in first.text

    disconnected = client.post(
        f"/api/stores/{stores[0]['id']}/disconnect", headers=auth(owner_token)
    )
    assert disconnected.status_code == 200
    assert disconnected.json()["status"] == "disconnected"
    assert (
        client.post(f"/api/stores/{stores[0]['id']}/connect", headers=auth(owner_token)).status_code
        == 201
    )


def test_same_edge_store_allows_independent_users_and_devices(system):
    client, _ = system
    admin_token = login(client, "admin", "Admin-password-123")
    users = []
    for username in ("parallel-a", "parallel-b"):
        created = client.post(
            "/api/admin/users",
            headers=auth(admin_token),
            json={"username": username, "password": "Member-password-123"},
        )
        assert created.status_code == 201
        users.append(created.json())

    store = client.get("/api/admin/stores", headers=auth(admin_token)).json()[1]
    for user in users:
        granted = client.put(
            f"/api/admin/users/{user['id']}/edge-nodes",
            headers=auth(admin_token),
            json={"node_ids": [store["edge_node_id"]]},
        )
        assert granted.status_code == 200

    token_a = login(client, "parallel-a", "Member-password-123")
    token_b = login(client, "parallel-b", "Member-password-123")
    store_url = f"/api/stores/{store['id']}"
    connections = []
    for token, device_id in (
        (token_a, "parallel-a-device-1"),
        (token_a, "parallel-a-device-2"),
        (token_b, "parallel-b-device-1"),
    ):
        response = client.post(
            f"{store_url}/connect",
            headers=auth(token),
            json={"device_id": device_id},
        )
        assert response.status_code == 201, response.text
        connections.append(response.json())

    assert len({item["lease_id"] for item in connections}) == 3
    admin_store = next(
        item
        for item in client.get("/api/admin/stores", headers=auth(admin_token)).json()
        if item["id"] == store["id"]
    )
    assert admin_store["active_connection_count"] == 3
    assert {lease["device_id"] for lease in admin_store["active_leases"]} == {
        "parallel-a-device-1",
        "parallel-a-device-2",
        "parallel-b-device-1",
    }
    recovered = client.post(
        f"{store_url}/connect",
        headers=auth(token_a),
        json={"device_id": "parallel-a-device-1"},
    )
    assert recovered.status_code == 201
    assert recovered.json()["lease_id"] == connections[0]["lease_id"]
    assert recovered.json()["recovered"] is True

    assert (
        client.post(
            f"{store_url}/tickets",
            headers=auth(token_a),
            json={"host": "8.8.8.8", "port": 443},
        ).status_code
        == 409
    )
    for token, device_id, connection in (
        (token_a, "parallel-a-device-1", connections[0]),
        (token_a, "parallel-a-device-2", connections[1]),
        (token_b, "parallel-b-device-1", connections[2]),
    ):
        ticket = client.post(
            f"{store_url}/tickets",
            headers=auth(token),
            json={
                "host": "8.8.8.8",
                "port": 443,
                "lease_id": connection["lease_id"],
                "device_id": device_id,
            },
        )
        assert ticket.status_code == 201, ticket.text
        assert ticket.json()["lease_id"] == connection["lease_id"]

    disconnected = client.post(
        f"{store_url}/disconnect",
        headers=auth(token_a),
        json={
            "lease_id": connections[0]["lease_id"],
            "device_id": "parallel-a-device-1",
        },
    )
    assert disconnected.status_code == 200
    for token, device_id, connection in (
        (token_a, "parallel-a-device-2", connections[1]),
        (token_b, "parallel-b-device-1", connections[2]),
    ):
        heartbeat = client.post(
            f"{store_url}/heartbeat",
            headers=auth(token),
            json={"lease_id": connection["lease_id"], "device_id": device_id},
        )
        assert heartbeat.status_code == 200
