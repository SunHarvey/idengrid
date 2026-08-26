import pytest
from edge_tunnel.app import ReplayCache
from edge_tunnel.tickets import TicketError, TicketVerifier
from fastapi.testclient import TestClient
from sqlalchemy import select

from cloudbrowser.edge_tickets import EdgeTicketIssuer
from cloudbrowser.models import EdgeNode


def _login(client: TestClient, username: str, password: str) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200
    return response.json()["access_token"]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _create_member(client: TestClient, admin: str, username: str) -> str:
    response = client.post(
        "/api/admin/users",
        headers=_auth(admin),
        json={"username": username, "password": "Member-password-123"},
    )
    assert response.status_code == 201
    return _login(client, username, "Member-password-123")


def test_central_ticket_is_accepted_by_edge_verifier() -> None:
    now = 1_000
    secret = "central-and-edge-share-this-node-secret"
    issuer = EdgeTicketIssuer(secret, "edge-sg01", clock=lambda: now)
    verifier = TicketVerifier(secret.encode(), "edge-sg01", clock=lambda: now)

    token = issuer.issue(store="42", host="example.com", port=443)
    ticket = verifier.verify(token)

    assert ticket.node == "edge-sg01"
    assert ticket.store == "42"
    assert ticket.host == "example.com"
    assert ticket.port == 443
    assert ticket.expires_at - ticket.issued_at == 60


def test_ticket_wire_contract_and_lease_lifecycle_remain_unchanged(system) -> None:
    client, _ = system
    token = _login(client, "admin", "Admin-password-123")
    store = client.get("/api/stores", headers=_auth(token)).json()[0]

    connected = client.post(f"/api/stores/{store['id']}/connect", headers=_auth(token))
    ticket = client.post(
        f"/api/stores/{store['id']}/tickets",
        headers=_auth(token),
        json={"host": "8.8.8.8", "port": 443},
    )
    disconnected = client.post(
        f"/api/stores/{store['id']}/disconnect", headers=_auth(token)
    )

    assert connected.status_code == 201
    assert connected.json()["status"] == "active"
    assert connected.json()["expires_in"] == 8 * 60 * 60
    assert ticket.status_code == 201
    assert set(ticket.json()) == {
        "ticket",
        "expires_in",
        "edge_endpoint",
        "lease_id",
    }
    assert ticket.json()["expires_in"] <= 60
    assert disconnected.status_code == 200
    assert disconnected.json()["status"] == "disconnected"


def test_edge_replay_cache_rejects_second_use_of_central_ticket() -> None:
    now = 1_000
    secret = "central-and-edge-share-this-node-secret"
    token = EdgeTicketIssuer(secret, "edge-sg01", clock=lambda: now).issue(
        store="42", host="example.com", port=443
    )
    ticket = TicketVerifier(secret.encode(), "edge-sg01", clock=lambda: now).verify(token)
    replays = ReplayCache(clock=lambda: now)

    assert replays.claim(ticket) is True
    assert replays.claim(ticket) is False


@pytest.mark.parametrize(
    ("secret", "node", "verify_at", "message"),
    [
        ("central-and-edge-share-this-node-secret", "edge-sg01", 1_061, "expired"),
        ("central-and-edge-share-this-node-secret", "edge-hk01", 1_000, "wrong node"),
        ("different-edge-signing-secret-value", "edge-sg01", 1_000, "signature"),
    ],
)
def test_edge_rejects_expired_wrong_node_or_wrong_signature_central_ticket(
    secret: str, node: str, verify_at: int, message: str
) -> None:
    token = EdgeTicketIssuer(
        "central-and-edge-share-this-node-secret", "edge-sg01", clock=lambda: 1_000
    ).issue(store="42", host="example.com", port=443)
    verifier = TicketVerifier(secret.encode(), node, clock=lambda: verify_at)

    with pytest.raises(TicketError, match=message):
        verifier.verify(token)


@pytest.mark.parametrize("unhealthy_state", ["offline", "degraded", "quarantined", "maintenance"])
def test_connect_and_ticket_fail_closed_while_existing_lease_remains_active(
    system, unhealthy_state
) -> None:
    client, _ = system
    token = _login(client, "admin", "Admin-password-123")
    store = client.get("/api/stores", headers=_auth(token)).json()[0]
    with client.app.state.db() as db:
        node = db.scalar(select(EdgeNode).where(EdgeNode.name == store["edge_node_name"]))
        node.health_status = unhealthy_state
        db.commit()

    unavailable_connect = client.post(
        f"/api/stores/{store['id']}/connect",
        headers=_auth(token),
        json={"device_id": "mac-primary"},
    )
    assert unavailable_connect.status_code == 503
    assert "secret" not in unavailable_connect.text

    with client.app.state.db() as db:
        node = db.scalar(select(EdgeNode).where(EdgeNode.name == store["edge_node_name"]))
        node.health_status = "online"
        db.commit()
    connected = client.post(
        f"/api/stores/{store['id']}/connect",
        headers=_auth(token),
        json={"device_id": "mac-primary"},
    )
    assert connected.status_code == 201

    with client.app.state.db() as db:
        node = db.scalar(select(EdgeNode).where(EdgeNode.name == store["edge_node_name"]))
        node.health_status = unhealthy_state
        db.commit()
    refused_ticket = client.post(
        f"/api/stores/{store['id']}/tickets",
        headers=_auth(token),
        json={"host": "8.8.8.8", "port": 443},
    )
    heartbeat = client.post(
        f"/api/stores/{store['id']}/heartbeat",
        headers=_auth(token),
        json={"lease_id": connected.json()["lease_id"], "device_id": "mac-primary"},
    )

    assert refused_ticket.status_code == 503
    assert "ticket" not in refused_ticket.json()
    assert "secret" not in refused_ticket.text
    assert heartbeat.status_code == 200
    assert heartbeat.json()["status"] == "active"


def test_owner_issues_per_target_ticket_for_active_lease_accepted_by_assigned_edge(system) -> None:
    client, _ = system
    token = _login(client, "admin", "Admin-password-123")
    store = client.get("/api/stores", headers=_auth(token)).json()[0]
    secret = "known-central-edge-ticket-secret-value"
    with client.app.state.db() as db:
        node = db.scalar(select(EdgeNode).where(EdgeNode.name == store["edge_node_name"]))
        node.shared_secret = secret
        db.commit()

    connection = client.post(f"/api/stores/{store['id']}/connect", headers=_auth(token))
    issued = client.post(
        f"/api/stores/{store['id']}/tickets",
        headers=_auth(token),
        json={"host": "8.8.8.8", "port": 443},
    )

    assert connection.status_code == 201
    assert set(connection.json()) >= {
        "lease_id",
        "status",
        "created_at",
        "expires_at",
        "expires_in",
        "edge_endpoint",
    }
    assert "ticket" not in connection.json()
    assert issued.status_code == 201
    body = issued.json()
    assert body["lease_id"] == connection.json()["lease_id"]
    assert body["edge_endpoint"] == store["edge_endpoint"]
    assert 0 < body["expires_in"] <= 60
    assert secret not in issued.text

    ticket = TicketVerifier(secret.encode(), store["edge_node_name"]).verify(body["ticket"])
    assert ticket.node == store["edge_node_name"]
    assert ticket.store == str(store["id"])
    assert (ticket.host, ticket.port) == ("8.8.8.8", 443)
    audit = client.get("/api/admin/audit", headers=_auth(token))
    assert secret not in audit.text


def test_ticket_endpoint_rejects_inactive_lease_wrong_owner_and_private_target(system) -> None:
    client, _ = system
    admin = _login(client, "admin", "Admin-password-123")
    other = _create_member(client, admin, "other-owner")
    store = client.get("/api/stores", headers=_auth(admin)).json()[0]
    url = f"/api/stores/{store['id']}/tickets"

    inactive = client.post(url, headers=_auth(admin), json={"host": "8.8.8.8", "port": 443})
    wrong_owner = client.post(url, headers=_auth(other), json={"host": "8.8.8.8", "port": 443})
    client.post(f"/api/stores/{store['id']}/connect", headers=_auth(admin))
    private = client.post(url, headers=_auth(admin), json={"host": "127.0.0.1", "port": 443})

    assert inactive.status_code == 409
    assert wrong_owner.status_code == 404
    assert private.status_code == 403
    assert "ticket" not in private.json()


def test_different_stores_hold_simultaneous_leases_and_issue_edge_valid_tickets(system) -> None:
    client, _ = system
    admin = _login(client, "admin", "Admin-password-123")
    stores = client.get("/api/stores", headers=_auth(admin)).json()[:2]
    secrets_by_node = {
        store["edge_node_name"]: f"shared-secret-for-{store['edge_node_name']}-value"
        for store in stores
    }
    with client.app.state.db() as db:
        for node_name, secret in secrets_by_node.items():
            node = db.scalar(select(EdgeNode).where(EdgeNode.name == node_name))
            node.shared_secret = secret
        db.commit()

    connections = [
        client.post(f"/api/stores/{store['id']}/connect", headers=_auth(admin)) for store in stores
    ]
    issued = [
        client.post(
            f"/api/stores/{store['id']}/tickets",
            headers=_auth(admin),
            json={"host": "8.8.8.8", "port": 443},
        )
        for store in stores
    ]

    assert all(response.status_code == 201 for response in connections + issued)
    assert connections[0].json()["lease_id"] != connections[1].json()["lease_id"]
    for store, response in zip(stores, issued, strict=True):
        ticket = TicketVerifier(
            secrets_by_node[store["edge_node_name"]].encode(), store["edge_node_name"]
        ).verify(response.json()["ticket"])
        assert ticket.store == str(store["id"])
