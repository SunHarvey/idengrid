from __future__ import annotations

import hashlib
import json
import shlex
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

import cloudbrowser.app as app_module
from cloudbrowser.app import create_app
from cloudbrowser.models import AuditEvent, EdgeNode, NodeEnrollment
from cloudbrowser.runner import FakeBrowserRunner


def login(client: TestClient) -> str:
    response = client.post(
        "/api/login", json={"username": "admin", "password": "Admin-password-123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_enrollment(client: TestClient, token: str, **overrides):
    body = {
        "node_name": "edge-wizard-01",
        "endpoint": "https://edge-wizard-01.example.com",
        "expected_public_ipv4": "8.8.8.8",
    }
    body.update(overrides)
    return client.post("/api/admin/edge-enrollments", headers=auth(token), json=body)


def test_node_enrollment_table_is_idempotent_and_has_one_active_per_node(system):
    client, _ = system
    columns = {
        column["name"]
        for column in inspect(client.app.state.db.kw["bind"]).get_columns("node_enrollments")
    }
    assert columns == {
        "id",
        "edge_node_id",
        "created_by_user_id",
        "token_hash",
        "report_token_hash",
        "status",
        "phase",
        "expires_at",
        "claimed_at",
        "updated_at",
        "last_error",
        "claimed_public_ipv4",
        "agent_version",
    }
    with client.app.state.db() as db:
        node = db.scalar(select(EdgeNode).order_by(EdgeNode.id))
        first = NodeEnrollment(
            id="first",
            edge_node_id=node.id,
            created_by_user_id=1,
            token_hash="a" * 64,
            status="pending",
            expires_at=datetime.now(UTC) + timedelta(minutes=15),
        )
        db.add(first)
        db.commit()
        db.add(
            NodeEnrollment(
                id="second",
                edge_node_id=node.id,
                created_by_user_id=1,
                token_hash="b" * 64,
                status="pending",
                expires_at=datetime.now(UTC) + timedelta(minutes=15),
            )
        )
        with pytest.raises(IntegrityError):
            db.commit()


def test_admin_creation_returns_token_once_and_persists_only_hash(system):
    client, _ = system
    admin = login(client)
    response = create_enrollment(client, admin)
    assert response.status_code == 201, response.text
    result = response.json()
    raw_token = result["enrollment_token"]
    enrollment_id, random_secret = raw_token.split(".", 1)
    assert enrollment_id == result["id"]
    assert len(random_secret) >= 32
    assert shlex.split(result["install_command"])[-1] == raw_token
    assert "https://" in result["install_command"]
    assert result["expires_at"]

    with client.app.state.db() as db:
        enrollment = db.get(NodeEnrollment, enrollment_id)
        node = db.get(EdgeNode, enrollment.edge_node_id)
        assert enrollment.token_hash == hashlib.sha256(raw_token.encode()).hexdigest()
        assert raw_token not in json.dumps(
            {key: value for key, value in vars(enrollment).items() if key != "_sa_instance_state"},
            default=str,
        )
        assert node.enabled is False
        assert node.health_status == "disabled"
        assert len(node.shared_secret) >= 32
        events = db.scalars(select(AuditEvent).where(AuditEvent.target_id == enrollment_id)).all()
        assert events
        assert raw_token not in "".join(event.details_json for event in events)
        assert node.shared_secret not in "".join(event.details_json for event in events)

    listed = client.get("/api/admin/edge-enrollments", headers=auth(admin))
    assert listed.status_code == 200
    assert result["id"] in listed.text
    for forbidden in (raw_token, random_secret, "token_hash", "report_token_hash", "shared_secret"):
        assert forbidden not in listed.text


@pytest.mark.parametrize(
    ("endpoint", "ip"),
    [
        ("http://edge.example.com", "8.8.8.8"),
        ("https://u:p@edge.example.com", "8.8.8.8"),
        ("https://edge.example.com", "10.0.0.1"),
        ("https://edge.example.com", "2001:4860::8888"),
    ],
)
def test_admin_creation_requires_safe_endpoint_and_global_ipv4(system, endpoint, ip):
    client, _ = system
    response = create_enrollment(client, login(client), endpoint=endpoint, expected_public_ipv4=ip)
    assert response.status_code == 422
    assert "p@" not in response.text


def claim(client: TestClient, raw_token: str, **overrides):
    body = {"node_name": "edge-wizard-01", "public_ipv4": "8.8.8.8", "agent_version": "1.2.3"}
    body.update(overrides)
    return client.post(
        "/api/edge-enrollments/claim",
        headers={"Authorization": f"Enrollment {raw_token}"},
        json=body,
    )


def test_claim_is_one_time_bound_and_returns_secrets_once(system):
    client, _ = system
    admin = login(client)
    created = create_enrollment(client, admin).json()
    raw = created["enrollment_token"]

    accepted = claim(client, raw)
    assert accepted.status_code == 200, accepted.text
    result = accepted.json()
    assert result["node_name"] == "edge-wizard-01"
    assert result["domain"] == "edge-wizard-01.example.com"
    assert result["edge_ticket_secret"]
    assert result["report_token"]
    assert result["package_url"].startswith("https://")
    assert len(result["package_sha256"]) == 64
    assert result["resources"] == {
        "max_connections": 256,
        "max_frame_bytes": 1_048_576,
        "max_bytes": 2_147_483_648,
        "idle_timeout": 300,
        "max_duration": 28_800,
        "connect_timeout": 10,
        "ticket_max_ttl": 60,
    }

    replay = claim(client, raw)
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid or expired enrollment"}
    listed = client.get("/api/admin/edge-enrollments", headers=auth(admin))
    assert raw not in listed.text
    assert result["report_token"] not in listed.text
    assert result["edge_ticket_secret"] not in listed.text

    with client.app.state.db() as db:
        item = db.get(NodeEnrollment, created["id"])
        node = db.get(EdgeNode, item.edge_node_id)
        assert item.status == "claimed"
        assert item.claimed_at is not None
        assert item.claimed_public_ipv4 == "8.8.8.8"
        assert item.agent_version == "1.2.3"
        assert item.report_token_hash == hashlib.sha256(result["report_token"].encode()).hexdigest()
        assert result["report_token"] not in repr(vars(item))
        assert result["edge_ticket_secret"] == node.shared_secret


def test_package_verification_failure_does_not_consume_legacy_linux_claim(
    system, tmp_path, monkeypatch
):
    client, _ = system
    package = tmp_path / "edge-tunnel.tar.gz"
    package.write_bytes(b"tampered-package")
    package.with_suffix(package.suffix + ".sha256").write_text(
        f"{'0' * 64}  {package.name}\n", encoding="ascii"
    )
    monkeypatch.setattr(app_module, "LINUX_EDGE_PACKAGE_PATH", package)
    created = create_enrollment(client, login(client)).json()

    response = claim(client, created["enrollment_token"])

    assert response.status_code == 503
    with client.app.state.db() as db:
        enrollment = db.get(NodeEnrollment, created["id"])
        assert enrollment.status == "pending"
        assert enrollment.claimed_at is None
        assert enrollment.token_hash == hashlib.sha256(
            created["enrollment_token"].encode()
        ).hexdigest()


def test_claim_rejects_wrong_node_ip_id_expiry_and_revoke_uniformly(system):
    client, _ = system
    admin = login(client)
    cases = [
        ({"node_name": "wrong"}, None),
        ({"public_ipv4": "8.8.4.4"}, None),
    ]
    for index, (override, _) in enumerate(cases):
        made = create_enrollment(
            client,
            admin,
            node_name=f"edge-wizard-{index + 2:02d}",
            endpoint=f"https://edge-wizard-{index + 2:02d}.example.com",
        ).json()
        claims = {"node_name": f"edge-wizard-{index + 2:02d}", **override}
        response = claim(client, made["enrollment_token"], **claims)
        assert response.status_code == 401
        assert response.json() == {"detail": "Invalid or expired enrollment"}

    expired = create_enrollment(
        client, admin, node_name="edge-expired", endpoint="https://edge-expired.example.com"
    ).json()
    with client.app.state.db() as db:
        item = db.get(NodeEnrollment, expired["id"])
        item.expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    assert claim(client, expired["enrollment_token"], node_name="edge-expired").status_code == 401

    revoked = create_enrollment(
        client, admin, node_name="edge-revoked", endpoint="https://edge-revoked.example.com"
    ).json()
    assert (
        client.post(
            f"/api/admin/edge-enrollments/{revoked['id']}/revoke", headers=auth(admin)
        ).status_code
        == 200
    )
    assert claim(client, revoked["enrollment_token"], node_name="edge-revoked").status_code == 401

    wrong_id = "f" * 32 + "." + "x" * 43
    assert claim(client, wrong_id).status_code == 401


def test_regenerate_invalidates_old_token_and_only_allows_safe_states(system):
    client, _ = system
    admin = login(client)
    made = create_enrollment(client, admin).json()
    regenerated = client.post(
        f"/api/admin/edge-enrollments/{made['id']}/regenerate", headers=auth(admin)
    )
    assert regenerated.status_code == 200
    new_token = regenerated.json()["enrollment_token"]
    assert new_token != made["enrollment_token"]
    assert claim(client, made["enrollment_token"]).status_code == 401
    accepted = claim(client, new_token)
    assert accepted.status_code == 200
    assert (
        client.post(
            f"/api/admin/edge-enrollments/{made['id']}/regenerate", headers=auth(admin)
        ).status_code
        == 409
    )


def test_report_auth_phase_error_sanitization_and_ready_enable(system):
    client, _ = system
    admin = login(client)
    made = create_enrollment(client, admin).json()
    claimed = claim(client, made["enrollment_token"]).json()
    url = "/api/edge-enrollments/report"
    assert client.post(url, json={"phase": "installing"}).status_code == 401
    assert (
        client.post(
            url, headers={"Authorization": "Report wrong"}, json={"phase": "installing"}
        ).status_code
        == 401
    )
    headers = {"Authorization": f"Report {claimed['report_token']}"}
    assert client.post(url, headers=headers, json={"phase": "arbitrary"}).status_code == 422
    assert client.post(url, headers=headers, json={"phase": "installing"}).status_code == 200
    failed = client.post(
        url, headers=headers, json={"phase": "failed", "error": "bad\nsecret\x00detail"}
    )
    assert failed.status_code == 200
    listed = client.get("/api/admin/edge-enrollments", headers=auth(admin)).json()[0]
    assert listed["last_error"] == "bad secret detail"
    ready = client.post(url, headers=headers, json={"phase": "ready"})
    assert ready.status_code == 200
    with client.app.state.db() as db:
        item = db.get(NodeEnrollment, made["id"])
        node = db.get(EdgeNode, item.edge_node_id)
        assert item.status == "ready"
        assert node.enabled is True
        assert node.health_status == "unknown"


def test_public_claim_is_body_size_bounded(system):
    client, _ = system
    response = client.post(
        "/api/edge-enrollments/claim",
        headers={"Authorization": "Enrollment x.y", "Content-Length": "5000"},
        content=b"{}",
    )
    assert response.status_code == 413


def test_claim_source_ip_verifier_is_injectable_and_enforced(tmp_path):
    source = ["8.8.4.4"]
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'source.db'}",
        secret_key="source-verifier-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        enrollment_source_ip=lambda request: source[0],
    )
    with TestClient(app) as client:
        admin = login(client)
        made = create_enrollment(client, admin).json()
        rejected = claim(client, made["enrollment_token"])
        assert rejected.status_code == 401
        source[0] = "8.8.8.8"
        assert claim(client, made["enrollment_token"]).status_code == 200
