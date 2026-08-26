from __future__ import annotations

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import inspect, select

from cloudbrowser.app import create_app
from cloudbrowser.models import AuditEvent, EdgeNode, NodeEnrollment, NodeRegistrationRequest
from cloudbrowser.runner import FakeBrowserRunner


@pytest.fixture()
def registration_system(tmp_path):
    admin_key = tmp_path / "admin.pub"
    admin_key.write_bytes(
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        + b" admin@example\n"
    )
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'registration.db'}",
        secret_key="registration-test-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        public_origin="https://central.example",
        enrollment_source_ip=lambda request: "8.8.8.8",
        admin_ssh_public_key_file=str(admin_key),
    )
    with TestClient(app) as client:
        yield client


def key_material():
    private = Ed25519PrivateKey.generate()
    public_pem = (
        private.public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    return private, public_pem


def registration_body(public_key_pem: str, **overrides):
    body = {
        "public_key_pem": public_key_pem,
        "machine_fingerprint": hashlib.sha256(b"machine-id").hexdigest(),
        "reported_hostname": "rocky-edge",
        "public_ipv4": "8.8.8.8",
        "os_name": "Rocky Linux 9",
        "cpu_count": 4,
        "memory_total_bytes": 8 * 1024**3,
        "disk_total_bytes": 100 * 1024**3,
        "agent_version": "1.0.0",
    }
    body.update(overrides)
    return body


def register(client: TestClient, public_key_pem: str, **overrides):
    return client.post(
        "/api/node-registration-requests",
        json=registration_body(public_key_pem, **overrides),
    )


def registration_auth(created: dict) -> dict[str, str]:
    return {
        "Authorization": f"Registration {created['request_id']}.{created['registration_token']}"
    }


def proof_message(request_id: str, challenge: str, public_ip: str, machine: str) -> bytes:
    return (
        f"hermes-node-registration-v1\n{request_id}\n{challenge}\n{public_ip}\n{machine}\n".encode()
    )


def prove(client: TestClient, created: dict, private: Ed25519PrivateKey, **overrides):
    machine = hashlib.sha256(b"machine-id").hexdigest()
    signature = private.sign(
        proof_message(created["request_id"], created["challenge"], "8.8.8.8", machine)
    )
    body = {
        "challenge": created["challenge"],
        "signature": base64.b64encode(signature).decode(),
    }
    body.update(overrides)
    return client.post(
        f"/api/node-registration-requests/{created['request_id']}/proof",
        headers=registration_auth(created),
        json=body,
    )


def login(client: TestClient) -> str:
    response = client.post(
        "/api/login", json={"username": "admin", "password": "Admin-password-123"}
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def admin_auth(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {login(client)}"}


def test_node_registration_request_table_has_security_fields(system):
    client, _ = system
    columns = {
        column["name"]
        for column in inspect(client.app.state.db.kw["bind"]).get_columns(
            "node_registration_requests"
        )
    }
    assert columns == {
        "id",
        "status",
        "public_key_pem",
        "public_key_fingerprint",
        "machine_fingerprint",
        "reported_hostname",
        "actual_public_ipv4",
        "os_name",
        "cpu_count",
        "memory_total_bytes",
        "disk_total_bytes",
        "agent_version",
        "challenge_hash",
        "registration_token_hash",
        "challenge_expires_at",
        "created_at",
        "updated_at",
        "proved_at",
        "decided_at",
        "decided_by_user_id",
        "edge_node_id",
        "last_error",
        "install_admin_ssh_key",
    }


def test_registration_returns_secrets_once_and_persists_only_hashes(registration_system):
    private, public_pem = key_material()
    response = register(registration_system, public_pem)
    assert response.status_code == 201, response.text
    created = response.json()
    assert set(created) == {"request_id", "challenge", "registration_token", "expires_at"}
    assert created["challenge"] and created["registration_token"]
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        persisted = json.dumps(vars(item), default=str)
        assert item.status == "pending_proof"
        assert item.challenge_hash == hashlib.sha256(created["challenge"].encode()).hexdigest()
        raw_registration = f"{item.id}.{created['registration_token']}"
        assert item.registration_token_hash == hashlib.sha256(raw_registration.encode()).hexdigest()
        assert created["challenge"] not in persisted
        assert created["registration_token"] not in persisted
        assert "PRIVATE KEY" not in persisted
        expected_der = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        assert item.public_key_fingerprint == hashlib.sha256(expected_der).hexdigest()


def test_registration_proof_transitions_once_and_status_is_secret_free(registration_system):
    private, public_pem = key_material()
    created = register(registration_system, public_pem).json()
    response = prove(registration_system, created, private)
    assert response.status_code == 200, response.text
    assert response.json() == {"status": "pending_approval"}
    replay = prove(registration_system, created, private)
    assert replay.status_code == 401
    assert replay.json() == {"detail": "Invalid registration"}
    status_response = registration_system.get(
        f"/api/node-registration-requests/{created['request_id']}/status",
        headers=registration_auth(created),
    )
    assert status_response.status_code == 200
    assert set(status_response.json()) == {"status", "phase", "error", "decision"}
    assert created["challenge"] not in status_response.text
    assert created["registration_token"] not in status_response.text
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        assert item.challenge_hash is None
        assert item.proved_at is not None
        expiry = item.challenge_expires_at.replace(tzinfo=UTC)
        assert (
            datetime.now(UTC) + timedelta(hours=23)
            < expiry
            <= datetime.now(UTC) + timedelta(hours=24)
        )


def test_registration_rejects_bad_key_ip_fingerprint_body_and_rate(registration_system):
    _, public_pem = key_material()
    bad_cases = [
        {"public_key_pem": "not a key"},
        {"public_ipv4": "10.0.0.1"},
        {"public_ipv4": "8.8.4.4"},
        {"machine_fingerprint": "abc"},
        {"cpu_count": 0},
    ]
    for index, override in enumerate(bad_cases):
        registration_system.app.state.registration_rate.clear()
        body = registration_body(public_pem)
        body.update(override)
        body["machine_fingerprint"] = override.get(
            "machine_fingerprint", hashlib.sha256(f"machine-{index}".encode()).hexdigest()
        )
        response = registration_system.post("/api/node-registration-requests", json=body)
        assert response.status_code in {401, 422}, (override, response.text)
    oversized = registration_system.post(
        "/api/node-registration-requests",
        headers={"Content-Length": "9000"},
        content=b"{}",
    )
    assert oversized.status_code == 413

    registration_system.app.state.registration_rate.clear()
    for index in range(3):
        _, key = key_material()
        made = register(
            registration_system,
            key,
            machine_fingerprint=hashlib.sha256(f"rate-{index}".encode()).hexdigest(),
        )
        assert made.status_code == 201
    _, fourth_key = key_material()
    limited = register(
        registration_system,
        fourth_key,
        machine_fingerprint=hashlib.sha256(b"rate-fourth").hexdigest(),
    )
    assert limited.status_code == 429


def test_proof_rejects_wrong_signature_and_expiry_generically(registration_system):
    private, public_pem = key_material()
    created = register(registration_system, public_pem).json()
    wrong_private, _ = key_material()
    wrong = prove(registration_system, created, wrong_private)
    assert wrong.status_code == 401
    assert wrong.json() == {"detail": "Invalid registration"}
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        item.challenge_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    expired = prove(registration_system, created, private)
    assert expired.status_code == 401
    with registration_system.app.state.db() as db:
        assert db.get(NodeRegistrationRequest, created["request_id"]).status == "expired"


def prepared_request(client: TestClient):
    private, public_pem = key_material()
    created = register(client, public_pem).json()
    assert prove(client, created, private).status_code == 200
    return created


def test_admin_list_is_safe_and_accept_binds_ip_creates_disabled_node(registration_system):
    created = prepared_request(registration_system)
    headers = admin_auth(registration_system)
    listed = registration_system.get("/api/admin/node-registration-requests", headers=headers)
    assert listed.status_code == 200
    row = next(item for item in listed.json() if item["id"] == created["request_id"])
    assert row["actual_public_ipv4"] == "8.8.8.8"
    assert row["reported_hostname"] == "rocky-edge"
    assert row["os_name"] == "Rocky Linux 9"
    assert row["cpu_count"] == 4
    assert len(row["public_key_fingerprint"]) == 64
    for forbidden in (
        "challenge_hash",
        "registration_token_hash",
        created["challenge"],
        created["registration_token"],
        "public_key_pem",
    ):
        assert forbidden not in listed.text

    mismatch = registration_system.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/accept",
        headers=headers,
        json={
            "node_name": "edge-request-01",
            "endpoint": "https://edge-request-01.example.com",
            "expected_public_ipv4": "8.8.4.4",
        },
    )
    assert mismatch.status_code == 422
    accepted = registration_system.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/accept",
        headers=headers,
        json={
            "node_name": "edge-request-01",
            "endpoint": "https://edge-request-01.example.com",
            "expected_public_ipv4": "8.8.8.8",
            "install_admin_ssh_key": True,
        },
    )
    assert accepted.status_code == 200, accepted.text
    assert "secret" not in accepted.text.lower()
    assert "token" not in accepted.text.lower()
    replay = registration_system.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/accept",
        headers=headers,
        json={
            "node_name": "other",
            "endpoint": "https://other.example.com",
            "expected_public_ipv4": "8.8.8.8",
        },
    )
    assert replay.status_code == 409
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        node = db.get(EdgeNode, item.edge_node_id)
        enrollment = db.scalar(select(NodeEnrollment).where(NodeEnrollment.edge_node_id == node.id))
        assert item.status == "approved"
        assert item.decided_by_user_id is not None
        assert item.install_admin_ssh_key is True
        assert node.enabled is False
        assert node.expected_public_ipv4 == item.actual_public_ipv4
        assert enrollment.status == "claimed"
        assert enrollment.report_token_hash
        events = db.scalars(
            select(AuditEvent).where(AuditEvent.target_id == created["request_id"])
        ).all()
        audit_text = "".join(event.details_json for event in events)
        assert node.shared_secret not in audit_text
        assert enrollment.report_token_hash not in audit_text


def test_admin_reject_has_no_node_and_rejected_cannot_claim(registration_system):
    created = prepared_request(registration_system)
    headers = admin_auth(registration_system)
    rejected = registration_system.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/reject",
        headers=headers,
        json={"reason": "capacity unavailable\ntry another region"},
    )
    assert rejected.status_code == 200
    status_response = registration_system.get(
        f"/api/node-registration-requests/{created['request_id']}/status",
        headers=registration_auth(created),
    )
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "rejected"
    assert status_response.json()["decision"] == "rejected"
    claim = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
    )
    assert claim.status_code == 401
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        assert item.status == "rejected"
        assert item.edge_node_id is None
        assert item.last_error == "capacity unavailable try another region"


def test_claim_approved_returns_config_once_and_consumes_token(registration_system):
    created = prepared_request(registration_system)
    headers = admin_auth(registration_system)
    registration_system.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/accept",
        headers=headers,
        json={
            "node_name": "edge-claim-01",
            "endpoint": "https://edge-claim-01.example.com",
            "expected_public_ipv4": "8.8.8.8",
        },
    )
    response = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
    )
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["node_name"] == "edge-claim-01"
    assert result["domain"] == "edge-claim-01.example.com"
    assert result["edge_ticket_secret"]
    assert result["report_token"]
    assert len(result["package_sha256"]) == 64
    assert result["install_admin_ssh_key"] is False
    replay = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
    )
    assert replay.status_code == 401
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        assert item.status == "installing"
        assert item.registration_token_hash is None


def test_report_reconciles_registration_and_allows_failed_recovery(registration_system):
    created = prepared_request(registration_system)
    registration_system.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/accept",
        headers=admin_auth(registration_system),
        json={
            "node_name": "edge-report-01",
            "endpoint": "https://edge-report-01.example.com",
            "expected_public_ipv4": "8.8.8.8",
        },
    )
    claimed = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
    ).json()
    report_headers = {"Authorization": f"Report {claimed['report_token']}"}
    failed = registration_system.post(
        "/api/edge-enrollments/report",
        headers=report_headers,
        json={"phase": "failed", "error": "temporary failure"},
    )
    assert failed.status_code == 200
    with registration_system.app.state.db() as db:
        assert db.get(NodeRegistrationRequest, created["request_id"]).status == "failed"
    ready = registration_system.post(
        "/api/edge-enrollments/report",
        headers=report_headers,
        json={"phase": "ready"},
    )
    assert ready.status_code == 200
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        node = db.get(EdgeNode, item.edge_node_id)
        assert item.status == "ready"
        assert item.last_error is None
        assert node.enabled is True


def test_admin_ssh_public_key_endpoint_is_safe(registration_system):
    response = registration_system.get("/bootstrap/admin-ssh.pub")
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.text.startswith("ssh-ed25519 ")
    assert "PRIVATE" not in response.text
