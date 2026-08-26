from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi.testclient import TestClient
from itsdangerous import URLSafeSerializer
from sqlalchemy import inspect, select

from cloudbrowser.app import create_app
from cloudbrowser.models import (
    AuditEvent,
    DeviceSession,
    EdgeNode,
    ManagedStore,
    StoreConnectionLease,
)
from cloudbrowser.runner import FakeBrowserRunner
from tests.example_topology import EXAMPLE_TOPOLOGY

SECRET = "native-test-secret-that-is-long-enough"
PASSWORD = "Admin-password-123"
MEMBER_PASSWORD = "Member-password-123"


def make_app(path: Path):
    return create_app(
        database_url=f"sqlite:///{path}",
        secret_key=SECRET,
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", PASSWORD),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
        cloud_video_enabled=True,
    )


def native_login(
    client: TestClient,
    device_id: str = "mac-primary",
    username: str = "admin",
    password: str = PASSWORD,
    platform: str = "macos",
) -> dict:
    response = client.post(
        "/api/native/login",
        json={
            "username": username,
            "password": password,
            "device_id": device_id,
            "device_name": "Ada's MacBook" if platform == "macos" else "Windows PC",
            "platform": platform,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_native_login_accepts_windows_platform_and_persists_device_type(tmp_path: Path):
    app = make_app(tmp_path / "windows-native.db")
    with TestClient(app) as client:
        issued = native_login(client, device_id="windows-primary", platform="windows")

    with app.state.db() as db:
        item = db.get(DeviceSession, issued["device_session_id"])
        assert item is not None
        assert item.device_id == "windows-primary"
        assert item.device_name == "Windows PC"
        assert item.platform == "windows"


def legacy_login(client: TestClient, username: str = "admin", password: str = PASSWORD) -> str:
    response = client.post("/api/login", json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def refresh(token: str) -> dict[str, str]:
    return {"Authorization": f"Refresh {token}"}


def create_member(client: TestClient, admin_token: str) -> int:
    response = client.post(
        "/api/admin/users",
        headers=bearer(admin_token),
        json={"username": "member", "password": MEMBER_PASSWORD},
    )
    assert response.status_code == 201, response.text
    return response.json()["id"]


def online_first_store(app) -> int:
    with app.state.db() as db:
        store = db.scalar(select(ManagedStore).order_by(ManagedStore.id))
        node = db.get(EdgeNode, store.edge_node_id)
        node.enabled = True
        node.health_status = "online"
        db.commit()
        return store.id


def test_native_login_creates_idempotent_device_session_without_raw_secret(tmp_path: Path):
    database = tmp_path / "native.db"
    app = make_app(database)
    with TestClient(app) as client:
        first = native_login(client)
        second = native_login(client)

    assert second["token_type"] == "bearer"
    assert second["expires_in"] == 15 * 60
    assert second["refresh_expires_in"] == 30 * 24 * 60 * 60
    session_id, secret = second["refresh_token"].split(".", 1)
    assert session_id and secret
    assert second["device_session_id"] == session_id
    assert datetime.fromisoformat(second["access_expires_at"]) > datetime.now(UTC)
    assert datetime.fromisoformat(second["refresh_expires_at"]) > datetime.now(UTC)

    with app.state.db() as db:
        item = db.get(DeviceSession, session_id)
        assert item is not None
        assert item.device_id == "mac-primary"
        assert item.device_name == "Ada's MacBook"
        assert item.platform == "macos"
        assert (
            item.refresh_token_hash == hashlib.sha256(second["refresh_token"].encode()).hexdigest()
        )
        assert secret not in item.refresh_token_hash
        assert not hasattr(item, "refresh_token")
        assert len(db.scalars(select(DeviceSession)).all()) == 1

    with TestClient(app) as client:
        assert client.get("/api/me", headers=bearer(first["access_token"])).status_code == 401

    restarted = make_app(database)
    assert "device_sessions" in inspect(restarted.state.db.kw["bind"]).get_table_names()
    with restarted.state.db() as db:
        rows = db.scalars(select(DeviceSession)).all()
        assert len(rows) == 1


def test_native_access_token_binds_all_claims_and_expires_in_15_minutes(tmp_path: Path):
    app = make_app(tmp_path / "access.db")
    signer = URLSafeSerializer(SECRET, salt="native-access-token")
    with TestClient(app) as client:
        issued = native_login(client)
        assert client.get("/api/me", headers=bearer(issued["access_token"])).status_code == 200

        payload = signer.loads(issued["access_token"])
        assert set(payload) == {"uid", "ver", "dsid", "gen", "exp"}
        now = int(datetime.now(UTC).timestamp())
        assert 14 * 60 <= payload["exp"] - now <= 15 * 60

        replacements = {
            "uid": payload["uid"] + 999,
            "ver": payload["ver"] + 1,
            "dsid": "missing-device-session",
            "gen": payload["gen"] + 1,
            "exp": int((datetime.now(UTC) - timedelta(seconds=1)).timestamp()),
        }
        for claim, replacement in replacements.items():
            tampered_payload = {**payload, claim: replacement}
            tampered = signer.dumps(tampered_payload)
            assert client.get("/api/me", headers=bearer(tampered)).status_code == 401, claim


def test_refresh_rotates_once_and_replay_revokes_device(tmp_path: Path):
    app = make_app(tmp_path / "refresh.db")
    with TestClient(app) as client:
        first = native_login(client)
        rotated_response = client.post(
            "/api/native/refresh", headers=refresh(first["refresh_token"])
        )
        assert rotated_response.status_code == 200, rotated_response.text
        rotated = rotated_response.json()
        assert rotated["refresh_token"] != first["refresh_token"]
        assert rotated["device_session_id"] == rotated["refresh_token"].split(".", 1)[0]
        assert datetime.fromisoformat(rotated["access_expires_at"]) > datetime.now(UTC)
        assert datetime.fromisoformat(rotated["refresh_expires_at"]) > datetime.now(UTC)
        assert client.get("/api/me", headers=bearer(first["access_token"])).status_code == 401
        assert client.get("/api/me", headers=bearer(rotated["access_token"])).status_code == 200

        replay = client.post("/api/native/refresh", headers=refresh(first["refresh_token"]))
        assert replay.status_code == 401
        assert (
            client.post(
                "/api/native/refresh", headers=refresh(rotated["refresh_token"])
            ).status_code
            == 401
        )
        assert client.get("/api/me", headers=bearer(rotated["access_token"])).status_code == 401

    with app.state.db() as db:
        event_types = [event.event_type for event in db.scalars(select(AuditEvent)).all()]
        assert "native.refresh_rotated" not in event_types
        assert event_types.count("native.refresh_replayed") == 1


def test_two_concurrent_refreshes_use_database_conditional_update(tmp_path: Path):
    database = tmp_path / "concurrent-refresh.db"
    app = make_app(database)
    with TestClient(app) as client:
        first = native_login(client)

    def rotate() -> tuple[int, dict]:
        with TestClient(app) as concurrent_client:
            response = concurrent_client.post(
                "/api/native/refresh", headers=refresh(first["refresh_token"])
            )
            return response.status_code, response.json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: rotate(), range(2)))

    assert sorted(status_code for status_code, _ in results) == [200, 401]
    winner = next(payload for status_code, payload in results if status_code == 200)
    with TestClient(app) as client:
        assert client.get("/api/me", headers=bearer(winner["access_token"])).status_code == 401
        assert (
            client.post("/api/native/refresh", headers=refresh(winner["refresh_token"])).status_code
            == 401
        )

    session_id = first["refresh_token"].split(".", 1)[0]
    with app.state.db() as db:
        item = db.get(DeviceSession, session_id)
        assert item.revoked_at is not None


def test_current_logout_and_device_list_and_revoke_are_session_scoped(tmp_path: Path):
    app = make_app(tmp_path / "device-lifecycle.db")
    with TestClient(app) as client:
        primary = native_login(client)
        secondary = native_login(client, device_id="mac-secondary")

        devices = client.get("/api/native/devices", headers=bearer(primary["access_token"]))
        assert devices.status_code == 200, devices.text
        assert len(devices.json()["devices"]) == 2
        serialized = json.dumps(devices.json())
        assert primary["access_token"] not in serialized
        assert primary["refresh_token"] not in serialized
        assert secondary["access_token"] not in serialized
        assert secondary["refresh_token"] not in serialized
        assert "refresh_token_hash" not in serialized

        primary_id = primary["refresh_token"].split(".", 1)[0]
        secondary_id = secondary["refresh_token"].split(".", 1)[0]
        revoked = client.delete(
            f"/api/native/devices/{secondary_id}", headers=bearer(primary["access_token"])
        )
        assert revoked.status_code == 204, revoked.text
        assert client.get("/api/me", headers=bearer(secondary["access_token"])).status_code == 401
        assert client.get("/api/me", headers=bearer(primary["access_token"])).status_code == 200

        logged_out = client.post("/api/native/logout", headers=bearer(primary["access_token"]))
        assert logged_out.status_code == 200, logged_out.text
        assert client.get("/api/me", headers=bearer(primary["access_token"])).status_code == 401

    with app.state.db() as db:
        assert db.get(DeviceSession, primary_id).revoked_at is not None
        assert db.get(DeviceSession, secondary_id).revoked_at is not None


def test_password_change_delete_and_disable_explicitly_revoke_device_sessions(tmp_path: Path):
    app = make_app(tmp_path / "account-revocation.db")
    with TestClient(app) as client:
        admin_token = legacy_login(client)
        member_id = create_member(client, admin_token)
        password_session = native_login(client, username="member", password=MEMBER_PASSWORD)
        password_session_id = password_session["refresh_token"].split(".", 1)[0]

        changed = client.put(
            f"/api/admin/users/{member_id}/password",
            headers=bearer(admin_token),
            json={"password": "Changed-password-123"},
        )
        assert changed.status_code == 200, changed.text
        assert (
            client.get("/api/me", headers=bearer(password_session["access_token"])).status_code
            == 401
        )
        with app.state.db() as db:
            assert db.get(DeviceSession, password_session_id).revoked_at is not None

        disabled_session = native_login(client, username="member", password="Changed-password-123")
        disabled_session_id = disabled_session["refresh_token"].split(".", 1)[0]
        disabled = client.put(
            f"/api/admin/users/{member_id}/enabled",
            headers=bearer(admin_token),
            json={"enabled": False},
        )
        assert disabled.status_code == 200, disabled.text

    with app.state.db() as db:
        assert db.get(DeviceSession, password_session_id).revoked_at is not None
        assert db.get(DeviceSession, disabled_session_id).revoked_at is not None

    delete_app = make_app(tmp_path / "account-delete.db")
    with TestClient(delete_app) as client:
        admin_token = legacy_login(client)
        member_id = create_member(client, admin_token)
        deleted_session = native_login(client, username="member", password=MEMBER_PASSWORD)
        deleted_session_id = deleted_session["refresh_token"].split(".", 1)[0]
        deleted = client.delete(f"/api/admin/users/{member_id}", headers=bearer(admin_token))
        assert deleted.status_code == 204, deleted.text
    with delete_app.state.db() as db:
        assert db.get(DeviceSession, deleted_session_id).revoked_at is not None


def test_native_stores_dto_is_safe_and_preflight_acquires_matching_lease(
    tmp_path: Path,
):
    app = make_app(tmp_path / "native-stores.db")
    store_id = online_first_store(app)
    with TestClient(app) as client:
        issued = native_login(client)
        headers = bearer(issued["access_token"])

        listed = client.get("/api/native/stores", headers=headers)
        assert listed.status_code == 200, listed.text
        assert listed.json()["stores"]
        store = next(item for item in listed.json()["stores"] if int(item["id"]) == store_id)
        assert set(store) == {
            "id",
            "name",
            "node_name",
            "status",
            "health_status",
            "maintenance_mode",
            "enabled",
            "expected_public_ipv4",
            "actual_public_ipv4",
            "latency_ms",
            "active_connections",
            "max_connections",
            "legacy_profile_path",
        }
        assert store["node_name"]
        assert store["expected_public_ipv4"]
        forbidden = ("edge_endpoint", "endpoint", "secret", "token", "credential")
        assert not any(fragment in json.dumps(listed.json()).lower() for fragment in forbidden)

        before = datetime.now(UTC)
        preflight = client.post(f"/api/native/stores/{store_id}/preflight", headers=headers)
        assert preflight.status_code == 200, preflight.text
        assert preflight.json()["ready"] is True
        assert preflight.json()["recovered"] is False
        expires_at = datetime.fromisoformat(preflight.json()["expires_at"])
        assert (
            before + timedelta(hours=7, minutes=59)
            <= expires_at
            <= before + timedelta(hours=8, minutes=1)
        )
        assert not any(fragment in json.dumps(preflight.json()).lower() for fragment in forbidden)

        recovered = client.post(f"/api/native/stores/{store_id}/preflight", headers=headers)
        assert recovered.status_code == 200, recovered.text
        assert recovered.json()["lease_id"] == preflight.json()["lease_id"]
        assert recovered.json()["recovered"] is True

    with app.state.db() as db:
        lease = db.get(StoreConnectionLease, preflight.json()["lease_id"])
        lease.device_id = "different-device"
        db.commit()
    with TestClient(app) as client:
        second_device = client.post(
            f"/api/native/stores/{store_id}/preflight",
            headers=bearer(issued["access_token"]),
        )
        assert second_device.status_code == 200
        assert second_device.json()["recovered"] is False
        assert second_device.json()["lease_id"] != preflight.json()["lease_id"]

    with app.state.db() as db:
        active = db.scalars(
            select(StoreConnectionLease).where(
                StoreConnectionLease.store_id == store_id,
                StoreConnectionLease.status == "active",
            )
        ).all()
        assert {lease.device_id for lease in active} == {
            "different-device",
            "mac-primary",
        }

    with app.state.db() as db:
        store = db.get(ManagedStore, store_id)
        store.enabled = False
        db.commit()
    with TestClient(app) as client:
        disabled = client.post(
            f"/api/native/stores/{store_id}/preflight",
            headers=bearer(issued["access_token"]),
        )
        assert disabled.status_code == 409

    with app.state.db() as db:
        store = db.get(ManagedStore, store_id)
        store.enabled = True
        node = db.get(EdgeNode, store.edge_node_id)
        node.health_status = "offline"
        db.commit()
    with TestClient(app) as client:
        offline = client.post(
            f"/api/native/stores/{store_id}/preflight",
            headers=bearer(issued["access_token"]),
        )
        assert offline.status_code == 503


def test_ticket_endpoints_accept_native_bearer(tmp_path: Path):
    app = make_app(tmp_path / "native-tickets.db")
    with TestClient(app) as client:
        issued = native_login(client)
        started = client.post("/api/sessions/start", headers=bearer(issued["access_token"]))
        assert started.status_code == 200, started.text
        ticket = client.get(
            f"/api/sessions/{started.json()['id']}/ticket",
            headers=bearer(issued["access_token"]),
        )
        assert ticket.status_code == 200, ticket.text
        assert ticket.json()["ticket"]


def test_native_audits_never_contain_raw_tokens_or_edge_secrets(tmp_path: Path):
    app = make_app(tmp_path / "native-audit.db")
    with TestClient(app) as client:
        issued = native_login(client)
        rotated = client.post("/api/native/refresh", headers=refresh(issued["refresh_token"]))
        assert rotated.status_code == 200, rotated.text
        rotated_payload = rotated.json()
        client.get("/api/native/devices", headers=bearer(rotated_payload["access_token"]))
        client.post("/api/native/logout", headers=bearer(rotated_payload["access_token"]))

    secrets_to_reject = {
        issued["access_token"],
        issued["refresh_token"],
        rotated_payload["access_token"],
        rotated_payload["refresh_token"],
    }
    with app.state.db() as db:
        edge_secrets = set(db.scalars(select(EdgeNode.shared_secret)).all())
        audit_text = "\n".join(
            f"{event.target_id} {event.details_json}"
            for event in db.scalars(select(AuditEvent)).all()
        )
    for secret in secrets_to_reject | edge_secrets:
        assert secret not in audit_text


def test_legacy_auth_contract_is_unchanged_and_not_native(tmp_path: Path):
    app = make_app(tmp_path / "legacy.db")
    signer = URLSafeSerializer(SECRET, salt="api-access-token")
    with TestClient(app) as client:
        token = legacy_login(client)
        assert set(signer.loads(token)) == {"uid", "ver"}
        assert client.get("/api/me", headers=bearer(token)).status_code == 200
        assert client.get("/api/stores", headers=bearer(token)).status_code == 200
        assert client.get("/api/native/devices", headers=bearer(token)).status_code == 401
