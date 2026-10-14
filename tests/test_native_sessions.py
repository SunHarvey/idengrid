from __future__ import annotations

import hashlib
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from itsdangerous import URLSafeSerializer
from sqlalchemy import inspect, select

import cloudbrowser.app as app_module
from cloudbrowser.app import create_app
from cloudbrowser.models import (
    AuditEvent,
    DeviceSession,
    EdgeNode,
    ManagedStore,
    NativeLoginThrottle,
    StoreConnectionLease,
)
from cloudbrowser.runner import FakeBrowserRunner
from tests.example_topology import EXAMPLE_TOPOLOGY

SECRET = "native-test-secret-that-is-long-enough"
PASSWORD = "Admin-password-123"
MEMBER_PASSWORD = "Member-password-123"


class MutableClock:
    def __init__(self, current: datetime):
        self.current = current

    def __call__(self) -> datetime:
        return self.current

    def advance(self, **kwargs: float) -> None:
        self.current += timedelta(**kwargs)


def make_app(path: Path, login_clock=None):
    return create_app(
        database_url=f"sqlite:///{path}",
        secret_key=SECRET,
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", PASSWORD),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
        cloud_video_enabled=True,
        login_clock=login_clock,
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


def test_native_login_fifth_failure_starts_five_minute_cooldown(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-throttle.db", login_clock=clock)
    payload = {
        "username": "admin",
        "password": "wrong-password",
        "device_id": "windows-primary",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            response = client.post("/api/native/login", json=payload)
            assert response.status_code == 401

        limited = client.post("/api/native/login", json=payload)
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "300"
        assert limited.json() == {"detail": "Too many login attempts"}

        payload["password"] = PASSWORD
        still_limited = client.post("/api/native/login", json=payload)
        assert still_limited.status_code == 429
        assert still_limited.headers["retry-after"] == "300"


def test_native_login_success_clears_previous_failures(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-success-reset.db", login_clock=clock)
    payload = {
        "username": "admin",
        "password": "wrong-password",
        "device_id": "windows-primary",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401

        payload["password"] = PASSWORD
        assert client.post("/api/native/login", json=payload).status_code == 200

        payload["password"] = "wrong-password"
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401


def test_native_login_repeated_cooldowns_escalate_and_cap_at_thirty_minutes(
    tmp_path: Path,
):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-escalation.db", login_clock=clock)
    payload = {
        "username": "missing-user",
        "password": "wrong-password",
        "device_id": "windows-primary",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for expected_wait in (300, 900, 1800, 1800):
            for _ in range(4):
                assert client.post("/api/native/login", json=payload).status_code == 401
            limited = client.post("/api/native/login", json=payload)
            assert limited.status_code == 429
            assert limited.headers["retry-after"] == str(expected_wait)
            clock.advance(seconds=expected_wait + 1)


def test_native_login_penalty_resets_after_twenty_four_hours(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-penalty-reset.db", login_clock=clock)
    payload = {
        "username": "missing-user",
        "password": "wrong-password",
        "device_id": "windows-primary",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401
        first_cycle = client.post("/api/native/login", json=payload)
        assert first_cycle.status_code == 429
        assert first_cycle.headers["retry-after"] == "300"

        clock.advance(hours=24, seconds=1)
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401
        reset_cycle = client.post("/api/native/login", json=payload)
        assert reset_cycle.status_code == 429
        assert reset_cycle.headers["retry-after"] == "300"


def test_native_login_cooldown_cannot_be_bypassed_by_changing_device(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-device-bypass.db", login_clock=clock)
    payload = {
        "username": "admin",
        "password": "wrong-password",
        "device_id": "device-one",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401
        limited = client.post("/api/native/login", json=payload)
        assert limited.status_code == 429

        payload["password"] = PASSWORD
        payload["device_id"] = "device-two"
        bypass = client.post("/api/native/login", json=payload)
        assert bypass.status_code == 429
        assert bypass.headers["retry-after"] == "300"


def test_native_login_cooldown_cannot_be_bypassed_by_changing_username(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-username-bypass.db", login_clock=clock)
    payload = {
        "username": "missing-user-one",
        "password": "wrong-password",
        "device_id": "device-one",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401
        assert client.post("/api/native/login", json=payload).status_code == 429

        payload["username"] = "missing-user-two"
        bypass = client.post("/api/native/login", json=payload)
        assert bypass.status_code == 429
        assert bypass.headers["retry-after"] == "300"


def test_native_login_cooldown_persists_across_restart_and_is_audited(tmp_path: Path):
    database = tmp_path / "native-login-persistent.db"
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(database, login_clock=clock)
    payload = {
        "username": "admin",
        "password": "wrong-password",
        "device_id": "device-one",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401
        assert client.post("/api/native/login", json=payload).status_code == 429

    restarted = make_app(database, login_clock=clock)
    payload["password"] = PASSWORD
    with TestClient(restarted) as client:
        limited = client.post("/api/native/login", json=payload)
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "300"

    with restarted.state.db() as db:
        assert len(db.scalars(select(NativeLoginThrottle)).all()) == 3
        events = db.scalars(select(AuditEvent).order_by(AuditEvent.id)).all()
        assert [event.event_type for event in events].count("native.login_failed") == 5
        throttled = [event for event in events if event.event_type == "native.login_throttled"]
        assert len(throttled) == 1
        assert json.loads(throttled[0].details_json)["retry_after_seconds"] == 300
        assert "wrong-password" not in "".join(event.details_json for event in events)


def test_native_login_source_ip_limit_stops_rotating_usernames_and_devices(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-source-ip.db", login_clock=clock)

    with TestClient(app) as client:
        for attempt in range(19):
            response = client.post(
                "/api/native/login",
                json={
                    "username": f"missing-user-{attempt}",
                    "password": "wrong-password",
                    "device_id": f"device-{attempt}",
                    "device_name": "Windows PC",
                    "platform": "windows",
                },
            )
            assert response.status_code == 401

        limited = client.post(
            "/api/native/login",
            json={
                "username": "missing-user-19",
                "password": "wrong-password",
                "device_id": "device-19",
                "device_name": "Windows PC",
                "platform": "windows",
            },
        )
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "300"


def test_concurrent_native_login_failures_cannot_lose_throttle_updates(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-concurrent.db", login_clock=clock)
    payload = {
        "username": "admin",
        "password": "wrong-password",
        "device_id": "windows-primary",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    def fail_login(_: int) -> int:
        with TestClient(app) as concurrent_client:
            return concurrent_client.post("/api/native/login", json=payload).status_code

    with ThreadPoolExecutor(max_workers=5) as executor:
        statuses = list(executor.map(fail_login, range(5)))

    assert sorted(statuses) == [401, 401, 401, 401, 429]

    with TestClient(app) as client:
        payload["password"] = PASSWORD
        limited = client.post("/api/native/login", json=payload)
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "300"


def test_success_does_not_clear_unrelated_source_failures(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-source-preserved.db", login_clock=clock)

    with TestClient(app) as client:
        for attempt in range(19):
            response = client.post(
                "/api/native/login",
                json={
                    "username": f"missing-user-{attempt}",
                    "password": "wrong-password",
                    "device_id": f"rotating-device-{attempt}",
                    "device_name": "Windows PC",
                    "platform": "windows",
                },
            )
            assert response.status_code == 401

        success = client.post(
            "/api/native/login",
            json={
                "username": "admin",
                "password": PASSWORD,
                "device_id": "valid-device",
                "device_name": "Windows PC",
                "platform": "windows",
            },
        )
        assert success.status_code == 200

        limited = client.post(
            "/api/native/login",
            json={
                "username": "missing-user-final",
                "password": "wrong-password",
                "device_id": "rotating-device-final",
                "device_name": "Windows PC",
                "platform": "windows",
            },
        )
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "300"


def test_native_login_purges_throttle_rows_stale_for_twenty_four_hours(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-stale-cleanup.db", login_clock=clock)
    failed_payload = {
        "username": "missing-user",
        "password": "wrong-password",
        "device_id": "stale-device",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app, client=("198.51.100.10", 5010)) as client:
        assert client.post("/api/native/login", json=failed_payload).status_code == 401

    clock.advance(hours=24, seconds=1)
    with TestClient(app, client=("198.51.100.11", 5011)) as client:
        success = client.post(
            "/api/native/login",
            json={
                "username": "admin",
                "password": PASSWORD,
                "device_id": "fresh-device",
                "device_name": "Windows PC",
                "platform": "windows",
            },
        )
        assert success.status_code == 200

    with app.state.db() as db:
        assert db.scalar(select(NativeLoginThrottle).where(NativeLoginThrottle.updated_at < clock.current)) is None


def test_native_login_retry_after_rounds_positive_fraction_up(tmp_path: Path):
    clock = MutableClock(datetime(2026, 10, 13, 12, 0, tzinfo=UTC))
    app = make_app(tmp_path / "native-login-retry-ceiling.db", login_clock=clock)
    payload = {
        "username": "admin",
        "password": "wrong-password",
        "device_id": "windows-primary",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with TestClient(app) as client:
        for _ in range(4):
            assert client.post("/api/native/login", json=payload).status_code == 401
        assert client.post("/api/native/login", json=payload).status_code == 429
        clock.advance(seconds=299.5)
        payload["password"] = PASSWORD
        limited = client.post("/api/native/login", json=payload)
        assert limited.status_code == 429
        assert limited.headers["retry-after"] == "1"


def test_parallel_independent_failures_do_not_hit_sqlite_lock_errors(tmp_path: Path):
    app = make_app(tmp_path / "native-login-independent-concurrency.db")

    def fail_login(attempt: int) -> int:
        payload = {
            "username": "admin",
            "password": "wrong-password",
            "device_id": f"device-{attempt}",
            "device_name": "Windows PC",
            "platform": "windows",
        }
        with TestClient(
            app,
            client=(f"198.51.100.{attempt + 1}", 5100 + attempt),
            raise_server_exceptions=False,
        ) as concurrent_client:
            return concurrent_client.post("/api/native/login", json=payload).status_code

    with ThreadPoolExecutor(max_workers=30) as executor:
        statuses = list(executor.map(fail_login, range(30)))

    assert statuses == [401] * 30
    with app.state.db() as db:
        assert len(db.scalars(select(NativeLoginThrottle)).all()) == 90


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


@pytest.mark.parametrize("mutation", ["password", "disable", "delete"])
def test_native_login_revalidates_account_after_password_verification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
):
    app = make_app(tmp_path / f"native-login-race-{mutation}.db")
    with TestClient(app) as client:
        admin_token = legacy_login(client)
        member_id = create_member(client, admin_token)

    started = threading.Event()
    release = threading.Event()
    original_passwords = app_module.passwords

    class BlockingPasswords:
        def hash(self, password: str) -> str:
            return original_passwords.hash(password)

        def verify(self, password_hash: str, password: str) -> bool:
            if password == MEMBER_PASSWORD:
                started.set()
                assert release.wait(timeout=15)
            return original_passwords.verify(password_hash, password)

    monkeypatch.setattr(app_module, "passwords", BlockingPasswords())
    payload = {
        "username": "member",
        "password": MEMBER_PASSWORD,
        "device_id": f"race-device-{mutation}",
        "device_name": "Windows PC",
        "platform": "windows",
    }

    with ThreadPoolExecutor(max_workers=1) as executor, TestClient(app) as login_client:
        future = executor.submit(login_client.post, "/api/native/login", json=payload)
        assert started.wait(timeout=15)
        with TestClient(app) as admin_client:
            if mutation == "password":
                changed = admin_client.put(
                    f"/api/admin/users/{member_id}/password",
                    headers=bearer(admin_token),
                    json={"password": "Changed-password-123"},
                )
                assert changed.status_code == 200, changed.text
            elif mutation == "disable":
                disabled = admin_client.put(
                    f"/api/admin/users/{member_id}/enabled",
                    headers=bearer(admin_token),
                    json={"enabled": False},
                )
                assert disabled.status_code == 200, disabled.text
            else:
                deleted = admin_client.delete(
                    f"/api/admin/users/{member_id}", headers=bearer(admin_token)
                )
                assert deleted.status_code == 204, deleted.text
        release.set()
        response = future.result(timeout=15)

    assert response.status_code == 401, response.text
    with app.state.db() as db:
        active = db.scalars(
            select(DeviceSession).where(
                DeviceSession.user_id == member_id,
                DeviceSession.revoked_at.is_(None),
            )
        ).all()
        assert active == []


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
