from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session, sessionmaker

from cloudbrowser.app import create_app
from cloudbrowser.edge_health import EdgeHealthMonitor, migrate_edge_health_schema
from cloudbrowser.models import Base, EdgeNode, NodeEnrollment, NodeRegistrationRequest
from cloudbrowser.runner import FakeBrowserRunner
from tests.example_topology import EXAMPLE_TOPOLOGY


def status_payload(node: str, public_ipv4: str, **overrides) -> dict:
    payload = {
        "node": node,
        "active_connections": 2,
        "max_connections": 16,
        "accepted_connections": 25,
        "denied_connections": 3,
        "public_ipv4": public_ipv4,
        "load_1m": 0.25,
        "memory_total_bytes": 4_294_967_296,
        "memory_available_bytes": 3_221_225_472,
        "disk_total_bytes": 107_374_182_400,
        "disk_free_bytes": 85_899_345_920,
        "uptime_seconds": 12_345.5,
        "agent_version": "1.0.0",
    }
    payload.update(overrides)
    return payload


def single_node_sessions(tmp_path, filename: str):
    engine = create_engine(f"sqlite:///{tmp_path / filename}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
            )
        )
        db.commit()
    return sessions


@pytest.fixture(autouse=True)
def disable_real_edge_health_sample_sleep(monkeypatch) -> None:
    monkeypatch.setattr("cloudbrowser.edge_health.time.sleep", lambda _seconds: None)


def test_monitor_rejects_a_success_quorum_below_three() -> None:
    with pytest.raises(ValueError, match="valid quorum"):
        EdgeHealthMonitor(lambda: None, sample_count=5, min_success=2)  # type: ignore[arg-type]


def test_sqlite_migration_adds_backward_compatible_edge_health_columns(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE edge_nodes (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    endpoint VARCHAR(255) NOT NULL,
                    shared_secret VARCHAR(255) NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )
        connection.execute(
            text(
                """
                INSERT INTO edge_nodes
                    (id, name, endpoint, shared_secret, enabled, created_at)
                VALUES
                    (1, 'legacy-edge', 'https://legacy.example', 'never-log-me', 1,
                     '2026-08-18 00:00:00')
                """
            )
        )

    migrate_edge_health_schema(engine)
    migrate_edge_health_schema(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("edge_nodes")}
    assert {
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
    } <= columns
    with engine.connect() as connection:
        row = connection.execute(
            text(
                """
                SELECT health_status, last_seen_at, latency_ms, active_connections,
                       max_connections, accepted_connections, denied_connections,
                       expected_public_ipv4, actual_public_ipv4, load_1m,
                       memory_total_bytes, memory_available_bytes, disk_total_bytes,
                       disk_free_bytes, uptime_seconds, agent_version, last_error
                FROM edge_nodes WHERE id = 1
                """
            )
        ).one()
    assert row.health_status == "unknown"
    assert tuple(row)[1:] == (None, None, 0, 0, 0, 0, *([None] * 10))


def test_sqlite_migration_adds_idempotent_maintenance_mode_default_false(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy-maintenance.db'}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE edge_nodes (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    endpoint VARCHAR(255) NOT NULL,
                    shared_secret VARCHAR(255) NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )
        connection.execute(
            text(
                "INSERT INTO edge_nodes VALUES "
                "(1, 'legacy', 'https://legacy.example', 'write-only', 1, '2026-08-18')"
            )
        )

    migrate_edge_health_schema(engine)
    migrate_edge_health_schema(engine)

    columns = {column["name"] for column in inspect(engine).get_columns("edge_nodes")}
    assert "maintenance_mode" in columns
    with engine.connect() as connection:
        assert (
            connection.execute(
                text("SELECT maintenance_mode FROM edge_nodes WHERE id = 1")
            ).scalar_one()
            == 0
        )


def test_app_startup_migrates_legacy_edge_node_table_before_querying_it(tmp_path) -> None:
    database_path = tmp_path / "legacy-app.db"
    engine = create_engine(f"sqlite:///{database_path}")
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                CREATE TABLE edge_nodes (
                    id INTEGER PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    endpoint VARCHAR(255) NOT NULL UNIQUE,
                    shared_secret VARCHAR(255) NOT NULL,
                    enabled BOOLEAN NOT NULL,
                    created_at DATETIME NOT NULL
                )
                """
            )
        )

    app = create_app(
        database_url=f"sqlite:///{database_path}",
        secret_key="startup-migration-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
    )

    with app.state.db() as db:
        assert db.scalar(select(EdgeNode).where(EdgeNode.name == "sg-browser")).health_status == (
            "unknown"
        )


def test_seed_sets_expected_public_ips_without_overwriting_admin_value(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'seed.db'}"
    app = create_app(
        database_url=database_url,
        secret_key="seed-test-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
    )
    with app.state.db() as db:
        node = db.scalar(select(EdgeNode).where(EdgeNode.name == "edge-sg01"))
        node.expected_public_ipv4 = "8.8.8.8"
        db.commit()

    restarted = create_app(
        database_url=database_url,
        secret_key="seed-test-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
    )

    with restarted.state.db() as db:
        nodes = {
            node.name: node.expected_public_ipv4 for node in db.scalars(select(EdgeNode)).all()
        }
    assert nodes == {
        "sg-browser": "192.0.2.10",
        "edge-sg01": "8.8.8.8",
        "edge-hk01": "203.0.113.30",
    }


def test_new_edge_node_starts_with_unknown_health_and_zero_metrics(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'new.db'}")
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        node = EdgeNode(
            name="edge-new",
            endpoint="https://edge-new.example",
            shared_secret="never-log-me",
        )
        db.add(node)
        db.commit()
        db.refresh(node)

        assert node.health_status == "unknown"
        assert node.last_seen_at is None
        assert node.latency_ms is None
        assert (
            node.active_connections,
            node.max_connections,
            node.accepted_connections,
            node.denied_connections,
        ) == (0, 0, 0, 0)
        assert node.last_error is None


def test_monitor_updates_healthy_central_and_remote_edges(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'monitor.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add_all(
            [
                EdgeNode(
                    name="sg-browser",
                    endpoint="https://sg-browser.example",
                    shared_secret="central-secret-never-send",
                    expected_public_ipv4="8.8.8.8",
                ),
                EdgeNode(
                    name="edge-sg01",
                    endpoint="https://edge-sg01.example/base/",
                    shared_secret="remote-secret-never-send",
                    expected_public_ipv4="8.8.4.4",
                ),
            ]
        )
        db.commit()

    requested: list[httpx.Request] = []

    def status_response(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        node = "sg-browser" if request.url.host == "127.0.0.1" else "edge-sg01"
        return httpx.Response(
            200,
            json=status_payload(
                node, "8.8.8.8" if node == "sg-browser" else "8.8.4.4"
            ),
        )

    client = httpx.Client(transport=httpx.MockTransport(status_response))
    results = EdgeHealthMonitor(sessions, client=client).run_once()

    assert [str(request.url) for request in requested] == [
        *("http://127.0.0.1:8787/status" for _ in range(5)),
        *("https://edge-sg01.example/base/status" for _ in range(5)),
    ]
    assert all("secret" not in request.headers for request in requested)
    assert results == [
        {"node": "sg-browser", "health_status": "online"},
        {"node": "edge-sg01", "health_status": "online"},
    ]
    with sessions() as db:
        nodes = db.scalars(select(EdgeNode).order_by(EdgeNode.id)).all()
        for node in nodes:
            assert node.health_status == "online"
            assert node.last_seen_at is not None
            assert node.latency_ms is not None
            assert (
                node.active_connections,
                node.max_connections,
                node.accepted_connections,
                node.denied_connections,
            ) == (2, 16, 25, 3)
            assert node.last_error is None
            assert node.actual_public_ipv4 == node.expected_public_ipv4
            assert node.load_1m == 0.25
            assert node.memory_total_bytes == 4_294_967_296
            assert node.memory_available_bytes == 3_221_225_472
            assert node.disk_total_bytes == 107_374_182_400
            assert node.disk_free_bytes == 85_899_345_920
            assert node.uptime_seconds == 12_345.5
            assert node.agent_version == "1.0.0"


def test_monitor_starts_samples_sequentially_one_interval_after_completion(tmp_path) -> None:
    sessions = single_node_sessions(tmp_path, "sample-cadence.db")
    now = 0.0
    starts: list[float] = []
    sleeps: list[float] = []
    durations = iter((0.01, 0.02, 0.03, 0.04, 0.05))

    class TimelineClient:
        def get(self, url: str, *, timeout: float) -> httpx.Response:
            nonlocal now
            assert timeout == 5.0
            starts.append(now)
            now += next(durations)
            return httpx.Response(
                200,
                request=httpx.Request("GET", url),
                json=status_payload("edge-sg01", "8.8.4.4"),
            )

    def sleep(seconds: float) -> None:
        nonlocal now
        sleeps.append(seconds)
        now += seconds

    EdgeHealthMonitor(
        sessions,
        client=TimelineClient(),  # type: ignore[arg-type]
        timer=lambda: now,
        sleeper=sleep,
    ).run_once()

    assert starts == pytest.approx([0.0, 1.01, 2.03, 3.06, 4.10])
    assert sleeps == [1.0, 1.0, 1.0, 1.0]


@pytest.mark.parametrize(
    ("durations", "failed_indexes", "expected_latency_ms"),
    [
        ((0.01, 0.02, 0.03, 0.04, 0.09), set(), 30),
        ((0.01, 0.02, 0.03, 0.04, 0.09), {1}, 35),
        ((0.01, 0.02, 0.03, 0.04, 0.09), {1, 3}, 30),
    ],
)
def test_monitor_uses_trimmed_mean_of_five_four_or_three_successes(
    tmp_path, durations, failed_indexes, expected_latency_ms
) -> None:
    sessions = single_node_sessions(tmp_path, f"trimmed-{len(failed_indexes)}.db")
    now = 0.0
    attempt = 0

    class DeterministicClient:
        def get(self, url: str, *, timeout: float) -> httpx.Response:
            nonlocal now, attempt
            index = attempt
            attempt += 1
            now += durations[index]
            request = httpx.Request("GET", url)
            if index in failed_indexes:
                raise httpx.ReadTimeout("sample timed out", request=request)
            return httpx.Response(
                200,
                request=request,
                json=status_payload(
                    "edge-sg01",
                    "8.8.4.4",
                    active_connections=index + 1,
                ),
            )

    monitor = EdgeHealthMonitor(
        sessions,
        client=DeterministicClient(),  # type: ignore[arg-type]
        timer=lambda: now,
        sleeper=lambda _seconds: None,
    )

    assert monitor.run_once() == [{"node": "edge-sg01", "health_status": "online"}]
    assert attempt == 5
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.latency_ms == expected_latency_ms
        assert node.active_connections == 5
        assert node.last_error is None


def test_monitor_marks_node_offline_when_only_two_of_five_samples_succeed(tmp_path, caplog) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sample-quorum.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="database-secret-must-not-escape",
                health_status="online",
                active_connections=7,
            )
        )
        db.commit()

    attempts = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        attempt = attempts
        if attempt > 2:
            raise httpx.ConnectError("transport-secret-must-not-escape", request=request)
        return httpx.Response(200, json=status_payload("edge-sg01", "8.8.4.4"))

    with caplog.at_level("WARNING"):
        result = EdgeHealthMonitor(
            sessions,
            client=httpx.Client(transport=httpx.MockTransport(respond)),
        ).run_once()

    assert result == [{"node": "edge-sg01", "health_status": "offline"}]
    assert attempts == 5
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "offline"
        assert node.latency_ms is None
        assert node.active_connections == 7
        assert node.last_error == "health probe request failed"
    assert "transport-secret-must-not-escape" not in caplog.text
    assert "database-secret-must-not-escape" not in caplog.text


def test_monitor_fails_closed_when_one_successful_sample_has_wrong_identity(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sample-identity.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
            )
        )
        db.commit()

    attempts = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        attempt = attempts
        node = "wrong-node-secret" if attempt == 3 else "edge-sg01"
        return httpx.Response(200, json=status_payload(node, "8.8.4.4"))

    result = EdgeHealthMonitor(
        sessions,
        client=httpx.Client(transport=httpx.MockTransport(respond)),
    ).run_once()

    assert result == [{"node": "edge-sg01", "health_status": "offline"}]
    assert attempts == 5
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "offline"
        assert node.last_seen_at is None
        assert node.last_error == "health probe node identity mismatch"


def test_monitor_fails_closed_when_one_successful_sample_has_invalid_metrics(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sample-metrics.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
            )
        )
        db.commit()

    attempts = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        attempt = attempts
        overrides = {"max_connections": 0} if attempt == 3 else {}
        return httpx.Response(
            200,
            json=status_payload("edge-sg01", "8.8.4.4", **overrides),
        )

    EdgeHealthMonitor(
        sessions,
        client=httpx.Client(transport=httpx.MockTransport(respond)),
    ).run_once()

    assert attempts == 5
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "offline"
        assert node.last_seen_at is None
        assert node.last_error == "health probe returned invalid metrics"


def test_monitor_fails_closed_when_one_sample_returns_invalid_json(tmp_path) -> None:
    sessions = single_node_sessions(tmp_path, "sample-json.db")
    attempts = 0

    def respond(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 3:
            return httpx.Response(
                200,
                request=request,
                content=b"not-json",
                headers={"content-type": "application/json"},
            )
        return httpx.Response(200, json=status_payload("edge-sg01", "8.8.4.4"))

    result = EdgeHealthMonitor(
        sessions,
        client=httpx.Client(transport=httpx.MockTransport(respond)),
    ).run_once()

    assert result == [{"node": "edge-sg01", "health_status": "offline"}]
    assert attempts == 5
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.last_seen_at is None
        assert node.last_error == "health probe returned invalid JSON"


def test_monitor_quarantines_inconsistent_sample_ips_without_persisting_a_payload(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'sample-ip-consistency.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
                actual_public_ipv4="8.8.4.4",
                active_connections=9,
            )
        )
        db.commit()

    class InconsistentIpClient:
        attempts = 0

        def get(self, url: str, *, timeout: float) -> httpx.Response:
            del timeout
            sample_index = self.attempts
            self.attempts += 1
            public_ipv4 = "8.8.8.8" if sample_index == 4 else "8.8.4.4"
            return httpx.Response(
                200,
                request=httpx.Request("GET", url),
                json=status_payload(
                    "edge-sg01",
                    public_ipv4,
                    active_connections=sample_index + 1,
                ),
            )

    result = EdgeHealthMonitor(
        sessions,
        client=InconsistentIpClient(),  # type: ignore[arg-type]
    ).run_once()

    assert result == [{"node": "edge-sg01", "health_status": "quarantined"}]
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "quarantined"
        assert node.actual_public_ipv4 == "8.8.4.4"
        assert node.active_connections == 9
        assert node.last_seen_at is None
        assert node.last_error == "health probe public IPv4 inconsistent between samples"


def test_monitor_applies_default_timeout_to_each_sequential_sample(tmp_path) -> None:
    sessions = single_node_sessions(tmp_path, "sample-timeout.db")
    timeouts: list[float] = []

    class TimeoutClient:
        def get(self, url: str, *, timeout: float) -> httpx.Response:
            timeouts.append(timeout)
            raise httpx.ReadTimeout(
                "blocked request failed",
                request=httpx.Request("GET", url),
            )

    result = EdgeHealthMonitor(
        sessions,
        client=TimeoutClient(),  # type: ignore[arg-type]
    ).run_once()

    assert result == [{"node": "edge-sg01", "health_status": "offline"}]
    assert timeouts == [5.0] * 5


def test_monitor_probes_and_updates_metrics_without_clearing_manual_maintenance(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'maintenance-monitor.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-maintenance",
                endpoint="https://edge-maintenance.example",
                shared_secret="never-return-this-secret",
                expected_public_ipv4="8.8.8.8",
                maintenance_mode=True,
                health_status="maintenance",
            )
        )
        db.commit()
    requested = []

    def respond(request: httpx.Request) -> httpx.Response:
        requested.append(request)
        return httpx.Response(200, json=status_payload("edge-maintenance", "8.8.8.8"))

    results = EdgeHealthMonitor(
        sessions, client=httpx.Client(transport=httpx.MockTransport(respond))
    ).run_once()

    assert len(requested) == 5
    assert results == [{"node": "edge-maintenance", "health_status": "maintenance"}]
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.maintenance_mode is True
        assert node.health_status == "maintenance"
        assert node.last_seen_at is not None
        assert node.active_connections == 2
        assert node.actual_public_ipv4 == "8.8.8.8"


def test_monitor_quarantines_public_ipv4_mismatch(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'mismatch.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=status_payload("edge-sg01", "1.1.1.1"))
        )
    )

    results = EdgeHealthMonitor(sessions, client=client).run_once()

    assert results == [{"node": "edge-sg01", "health_status": "quarantined"}]
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "quarantined"
        assert node.actual_public_ipv4 == "1.1.1.1"
        assert node.last_seen_at is not None
        assert node.last_error is None


def test_monitor_marks_wrong_node_offline_without_persisting_or_logging_response_secrets(
    tmp_path, caplog
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'wrong-node.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    secret = "response-secret-must-not-escape"
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="database-secret-must-not-escape",
            )
        )
        db.commit()

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "node": secret,
                    "active_connections": 0,
                    "max_connections": 10,
                    "accepted_connections": 0,
                    "denied_connections": 0,
                    "shared_secret": secret,
                },
            )
        )
    )
    with caplog.at_level("WARNING"):
        results = EdgeHealthMonitor(sessions, client=client).run_once()

    assert results == [{"node": "edge-sg01", "health_status": "offline"}]
    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "offline"
        assert node.last_seen_at is None
        assert node.latency_ms is None
        assert node.last_error == "health probe node identity mismatch"
    assert secret not in caplog.text
    assert "database-secret-must-not-escape" not in caplog.text


def test_monitor_recovers_quarantined_node_to_online(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'recovery.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                health_status="quarantined",
                expected_public_ipv4="8.8.4.4",
                actual_public_ipv4="1.1.1.1",
            )
        )
        db.commit()

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json=status_payload(
                    "edge-sg01",
                    "8.8.4.4",
                    active_connections=1,
                    max_connections=8,
                    accepted_connections=4,
                    denied_connections=2,
                ),
            )
        )
    )
    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "online"
        assert node.last_seen_at is not None
        assert node.last_error is None
        assert node.active_connections == 1
        assert node.actual_public_ipv4 == "8.8.4.4"


def test_monitor_degrades_low_memory_node(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'low-memory.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json=status_payload(
                    "edge-sg01", "8.8.4.4", memory_available_bytes=128 * 1024 * 1024 - 1
                ),
            )
        )
    )

    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        assert db.scalar(select(EdgeNode)).health_status == "degraded"


def test_monitor_degrades_low_disk_node(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'low-disk.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json=status_payload(
                    "edge-sg01", "8.8.4.4", disk_free_bytes=2 * 1024 * 1024 * 1024 - 1
                ),
            )
        )
    )

    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        assert db.scalar(select(EdgeNode)).health_status == "degraded"


def test_monitor_degrades_node_at_eighty_percent_capacity(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'capacity.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json=status_payload(
                    "edge-sg01", "8.8.4.4", active_connections=8, max_connections=10
                ),
            )
        )
    )

    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        assert db.scalar(select(EdgeNode)).health_status == "degraded"


@pytest.mark.parametrize("public_ipv4", ["10.0.0.1", "2001:4860:4860::8888", "invalid"])
def test_monitor_marks_invalid_or_non_global_public_ip_offline(tmp_path, public_ipv4) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'invalid-ip.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        db.add(
            EdgeNode(
                name="edge-sg01",
                endpoint="https://edge-sg01.example",
                shared_secret="never-log-me",
                expected_public_ipv4="8.8.4.4",
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=status_payload("edge-sg01", public_ipv4))
        )
    )

    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        node = db.scalar(select(EdgeNode))
        assert node.health_status == "offline"
        assert node.actual_public_ipv4 is None
        assert node.last_error == "health probe returned invalid public IPv4"


def test_monitor_reconciles_ready_enrollment_to_online(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'enrollment-monitor.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        node = EdgeNode(
            name="edge-enrolled",
            endpoint="https://edge-enrolled.example",
            shared_secret="never-log",
            expected_public_ipv4="8.8.8.8",
            enabled=True,
        )
        db.add(node)
        db.flush()
        db.add(
            NodeEnrollment(
                id="enrollment-monitor",
                edge_node_id=node.id,
                created_by_user_id=1,
                token_hash="a" * 64,
                report_token_hash="b" * 64,
                status="ready",
                phase="ready",
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            )
        )
        db.add(
            NodeRegistrationRequest(
                id="registration-monitor",
                status="ready",
                public_key_pem="public",
                public_key_fingerprint="c" * 64,
                machine_fingerprint="d" * 64,
                reported_hostname="edge-enrolled",
                actual_public_ipv4="8.8.8.8",
                os_name="Rocky Linux 9",
                cpu_count=2,
                memory_total_bytes=1024,
                disk_total_bytes=2048,
                agent_version="1.0.0",
                challenge_expires_at=datetime.now(UTC) + timedelta(hours=1),
                edge_node_id=node.id,
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=status_payload("edge-enrolled", "8.8.8.8"))
        )
    )

    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        enrollment = db.get(NodeEnrollment, "enrollment-monitor")
        assert enrollment.status == "online"
        assert enrollment.phase == "ready"
        assert enrollment.report_token_hash is None
        registration = db.get(NodeRegistrationRequest, "registration-monitor")
        assert registration.status == "online"
        assert registration.last_error is None


def test_monitor_recovers_failed_enrollment_when_node_becomes_online(tmp_path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'enrollment-recovery.db'}")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(engine, expire_on_commit=False)
    with sessions() as db:
        node = EdgeNode(
            name="edge-recovered",
            endpoint="https://edge-recovered.example",
            shared_secret="never-log",
            expected_public_ipv4="8.8.8.8",
            enabled=True,
        )
        db.add(node)
        db.flush()
        db.add(
            NodeEnrollment(
                id="enrollment-recovery",
                edge_node_id=node.id,
                created_by_user_id=1,
                token_hash="a" * 64,
                report_token_hash="b" * 64,
                status="failed",
                phase="failed",
                last_error="certificate was not ready",
                expires_at=datetime.now(UTC) + timedelta(minutes=30),
            )
        )
        db.commit()
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json=status_payload("edge-recovered", "8.8.8.8"))
        )
    )

    EdgeHealthMonitor(sessions, client=client).run_once()

    with sessions() as db:
        enrollment = db.get(NodeEnrollment, "enrollment-recovery")
        assert enrollment.status == "online"
        assert enrollment.last_error is None
        assert enrollment.report_token_hash is None
