from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml
from sqlalchemy import create_mock_engine, inspect, text
from sqlalchemy.exc import IntegrityError

from cloudbrowser.database import create_database_engine
from cloudbrowser.models import Base
from cloudbrowser.schema import (
    migrate_mysql_active_uniqueness,
    mysql_active_uniqueness_statements,
    mysql_device_platform_constraint_statements,
)

ROOT = Path(__file__).parents[1]
MYSQL_DEPLOY = ROOT / "deploy" / "mysql"


def test_mysql_compose_is_loopback_persistent_and_health_checked() -> None:
    compose = yaml.safe_load((MYSQL_DEPLOY / "compose.yaml").read_text())
    service = compose["services"]["mysql"]

    assert service["image"] == "docker.io/library/mysql:8.4"
    assert service["ports"] == ["127.0.0.1:3306:3306"]
    assert "idengrid-mysql-data:/var/lib/mysql" in service["volumes"]
    assert "/data/mysql/data:/var/lib/mysql:Z" not in service["volumes"]
    assert "idengrid-mysql-data" in compose["volumes"]
    assert service["environment"]["TZ"] == "Asia/Singapore"
    assert service["env_file"] == ["mysql.env"]
    assert service["healthcheck"]["test"] == [
        "CMD-SHELL",
        'mysqladmin ping -h 127.0.0.1 -uroot -p"$${MYSQL_ROOT_PASSWORD}" --silent',
    ]


def test_mysql_config_contract_uses_requested_timezone_and_utf8mb4() -> None:
    compose_text = (MYSQL_DEPLOY / "compose.yaml").read_text()
    config = (MYSQL_DEPLOY / "my.cnf").read_text()
    init_sql = (MYSQL_DEPLOY / "init" / "001-charset.sql").read_text()
    env_template = (MYSQL_DEPLOY / "mysql.env.example").read_text()

    assert "--default-time-zone=+08:00" in compose_text
    assert "character-set-server=utf8mb4" in config
    assert "collation-server=utf8mb4_0900_ai_ci" in config
    assert "DEFAULT CHARACTER SET utf8mb4" in init_sql
    assert "DEFAULT COLLATE utf8mb4_0900_ai_ci" in init_sql
    assert "[REDACTED]" in env_template
    assert "mysql.env" in (ROOT / ".gitignore").read_text()


def test_database_engine_keeps_sqlite_compatible(tmp_path: Path) -> None:
    engine = create_database_engine(f"sqlite:///{tmp_path / 'engine.db'}")

    with engine.connect() as connection:
        assert connection.scalar(text("SELECT 1")) == 1


def test_database_engine_sets_mysql_utf8mb4_and_utc_session() -> None:
    engine = create_database_engine(
        "mysql+pymysql://app:secret@127.0.0.1/cloudbrowser",
        creator=lambda: None,
    )

    assert engine.url.query["charset"] == "utf8mb4"
    assert engine.dialect.create_connect_args(engine.url)[1]["init_command"] == (
        "SET time_zone = '+00:00'"
    )


def test_app_and_monitor_share_database_engine_helper() -> None:
    app_source = (ROOT / "cloudbrowser" / "app.py").read_text()
    monitor_source = (ROOT / "scripts" / "monitor_edge_health.py").read_text()

    assert "from .database import create_database_engine as create_engine" in app_source
    assert "from cloudbrowser.database import create_database_engine" in monitor_source
    assert "create_database_engine(args.database_url)" in monitor_source
    assert 'connect_args={"check_same_thread": False}' not in app_source


def _metadata_ddl(url: str) -> str:
    statements: list[str] = []
    engine = create_mock_engine(
        url,
        lambda sql, *multiparams, **params: statements.append(
            str(sql.compile(dialect=engine.dialect))
        ),
    )
    Base.metadata.create_all(engine)
    return "\n".join(statements)


def _table_ddl(metadata_ddl: str, table: str) -> str:
    return metadata_ddl.split(f"CREATE TABLE {table}", 1)[1].split("CREATE TABLE", 1)[0]


def test_resource_byte_counts_compile_as_mysql_bigint_and_sqlite_integer() -> None:
    mysql_ddl = _metadata_ddl("mysql+pymysql://")
    sqlite_ddl = _metadata_ddl("sqlite://")
    expected = {
        "edge_nodes": (
            "memory_total_bytes",
            "memory_available_bytes",
            "disk_total_bytes",
            "disk_free_bytes",
        ),
        "node_registration_requests": ("memory_total_bytes", "disk_total_bytes"),
        "local_history_entries": ("last_visit_ms",),
    }

    for table, columns in expected.items():
        mysql_table = _table_ddl(mysql_ddl, table)
        sqlite_table = _table_ddl(sqlite_ddl, table)
        for column in columns:
            assert f"{column} BIGINT" in mysql_table
            assert f"{column} INTEGER" in sqlite_table


def test_node_float_metrics_compile_as_mysql_double() -> None:
    mysql_table = _table_ddl(_metadata_ddl("mysql+pymysql://"), "edge_nodes")
    assert "load_1m DOUBLE" in mysql_table
    assert "uptime_seconds DOUBLE" in mysql_table


def test_partial_unique_indexes_are_not_rendered_as_full_mysql_indexes() -> None:
    mysql_ddl = _metadata_ddl("mysql+pymysql://")
    sqlite_ddl = _metadata_ddl("sqlite://")
    partial_names = {
        "uq_active_node_enrollment",
        "uq_active_node_registration_machine",
        "uq_active_node_registration_key",
        "uq_active_store_user_device_lease",
    }

    assert not any(name in mysql_ddl for name in partial_names)
    assert all(name in sqlite_ddl for name in partial_names)


def test_local_history_full_url_unique_constraint_is_not_rendered_for_mysql() -> None:
    mysql_ddl = _metadata_ddl("mysql+pymysql://")
    sqlite_ddl = _metadata_ddl("sqlite://")
    postgresql_ddl = _metadata_ddl("postgresql://")

    mysql_table = mysql_ddl.split("CREATE TABLE local_history_entries", 1)[1].split(
        "CREATE TABLE", 1
    )[0]
    sqlite_table = sqlite_ddl.split("CREATE TABLE local_history_entries", 1)[1].split(
        "CREATE TABLE", 1
    )[0]
    postgresql_table = postgresql_ddl.split("CREATE TABLE local_history_entries", 1)[1].split(
        "CREATE TABLE", 1
    )[0]
    assert "url TEXT NOT NULL" in mysql_table
    assert "UNIQUE (user_id, url)" not in mysql_table
    assert "url TEXT NOT NULL" in sqlite_table
    assert "UNIQUE (user_id, url)" in sqlite_table
    assert "url TEXT NOT NULL" in postgresql_table
    assert "UNIQUE (user_id, url)" in postgresql_table


class _SchemaInspector:
    def __init__(self, populated: bool = False) -> None:
        self.populated = populated

    def get_columns(self, table: str) -> list[dict[str, str]]:
        if not self.populated:
            return []
        if table == "store_connection_leases":
            return [
                {"name": "active_store_id"},
                {"name": "active_owner_user_id"},
                {"name": "active_device_id"},
            ]
        expected = {
            "node_enrollments": "active_edge_node_id",
            "node_registration_requests": "active_machine_fingerprint",
            "local_history_entries": "url_sha256",
        }
        columns = [{"name": expected[table]}]
        if table == "node_registration_requests":
            columns.append({"name": "active_public_key_fingerprint"})
        return columns

    def get_indexes(self, table: str) -> list[dict[str, str]]:
        if not self.populated:
            return []
        expected = {
            "node_enrollments": "uq_mysql_active_node_enrollment",
            "node_registration_requests": "uq_mysql_active_node_registration_machine",
            "store_connection_leases": "uq_mysql_active_store_user_device_lease",
            "local_history_entries": "uq_mysql_local_history_user_url_sha256",
        }
        indexes = [{"name": expected[table]}]
        if table == "node_registration_requests":
            indexes.append({"name": "uq_mysql_active_node_registration_key"})
        return indexes


def test_mysql_active_uniqueness_uses_generated_nullable_columns() -> None:
    statements = mysql_active_uniqueness_statements(_SchemaInspector())
    ddl = "\n".join(statements)

    assert len(statements) == 12
    assert "active_edge_node_id BIGINT GENERATED ALWAYS AS" in ddl
    assert "active_machine_fingerprint VARCHAR(64) GENERATED ALWAYS AS" in ddl
    assert "active_public_key_fingerprint VARCHAR(64) GENERATED ALWAYS AS" in ddl
    assert "active_store_id BIGINT GENERATED ALWAYS AS" in ddl
    assert "active_owner_user_id BIGINT GENERATED ALWAYS AS" in ddl
    assert "active_device_id VARCHAR(100) GENERATED ALWAYS AS" in ddl
    assert "ELSE NULL END) STORED" in ddl
    assert "CREATE UNIQUE INDEX uq_mysql_active_node_enrollment" in ddl
    assert "CREATE UNIQUE INDEX uq_mysql_active_node_registration_machine" in ddl
    assert "CREATE UNIQUE INDEX uq_mysql_active_node_registration_key" in ddl
    assert "CREATE UNIQUE INDEX uq_mysql_active_store_user_device_lease" in ddl
    assert "(active_store_id, active_owner_user_id, active_device_id)" in ddl


class _LegacyStoreLeaseInspector(_SchemaInspector):
    def get_columns(self, table: str) -> list[dict[str, str]]:
        if table == "store_connection_leases":
            return [{"name": "active_store_id"}]
        return super().get_columns(table)

    def get_indexes(self, table: str) -> list[dict[str, str]]:
        if table == "store_connection_leases":
            return [{"name": "uq_mysql_active_store_connection_lease"}]
        return super().get_indexes(table)


def test_mysql_store_lease_migration_drops_global_lock_before_scoped_index() -> None:
    statements = mysql_active_uniqueness_statements(_LegacyStoreLeaseInspector(populated=True))
    ddl = "\n".join(statements)
    assert statements[0] == (
        "DROP INDEX uq_mysql_active_store_connection_lease ON store_connection_leases"
    )
    assert "ADD COLUMN active_owner_user_id BIGINT" in ddl
    assert "ADD COLUMN active_device_id VARCHAR(100)" in ddl
    assert statements[-1] == (
        "CREATE UNIQUE INDEX uq_mysql_active_store_user_device_lease "
        "ON store_connection_leases "
        "(active_store_id, active_owner_user_id, active_device_id)"
    )


def test_mysql_history_uniqueness_uses_full_url_sha256_generated_column() -> None:
    ddl = "\n".join(mysql_active_uniqueness_statements(_SchemaInspector()))

    assert (
        "ALTER TABLE local_history_entries ADD COLUMN url_sha256 BINARY(32) "
        "GENERATED ALWAYS AS (UNHEX(SHA2(url,256))) STORED"
    ) in ddl
    assert (
        "CREATE UNIQUE INDEX uq_mysql_local_history_user_url_sha256 "
        "ON local_history_entries (user_id, url_sha256)"
    ) in ddl


def test_mysql_active_uniqueness_migration_is_idempotent_after_application() -> None:
    assert mysql_active_uniqueness_statements(_SchemaInspector(populated=True)) == []


class _DevicePlatformInspector:
    def __init__(self, names: tuple[str, ...]) -> None:
        self.names = names

    def get_check_constraints(self, table: str) -> list[dict[str, str]]:
        assert table == "device_sessions"
        return [{"name": name, "sqltext": ""} for name in self.names]


def test_mysql_device_platform_constraint_replaces_macos_only_check() -> None:
    statements = mysql_device_platform_constraint_statements(
        _DevicePlatformInspector(("ck_device_sessions_platform_macos",))
    )
    assert statements == [
        "ALTER TABLE device_sessions DROP CHECK ck_device_sessions_platform_macos",
        (
            "ALTER TABLE device_sessions ADD CONSTRAINT "
            "ck_device_sessions_platform_supported "
            "CHECK (platform IN ('macos','windows'))"
        ),
    ]


def test_mysql_device_platform_constraint_migration_is_idempotent() -> None:
    assert (
        mysql_device_platform_constraint_statements(
            _DevicePlatformInspector(("ck_device_sessions_platform_supported",))
        )
        == []
    )


def test_app_runs_mysql_constraint_migration_after_create_all() -> None:
    source = (ROOT / "cloudbrowser" / "app.py").read_text()
    assert source.index("Base.metadata.create_all(engine)") < source.index(
        "migrate_mysql_active_uniqueness(engine)"
    )


@pytest.mark.skipif(
    "CLOUDBROWSER_MYSQL_TEST_URL" not in os.environ,
    reason="requires an explicitly provided disposable MySQL schema",
)
def test_mysql_local_history_full_url_uniqueness_integration() -> None:
    engine = create_database_engine(os.environ["CLOUDBROWSER_MYSQL_TEST_URL"])
    assert engine.dialect.name == "mysql"

    # This test is destructive by design, so refuse to recreate a non-empty schema.
    existing_tables = inspect(engine).get_table_names()
    preparer = engine.dialect.identifier_preparer
    with engine.connect() as connection:
        nonempty = {
            table
            for table in existing_tables
            if connection.scalar(text(f"SELECT COUNT(*) FROM {preparer.quote(table)}"))
        }
    assert not nonempty, f"refusing to recreate non-empty MySQL tables: {sorted(nonempty)}"

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    migrate_mysql_active_uniqueness(engine)
    migrate_mysql_active_uniqueness(engine)

    schema = inspect(engine)
    history_columns = {
        column["name"]: column for column in schema.get_columns("local_history_entries")
    }
    history_indexes = {index["name"] for index in schema.get_indexes("local_history_entries")}
    assert history_columns["url"]["type"].__class__.__name__ == "TEXT"
    assert history_columns["url_sha256"]["computed"]["persisted"] is True
    assert "uq_mysql_local_history_user_url_sha256" in history_indexes
    lease_columns = {
        column["name"]: column for column in schema.get_columns("store_connection_leases")
    }
    lease_indexes = {index["name"] for index in schema.get_indexes("store_connection_leases")}
    assert lease_columns["active_store_id"]["computed"]["persisted"] is True
    assert lease_columns["active_owner_user_id"]["computed"]["persisted"] is True
    assert lease_columns["active_device_id"]["computed"]["persisted"] is True
    assert "uq_mysql_active_store_user_device_lease" in lease_indexes
    assert "uq_mysql_active_store_connection_lease" not in lease_indexes

    shared_prefix = "https://example.test/" + ("路😀" * 600)
    first_url = shared_prefix + "?variant=first"
    second_url = shared_prefix + "?variant=second"
    assert len(shared_prefix) > 1000

    with engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO egress_profiles (id, name, kind, config_json) "
                "VALUES (1, 'host', 'host', '{}')"
            )
        )
        connection.execute(
            text("INSERT INTO workspaces (id, name, egress_profile_id) VALUES (1, 'test', 1)")
        )
        connection.execute(
            text(
                "INSERT INTO users (id, username, password_hash, role, enabled, token_version, "
                "workspace_id, created_at) "
                "VALUES (1, 'one', 'x', 'member', 1, 1, 1, UTC_TIMESTAMP()), "
                "(2, 'two', 'x', 'member', 1, 1, 1, UTC_TIMESTAMP())"
            )
        )
        connection.execute(
            text(
                "INSERT INTO edge_nodes "
                "(id, name, endpoint, shared_secret, enabled, created_at) "
                "VALUES (1, 'edge', 'https://edge.example', 'test-secret-value', 1, "
                "UTC_TIMESTAMP())"
            )
        )
        connection.execute(
            text(
                "INSERT INTO managed_stores "
                "(id, label, owner_user_id, edge_node_id, enabled, created_at) "
                "VALUES (1, 'store', 1, 1, 1, UTC_TIMESTAMP())"
            )
        )
        connection.execute(
            text(
                "INSERT INTO store_connection_leases "
                "(id, store_id, owner_user_id, device_id, status, created_at, expires_at, "
                "last_heartbeat_at) VALUES "
                "('lease-1', 1, 1, 'device-1', 'active', UTC_TIMESTAMP(), "
                "DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR), UTC_TIMESTAMP()), "
                "('lease-2', 1, 1, 'device-2', 'active', UTC_TIMESTAMP(), "
                "DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR), UTC_TIMESTAMP()), "
                "('lease-3', 1, 2, 'device-1', 'active', UTC_TIMESTAMP(), "
                "DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR), UTC_TIMESTAMP())"
            )
        )
        connection.execute(
            text(
                "INSERT INTO local_history_entries "
                "(user_id, url, title, last_visit_ms, visit_count) "
                "VALUES (:user_id, :url, '', 1, 1)"
            ),
            [
                {"user_id": 1, "url": first_url},
                {"user_id": 1, "url": second_url},
                {"user_id": 2, "url": first_url},
            ],
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO local_history_entries "
                "(user_id, url, title, last_visit_ms, visit_count) "
                "VALUES (1, :url, '', 1, 1)"
            ),
            {"url": first_url},
        )

    with pytest.raises(IntegrityError), engine.begin() as connection:
        connection.execute(
            text(
                "INSERT INTO store_connection_leases "
                "(id, store_id, owner_user_id, device_id, status, created_at, expires_at, "
                "last_heartbeat_at) VALUES "
                "('lease-duplicate', 1, 1, 'device-1', 'active', UTC_TIMESTAMP(), "
                "DATE_ADD(UTC_TIMESTAMP(), INTERVAL 8 HOUR), UTC_TIMESTAMP())"
            )
        )

    with engine.connect() as connection:
        lease_rows = connection.execute(
            text(
                "SELECT owner_user_id, device_id FROM store_connection_leases "
                "WHERE status = 'active' ORDER BY id"
            )
        ).all()
    assert lease_rows == [(1, "device-1"), (1, "device-2"), (2, "device-1")]

    with engine.connect() as connection:
        roundtrip = connection.execute(
            text("SELECT user_id, url FROM local_history_entries ORDER BY id")
        ).all()
    assert roundtrip == [(1, first_url), (1, second_url), (2, first_url)]

    # Leave the disposable candidate schema empty for repeatable manual runs.
    with engine.begin() as connection:
        connection.execute(text("DELETE FROM local_history_entries WHERE user_id IN (1, 2)"))
        connection.execute(text("DELETE FROM store_connection_leases WHERE store_id = 1"))
        connection.execute(text("DELETE FROM managed_stores WHERE id = 1"))
        connection.execute(text("DELETE FROM edge_nodes WHERE id = 1"))
        connection.execute(text("DELETE FROM users WHERE id IN (1, 2)"))
        connection.execute(text("DELETE FROM workspaces WHERE id = 1"))
        connection.execute(text("DELETE FROM egress_profiles WHERE id = 1"))
