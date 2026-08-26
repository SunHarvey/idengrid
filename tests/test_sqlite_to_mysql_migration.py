from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import (
    Column,
    Computed,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    event,
    insert,
    select,
)

from scripts.migrate_sqlite_to_mysql import (
    MigrationError,
    _active_uniqueness_checks,
    canonical_row_bytes,
    copy_order,
    load_target_url,
    main,
    migrate_engines,
    validate_urls,
)


def test_active_lease_uniqueness_is_scoped_to_store_user_and_device() -> None:
    metadata = MetaData()
    leases = Table(
        "store_connection_leases",
        metadata,
        Column("id", String(64), primary_key=True),
        Column("store_id", Integer, nullable=False),
        Column("owner_user_id", Integer, nullable=False),
        Column("device_id", String(100), nullable=False),
        Column("status", String(20), nullable=False),
    )
    engine = create_engine("sqlite://")
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(
            insert(leases),
            [
                {"id": "a1", "store_id": 1, "owner_user_id": 10, "device_id": "one", "status": "active"},
                {"id": "a2", "store_id": 1, "owner_user_id": 10, "device_id": "two", "status": "active"},
                {"id": "b1", "store_id": 1, "owner_user_id": 11, "device_id": "one", "status": "active"},
            ],
        )
        checks = _active_uniqueness_checks(connection, metadata)
        assert checks["store_connection_leases:store_id,owner_user_id,device_id"] == 0
        connection.execute(
            insert(leases),
            {"id": "duplicate", "store_id": 1, "owner_user_id": 10, "device_id": "one", "status": "active"},
        )
        checks = _active_uniqueness_checks(connection, metadata)
        assert checks["store_connection_leases:store_id,owner_user_id,device_id"] == 1


def test_mysql_generated_lease_contract_uses_composite_active_identity() -> None:
    source = (Path(__file__).parents[1] / "scripts" / "migrate_sqlite_to_mysql.py").read_text()
    assert '"active_owner_user_id"' in source
    assert '"active_device_id"' in source
    assert '"uq_mysql_active_store_user_device_lease"' in source
    assert '"uq_mysql_active_store_connection_lease"' not in source


def test_target_url_is_loaded_only_from_named_environment_variable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DISPOSABLE_MYSQL_URL", "mysql+pymysql://user:secret@localhost/db")
    assert load_target_url("DISPOSABLE_MYSQL_URL", None).drivername.startswith("mysql")


def test_target_file_must_not_be_group_or_world_accessible(tmp_path: Path) -> None:
    target_file = tmp_path / "mysql.url"
    target_file.write_text("mysql+pymysql://user:secret@localhost/db\n")
    target_file.chmod(0o644)
    with pytest.raises(MigrationError, match="permissions"):
        load_target_url(None, target_file)


@pytest.mark.parametrize(
    ("source", "target", "message"),
    [
        ("postgresql://localhost/a", "mysql://localhost/b", "SQLite"),
        ("sqlite:///a.db", "postgresql://localhost/b", "MySQL"),
        ("sqlite:///same.db", "sqlite:///same.db", "same"),
    ],
)
def test_url_validation_rejects_unsafe_dialects(source: str, target: str, message: str) -> None:
    with pytest.raises(MigrationError, match=message):
        validate_urls(source, target)


def test_canonicalization_is_typed_stable_and_secret_safe() -> None:
    row = {
        "z": "密碼😀",
        "none": None,
        "enabled": True,
        "created_at": datetime(2026, 1, 2, 3, 4, 5, 6000, tzinfo=UTC),
        "blob": b"\x00\xff",
    }
    canonical = canonical_row_bytes(row)
    assert canonical == canonical_row_bytes(dict(reversed(list(row.items()))))
    assert canonical == (
        b'{"blob":{"bytes":"AP8="},"created_at":{"datetime":"2026-01-02T03:04:05.006000Z"},'
        b'"enabled":true,"none":null,"z":"\\u5bc6\\u78bc\\ud83d\\ude00"}'
    )


def test_copy_order_is_foreign_key_safe() -> None:
    metadata = MetaData()
    parent = Table("parent", metadata, Column("id", Integer, primary_key=True))
    Table(
        "child",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("parent_id", Integer, __import__("sqlalchemy").ForeignKey("parent.id")),
    )
    assert copy_order(metadata) == [parent, metadata.tables["child"]]


def _migration_fixture(tmp_path: Path) -> tuple[object, object, MetaData]:
    metadata = MetaData()
    parent = Table(
        "parent",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("name", String(100), nullable=False),
    )
    Table(
        "child",
        metadata,
        Column("id", Integer, primary_key=True, autoincrement=True),
        Column("parent_id", Integer, ForeignKey("parent.id"), nullable=False),
        Column("secret", String(100), nullable=False),
        Column("target_only", String(200), Computed("secret || '-generated'")),
    )
    source = create_engine(f"sqlite:///{tmp_path / 'source.db'}")
    target = create_engine(f"sqlite:///{tmp_path / 'target.db'}")
    # Simulate the legacy source, which does not have the target generated column.
    source_metadata = MetaData()
    source_parent = parent.to_metadata(source_metadata)
    source_child = Table(
        "child",
        source_metadata,
        Column("id", Integer, primary_key=True),
        Column("parent_id", Integer, ForeignKey("parent.id"), nullable=False),
        Column("secret", String(100), nullable=False),
    )
    source_metadata.create_all(source)
    with source.begin() as connection:
        connection.execute(insert(source_parent), [{"id": 7, "name": "中文😀"}])
        connection.execute(
            insert(source_child), [{"id": 11, "parent_id": 7, "secret": "never-print-this"}]
        )
    return source, target, metadata


def test_nonempty_destination_is_refused_without_explicit_reset(tmp_path: Path) -> None:
    source, target, metadata = _migration_fixture(tmp_path)
    metadata.create_all(target)
    with target.begin() as connection:
        connection.execute(insert(metadata.tables["parent"]), {"id": 99, "name": "existing"})

    with pytest.raises(MigrationError, match="non-empty"):
        migrate_engines(source, target, metadata)

    with target.connect() as connection:
        assert connection.scalar(select(metadata.tables["parent"].c.name)) == "existing"


def test_unrelated_nonempty_destination_table_is_also_refused(tmp_path: Path) -> None:
    source, target, metadata = _migration_fixture(tmp_path)
    unrelated_metadata = MetaData()
    unrelated = Table(
        "unrelated",
        unrelated_metadata,
        Column("id", Integer, primary_key=True),
    )
    unrelated_metadata.create_all(target)
    with target.begin() as connection:
        connection.execute(insert(unrelated), {"id": 1})

    with pytest.raises(MigrationError, match="non-empty"):
        migrate_engines(source, target, metadata)


def test_migration_preserves_ids_uses_fk_order_and_omits_generated_columns(tmp_path: Path) -> None:
    source, target, metadata = _migration_fixture(tmp_path)
    report = migrate_engines(source, target, metadata)

    assert list(report["tables"]) == ["parent", "child"]
    assert report["tables"]["parent"]["source_count"] == 1
    assert report["tables"]["child"]["target_count"] == 1
    assert report["tables"]["child"]["source_sha256"] == report["tables"]["child"]["target_sha256"]
    rendered = json.dumps(report)
    assert "never-print-this" not in rendered
    with target.connect() as connection:
        assert connection.execute(select(metadata.tables["parent"])).mappings().one()["id"] == 7
        child = connection.execute(select(metadata.tables["child"])).mappings().one()
        assert child["id"] == 11
        assert child["target_only"] == "never-print-this-generated"


def test_dry_run_does_not_create_or_copy_tables(tmp_path: Path) -> None:
    source, target, metadata = _migration_fixture(tmp_path)
    report = migrate_engines(source, target, metadata, dry_run=True)
    assert report["mode"] == "dry-run"
    assert report["tables"]["parent"]["source_count"] == 1
    assert __import__("sqlalchemy").inspect(target).get_table_names() == []


def test_copy_failure_rolls_back_every_insert(tmp_path: Path) -> None:
    source, target, metadata = _migration_fixture(tmp_path)
    metadata.create_all(target)

    @event.listens_for(target, "before_cursor_execute")
    def fail_child(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().upper().startswith("INSERT INTO CHILD"):
            raise RuntimeError("injected copy failure")

    with pytest.raises(RuntimeError, match="injected"):
        migrate_engines(source, target, metadata)
    with target.connect() as connection:
        assert (
            connection.scalar(
                select(__import__("sqlalchemy").func.count()).select_from(metadata.tables["parent"])
            )
            == 0
        )
        assert (
            connection.scalar(
                select(__import__("sqlalchemy").func.count()).select_from(metadata.tables["child"])
            )
            == 0
        )


def test_cli_errors_and_json_never_expose_target_secret(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    secret_url = "mysql+pymysql://migration:super-secret-value@127.0.0.1/disposable"
    monkeypatch.setenv("MIGRATION_TEST_TARGET", secret_url)
    exit_code = main(
        [
            "--source-url",
            "postgresql://source.invalid/db",
            "--target-env",
            "MIGRATION_TEST_TARGET",
        ]
    )
    captured = capsys.readouterr()
    assert exit_code == 2
    assert "super-secret-value" not in captured.out
    assert "super-secret-value" not in captured.err
    error = json.loads(captured.err)
    assert set(error) == {"error"}


def _mysql_candidate_url() -> str:
    env_file = Path("/data/deploy/mysql/mysql.env")
    values = {
        key: value
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if line and not line.lstrip().startswith("#") and "=" in line
        for key, value in [line.split("=", 1)]
    }
    from sqlalchemy.engine import URL

    return URL.create(
        "mysql+pymysql",
        username=values["MYSQL_USER"],
        password=values["MYSQL_PASSWORD"],
        host="127.0.0.1",
        port=3306,
        database=values["MYSQL_DATABASE"],
    ).render_as_string(hide_password=False)


@pytest.mark.skipif(
    __import__("os").environ.get("RUN_MYSQL_MIGRATION_INTEGRATION") != "1",
    reason="requires explicit opt-in to destructive disposable MySQL candidate test",
)
def test_real_mysql_migration_roundtrip_and_cleanup(tmp_path: Path) -> None:
    from cloudbrowser.database import create_database_engine
    from cloudbrowser.models import Base
    from cloudbrowser.schema import migrate_mysql_active_uniqueness

    source = create_engine(f"sqlite:///{tmp_path / 'complete-source.db'}")
    target = create_database_engine(_mysql_candidate_url())
    existing_tables = __import__("sqlalchemy").inspect(target).get_table_names()
    existing_metadata = MetaData()
    if existing_tables:
        existing_metadata.reflect(bind=target, only=existing_tables)
    with target.connect() as connection:
        nonempty = [
            name
            for name in existing_tables
            if connection.execute(select(existing_metadata.tables[name]).limit(1)).first()
        ]
    assert not nonempty, f"refusing to recreate non-empty MySQL tables: {sorted(nonempty)}"

    Base.metadata.create_all(source)
    timestamp = datetime(2026, 2, 3, 4, 5, 6, 789012, tzinfo=UTC)
    memory_bytes = 8 * 1024**3
    available_memory_bytes = 5 * 1024**3
    disk_bytes = 158 * 1024**3
    free_disk_bytes = 151 * 1024**3
    tables = Base.metadata.tables
    with source.begin() as connection:
        connection.execute(
            insert(tables["egress_profiles"]),
            {"id": 42, "name": "出口😀", "kind": "host", "config_json": '{"秘密":"值"}'},
        )
        connection.execute(
            insert(tables["workspaces"]),
            {"id": 51, "name": "工作区", "egress_profile_id": 42},
        )
        connection.execute(
            insert(tables["users"]),
            {
                "id": 73,
                "username": "用户😀",
                "password_hash": "$argon2id$never-expose-this-hash",
                "role": "admin",
                "enabled": True,
                "token_version": 9,
                "workspace_id": 51,
                "created_at": timestamp,
                "deleted_at": None,
            },
        )
        connection.execute(
            insert(tables["edge_nodes"]),
            {
                "id": 88,
                "name": "边缘节点",
                "endpoint": "https://edge.example.test",
                "shared_secret": "never-expose-shared-secret",
                "enabled": True,
                "maintenance_mode": False,
                "health_status": "healthy",
                "active_connections": 0,
                "max_connections": 5,
                "accepted_connections": 2,
                "denied_connections": 1,
                "memory_total_bytes": memory_bytes,
                "memory_available_bytes": available_memory_bytes,
                "disk_total_bytes": disk_bytes,
                "disk_free_bytes": free_disk_bytes,
                "created_at": timestamp,
            },
        )
        connection.execute(
            insert(tables["node_registration_requests"]),
            {
                "id": "registration-large-resources",
                "status": "pending_proof",
                "public_key_pem": "test-public-key",
                "public_key_fingerprint": "b" * 64,
                "machine_fingerprint": "c" * 64,
                "reported_hostname": "large-resource-node",
                "actual_public_ipv4": "192.0.2.1",
                "os_name": "Linux",
                "cpu_count": 8,
                "memory_total_bytes": memory_bytes,
                "disk_total_bytes": disk_bytes,
                "agent_version": "test",
                "challenge_expires_at": timestamp,
                "created_at": timestamp,
                "updated_at": timestamp,
                "install_admin_ssh_key": False,
            },
        )
        connection.execute(
            insert(tables["device_sessions"]),
            {
                "id": "session-history-1",
                "user_id": 73,
                "device_id": "mac-😀",
                "device_name": "中文 Mac",
                "platform": "macos",
                "refresh_token_hash": "a" * 64,
                "token_generation": 2,
                "created_at": timestamp,
                "updated_at": timestamp,
                "last_seen_at": timestamp,
                "expires_at": timestamp,
                "revoked_at": None,
            },
        )
        connection.execute(
            insert(tables["local_history_entries"]),
            {
                "id": 101,
                "user_id": 73,
                "url": "https://例子.test/路径/😀?token=secret-query-value",
                "title": "历史记录 😀",
                "last_visit_ms": 1770000000000,
                "visit_count": 4,
            },
        )
        connection.execute(
            insert(tables["audit_events"]),
            {
                "id": 202,
                "actor_user_id": 73,
                "event_type": "migration_fixture",
                "target_type": "历史",
                "target_id": "101",
                "details_json": '{"secret":"audit-secret"}',
                "created_at": timestamp,
            },
        )

    try:
        report = migrate_engines(
            source,
            target,
            Base.metadata,
            reset_empty_destination=True,
            prepare_target=migrate_mysql_active_uniqueness,
        )
        assert len(report["tables"]) == 16
        assert (
            report["tables"]["local_history_entries"]["source_sha256"]
            == report["tables"]["local_history_entries"]["target_sha256"]
        )
        assert all(report["schema_checks"]["mysql_generated_constraints"].values())
        assert report["schema_checks"]["auto_increment_next"]["egress_profiles"] == 43
        mysql_schema = __import__("sqlalchemy").inspect(target)
        for table_name, column_names in {
            "edge_nodes": {
                "memory_total_bytes",
                "memory_available_bytes",
                "disk_total_bytes",
                "disk_free_bytes",
            },
            "node_registration_requests": {"memory_total_bytes", "disk_total_bytes"},
            "local_history_entries": {"last_visit_ms"},
        }.items():
            mysql_columns = {
                column["name"]: column for column in mysql_schema.get_columns(table_name)
            }
            assert all(
                mysql_columns[column_name]["type"].__class__.__name__ == "BIGINT"
                for column_name in column_names
            )
        safe_json = json.dumps(report)
        for secret in ("never-expose", "secret-query-value", "audit-secret"):
            assert secret not in safe_json
        with target.begin() as connection:
            edge_resources = connection.execute(
                select(
                    tables["edge_nodes"].c.memory_total_bytes,
                    tables["edge_nodes"].c.memory_available_bytes,
                    tables["edge_nodes"].c.disk_total_bytes,
                    tables["edge_nodes"].c.disk_free_bytes,
                ).where(tables["edge_nodes"].c.id == 88)
            ).one()
            assert edge_resources == (
                memory_bytes,
                available_memory_bytes,
                disk_bytes,
                free_disk_bytes,
            )
            registration_resources = connection.execute(
                select(
                    tables["node_registration_requests"].c.memory_total_bytes,
                    tables["node_registration_requests"].c.disk_total_bytes,
                ).where(tables["node_registration_requests"].c.id == "registration-large-resources")
            ).one()
            assert registration_resources == (memory_bytes, disk_bytes)
            result = connection.execute(
                insert(tables["egress_profiles"]),
                {"name": "next", "kind": "host", "config_json": "{}"},
            )
            assert result.inserted_primary_key == (43,)
    finally:
        with target.begin() as connection:
            for table in reversed(copy_order(Base.metadata)):
                connection.execute(table.delete())
        source.dispose()
        target.dispose()
