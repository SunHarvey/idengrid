from __future__ import annotations

from typing import Protocol

from sqlalchemy import Engine, inspect, text


class SchemaInspector(Protocol):
    def get_columns(self, table_name: str) -> list[dict]: ...

    def get_indexes(self, table_name: str) -> list[dict]: ...

    def get_check_constraints(self, table_name: str) -> list[dict]: ...


def edge_platform_migration_statements(
    schema: SchemaInspector, _dialect_name: str
) -> list[str]:
    """Add platform metadata without rewriting or dropping existing rows."""
    statements: list[str] = []
    for table in ("edge_nodes", "node_registration_requests"):
        columns = {item["name"] for item in schema.get_columns(table)}
        if "platform" not in columns:
            inline_check = (
                " CHECK (platform IN ('linux','windows'))"
                if _dialect_name == "sqlite"
                else ""
            )
            statements.append(
                f"ALTER TABLE {table} ADD COLUMN platform VARCHAR(20) "
                f"NOT NULL DEFAULT 'linux'{inline_check}"
            )
        if _dialect_name == "mysql":
            constraint = f"ck_{table}_platform"
            constraints = {
                item["name"]
                for item in schema.get_check_constraints(table)
                if item.get("name")
            }
            if constraint not in constraints:
                statements.append(
                    f"ALTER TABLE {table} ADD CONSTRAINT {constraint} "
                    "CHECK (platform IN ('linux','windows'))"
                )
    return statements


def migrate_edge_platform_schema(engine: Engine) -> None:
    """Idempotently backfill legacy Edge records as Linux on SQLite/MySQL."""
    schema = inspect(engine)
    statements = edge_platform_migration_statements(schema, engine.dialect.name)
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


_MYSQL_ACTIVE_UNIQUENESS = (
    (
        "node_enrollments",
        "active_edge_node_id",
        "BIGINT",
        (
            "CASE WHEN status IN ('pending','claimed','installing','ready') "
            "THEN edge_node_id ELSE NULL END"
        ),
        "uq_mysql_active_node_enrollment",
        "active_edge_node_id",
    ),
    (
        "node_registration_requests",
        "active_machine_fingerprint",
        "VARCHAR(64)",
        (
            "CASE WHEN status IN "
            "('pending_proof','pending_approval','approved','installing','ready') "
            "THEN machine_fingerprint ELSE NULL END"
        ),
        "uq_mysql_active_node_registration_machine",
        "active_machine_fingerprint",
    ),
    (
        "node_registration_requests",
        "active_public_key_fingerprint",
        "VARCHAR(64)",
        (
            "CASE WHEN status IN "
            "('pending_proof','pending_approval','approved','installing','ready') "
            "THEN public_key_fingerprint ELSE NULL END"
        ),
        "uq_mysql_active_node_registration_key",
        "active_public_key_fingerprint",
    ),
    (
        "local_history_entries",
        "url_sha256",
        "BINARY(32)",
        "UNHEX(SHA2(url,256))",
        "uq_mysql_local_history_user_url_sha256",
        "user_id, url_sha256",
    ),
)


def mysql_active_store_lease_statements(schema: SchemaInspector) -> list[str]:
    """Migrate active lease uniqueness from store-global to user/device scoped."""
    columns = {item["name"] for item in schema.get_columns("store_connection_leases")}
    indexes = {item["name"] for item in schema.get_indexes("store_connection_leases")}
    statements: list[str] = []
    legacy_index = "uq_mysql_active_store_connection_lease"
    scoped_index = "uq_mysql_active_store_user_device_lease"
    if legacy_index in indexes:
        statements.append(
            f"DROP INDEX {legacy_index} ON store_connection_leases"
        )
    generated = (
        (
            "active_store_id",
            "BIGINT",
            "CASE WHEN status = 'active' THEN store_id ELSE NULL END",
        ),
        (
            "active_owner_user_id",
            "BIGINT",
            "CASE WHEN status = 'active' THEN owner_user_id ELSE NULL END",
        ),
        (
            "active_device_id",
            "VARCHAR(100)",
            "CASE WHEN status = 'active' THEN device_id ELSE NULL END",
        ),
    )
    for column, data_type, expression in generated:
        if column not in columns:
            statements.append(
                f"ALTER TABLE store_connection_leases ADD COLUMN {column} {data_type} "
                f"GENERATED ALWAYS AS ({expression}) STORED"
            )
    if scoped_index not in indexes:
        statements.append(
            f"CREATE UNIQUE INDEX {scoped_index} ON store_connection_leases "
            "(active_store_id, active_owner_user_id, active_device_id)"
        )
    return statements


def mysql_active_uniqueness_statements(schema: SchemaInspector) -> list[str]:
    """Return only missing MySQL DDL for dialect-specific uniqueness."""
    statements: list[str] = mysql_active_store_lease_statements(schema)
    by_table: dict[str, tuple[set[str], set[str]]] = {}
    for (
        table,
        column,
        data_type,
        generated_expression,
        index_name,
        index_columns,
    ) in _MYSQL_ACTIVE_UNIQUENESS:
        if table not in by_table:
            columns = {item["name"] for item in schema.get_columns(table)}
            indexes = {item["name"] for item in schema.get_indexes(table)}
            by_table[table] = columns, indexes
        columns, indexes = by_table[table]
        if column not in columns:
            statements.append(
                f"ALTER TABLE {table} ADD COLUMN {column} {data_type} "
                f"GENERATED ALWAYS AS ({generated_expression}) STORED"
            )
        if index_name not in indexes:
            statements.append(f"CREATE UNIQUE INDEX {index_name} ON {table} ({index_columns})")
    return statements


def migrate_mysql_active_uniqueness(engine: Engine) -> None:
    """Idempotently add MySQL generated-column uniqueness equivalents."""
    if engine.dialect.name != "mysql":
        return
    schema = inspect(engine)
    with engine.begin() as connection:
        for statement in mysql_active_uniqueness_statements(schema):
            connection.execute(text(statement))


def mysql_device_platform_constraint_statements(schema: SchemaInspector) -> list[str]:
    """Return idempotent MySQL DDL that enables macOS and Windows devices."""
    names = {
        item["name"]
        for item in schema.get_check_constraints("device_sessions")
        if item.get("name")
    }
    supported = "ck_device_sessions_platform_supported"
    if supported in names:
        return []

    statements: list[str] = []
    legacy = "ck_device_sessions_platform_macos"
    if legacy in names:
        statements.append(f"ALTER TABLE device_sessions DROP CHECK {legacy}")
    statements.append(
        "ALTER TABLE device_sessions ADD CONSTRAINT "
        "ck_device_sessions_platform_supported "
        "CHECK (platform IN ('macos','windows'))"
    )
    return statements


def migrate_mysql_device_platform_constraint(engine: Engine) -> None:
    """Idempotently allow supported native client platforms in MySQL."""
    if engine.dialect.name != "mysql":
        return
    schema = inspect(engine)
    with engine.begin() as connection:
        for statement in mysql_device_platform_constraint_statements(schema):
            connection.execute(text(statement))
