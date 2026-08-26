#!/usr/bin/env python3
"""Safely migrate all Cloud Browser model data from SQLite to MySQL."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from datetime import UTC, date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, MetaData, Table, create_engine, func, inspect, select, text
from sqlalchemy.engine import URL, make_url


class MigrationError(RuntimeError):
    """A safe, expected migration refusal or verification failure."""


def load_target_url(environment_variable: str | None, protected_file: Path | None) -> URL:
    """Load a target URL without accepting its secret on the command line."""
    if bool(environment_variable) == bool(protected_file):
        raise MigrationError("specify exactly one target environment variable or protected file")
    if environment_variable:
        value = os.environ.get(environment_variable)
        if not value:
            raise MigrationError(f"target environment variable {environment_variable!r} is unset")
    else:
        assert protected_file is not None
        mode = stat.S_IMODE(protected_file.stat().st_mode)
        if mode & 0o077:
            raise MigrationError(
                "target URL file permissions must be owner-only (mode 0600 or stricter)"
            )
        value = protected_file.read_text(encoding="utf-8").strip()
    try:
        return make_url(value)
    except Exception as exc:
        raise MigrationError("target URL is invalid") from exc


def validate_urls(source: str | URL, target: str | URL) -> tuple[URL, URL]:
    source_url, target_url = make_url(source), make_url(target)
    if source_url.render_as_string(hide_password=False) == target_url.render_as_string(
        hide_password=False
    ):
        raise MigrationError("source and target must not be the same database")
    if source_url.get_backend_name() != "sqlite":
        raise MigrationError("source must be SQLite")
    if target_url.get_backend_name() != "mysql":
        raise MigrationError("target must be MySQL")
    return source_url, target_url


def _canonical_value(value: Any) -> Any:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        value = value.astimezone(UTC)
        return {"datetime": value.isoformat(timespec="microseconds").replace("+00:00", "Z")}
    if isinstance(value, date):
        return {"date": value.isoformat()}
    if isinstance(value, time):
        return {"time": value.isoformat(timespec="microseconds")}
    if isinstance(value, bytes):
        return {"bytes": base64.b64encode(value).decode("ascii")}
    if isinstance(value, Decimal):
        return {"decimal": str(value)}
    return value


def canonical_row_bytes(row: dict[str, Any]) -> bytes:
    canonical = {key: _canonical_value(value) for key, value in row.items()}
    return json.dumps(
        canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("ascii")


def copy_order(metadata: MetaData) -> list[Table]:
    """Return SQLAlchemy's deterministic dependency-sorted table order."""
    return list(metadata.sorted_tables)


def _copy_columns(table: Table, source_table: Table) -> list[str]:
    source_names = set(source_table.c.keys())
    return [
        column.name
        for column in table.columns
        if column.name in source_names and column.computed is None
    ]


def _ordered_rows(connection: Any, table: Table, columns: list[str]) -> list[dict[str, Any]]:
    selected = [table.c[name] for name in columns]
    statement = select(*selected)
    primary_key = [table.c[column.name] for column in table.primary_key if column.name in columns]
    if primary_key:
        statement = statement.order_by(*primary_key)
    return [dict(row) for row in connection.execute(statement).mappings()]


def _fingerprint(rows: list[dict[str, Any]]) -> str:
    digest = hashlib.sha256()
    for row in rows:
        payload = canonical_row_bytes(row)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest()


def _destination_nonempty(engine: Engine, metadata: MetaData) -> list[str]:
    existing = inspect(engine).get_table_names()
    if not existing:
        return []
    reflected = MetaData()
    reflected.reflect(bind=engine, only=existing)
    nonempty: list[str] = []
    with engine.connect() as connection:
        for name in existing:
            table = reflected.tables[name]
            if connection.scalar(select(func.count()).select_from(table)):
                nonempty.append(name)
    return sorted(nonempty)


def _foreign_key_orphans(connection: Any, metadata: MetaData) -> dict[str, int]:
    checks: dict[str, int] = {}
    for table in copy_order(metadata):
        for constraint in table.foreign_key_constraints:
            pairs = list(constraint.elements)
            local = [pair.parent for pair in pairs]
            remote = [pair.column for pair in pairs]
            parent = remote[0].table
            join_condition = local[0] == remote[0]
            for left, right in zip(local[1:], remote[1:], strict=True):
                join_condition &= left == right
            nonnull = local[0].is_not(None)
            for column in local[1:]:
                nonnull &= column.is_not(None)
            statement = (
                select(func.count())
                .select_from(table.outerjoin(parent, join_condition))
                .where(nonnull, remote[0].is_(None))
            )
            key = f"{table.name}:{constraint.name or ','.join(column.name for column in local)}"
            checks[key] = int(connection.scalar(statement) or 0)
    return checks


def _reset_mysql_auto_increment(engine: Engine, metadata: MetaData) -> dict[str, int]:
    if engine.dialect.name != "mysql":
        return {}
    values: dict[str, int] = {}
    preparer = engine.dialect.identifier_preparer
    with engine.begin() as connection:
        for table in copy_order(metadata):
            integer_pk = [
                column
                for column in table.primary_key
                if column.autoincrement is True or column.autoincrement == "auto"
            ]
            if len(integer_pk) != 1:
                continue
            column = integer_pk[0]
            try:
                python_type = column.type.python_type
            except NotImplementedError:
                continue
            if python_type is not int:
                continue
            maximum = connection.scalar(select(func.max(column)))
            next_value = max(1, int(maximum or 0) + 1)
            table_name = preparer.quote(table.name)
            connection.execute(text(f"ALTER TABLE {table_name} AUTO_INCREMENT = {next_value}"))
            values[table.name] = next_value
    return values


def _active_uniqueness_checks(connection: Any, metadata: MetaData) -> dict[str, int]:
    specs = (
        ("node_enrollments", ("edge_node_id",), ("pending", "claimed", "installing", "ready")),
        (
            "node_registration_requests",
            ("machine_fingerprint",),
            ("pending_proof", "pending_approval", "approved", "installing", "ready"),
        ),
        (
            "node_registration_requests",
            ("public_key_fingerprint",),
            ("pending_proof", "pending_approval", "approved", "installing", "ready"),
        ),
        (
            "store_connection_leases",
            ("store_id", "owner_user_id", "device_id"),
            ("active",),
        ),
    )
    checks: dict[str, int] = {}
    for table_name, keys, statuses in specs:
        if table_name not in metadata.tables:
            continue
        table = metadata.tables[table_name]
        grouped = (
            select(*(table.c[key] for key in keys))
            .where(table.c.status.in_(statuses))
            .group_by(*(table.c[key] for key in keys))
            .having(func.count() > 1)
            .subquery()
        )
        name = f"{table_name}:{','.join(keys)}"
        checks[name] = int(connection.scalar(select(func.count()).select_from(grouped)) or 0)
    return checks


def _mysql_generated_constraint_checks(engine: Engine) -> dict[str, bool]:
    if engine.dialect.name != "mysql":
        return {}
    expected_columns = {
        "node_enrollments": {"active_edge_node_id"},
        "node_registration_requests": {
            "active_machine_fingerprint",
            "active_public_key_fingerprint",
        },
        "store_connection_leases": {
            "active_store_id",
            "active_owner_user_id",
            "active_device_id",
        },
        "local_history_entries": {"url_sha256"},
    }
    expected_indexes = {
        "node_enrollments": {"uq_mysql_active_node_enrollment"},
        "node_registration_requests": {
            "uq_mysql_active_node_registration_machine",
            "uq_mysql_active_node_registration_key",
        },
        "store_connection_leases": {"uq_mysql_active_store_user_device_lease"},
        "local_history_entries": {"uq_mysql_local_history_user_url_sha256"},
    }
    schema = inspect(engine)
    checks: dict[str, bool] = {}
    for table, names in expected_columns.items():
        actual = {column["name"] for column in schema.get_columns(table)}
        checks[f"{table}:generated_columns"] = names <= actual
    for table, names in expected_indexes.items():
        actual = {index["name"] for index in schema.get_indexes(table)}
        checks[f"{table}:unique_indexes"] = names <= actual
    return checks


def migrate_engines(
    source: Engine,
    target: Engine,
    metadata: MetaData,
    *,
    reset_empty_destination: bool = False,
    dry_run: bool = False,
    prepare_target: Any | None = None,
) -> dict[str, Any]:
    """Copy and verify model tables. Engines are injectable for isolated tests."""
    source_tables = set(inspect(source).get_table_names())
    missing = [table.name for table in copy_order(metadata) if table.name not in source_tables]
    if missing:
        raise MigrationError(f"source is missing model tables: {', '.join(missing)}")

    nonempty = _destination_nonempty(target, metadata)
    if nonempty and not reset_empty_destination:
        raise MigrationError("refusing non-empty destination; explicit safe reset is required")

    reflected = MetaData()
    reflected.reflect(bind=source, only=[table.name for table in copy_order(metadata)])
    source_report: dict[str, dict[str, Any]] = {}
    with source.connect() as source_connection:
        for table in copy_order(metadata):
            source_table = reflected.tables[table.name]
            columns = _copy_columns(table, source_table)
            rows = _ordered_rows(source_connection, source_table, columns)
            source_report[table.name] = {
                "source_count": len(rows),
                "source_sha256": _fingerprint(rows),
            }

    if dry_run:
        return {
            "mode": "dry-run",
            "tables": source_report,
            "schema_checks": {"source_model_tables_present": True},
        }

    if reset_empty_destination:
        metadata.drop_all(target)
    metadata.create_all(target)
    if prepare_target is not None:
        prepare_target(target)

    # One transaction covers every data insert. FK-safe order avoids disabling checks.
    with source.connect() as source_connection, target.begin() as target_connection:
        for table in copy_order(metadata):
            source_table = reflected.tables[table.name]
            columns = _copy_columns(table, source_table)
            rows = _ordered_rows(source_connection, source_table, columns)
            if rows:
                target_connection.execute(table.insert(), rows)

    auto_increment = _reset_mysql_auto_increment(target, metadata)
    generated_checks = _mysql_generated_constraint_checks(target)
    if generated_checks and not all(generated_checks.values()):
        raise MigrationError("MySQL generated constraint verification failed")

    report_tables: dict[str, dict[str, Any]] = {}
    with target.connect() as target_connection:
        orphan_checks = _foreign_key_orphans(target_connection, metadata)
        uniqueness_checks = _active_uniqueness_checks(target_connection, metadata)
        for table in copy_order(metadata):
            source_table = reflected.tables[table.name]
            columns = _copy_columns(table, source_table)
            rows = _ordered_rows(target_connection, table, columns)
            target_hash = _fingerprint(rows)
            entry = {
                **source_report[table.name],
                "target_count": len(rows),
                "target_sha256": target_hash,
            }
            if (
                entry["source_count"] != entry["target_count"]
                or entry["source_sha256"] != target_hash
            ):
                raise MigrationError(f"verification failed for table {table.name}")
            report_tables[table.name] = entry
    if any(orphan_checks.values()):
        raise MigrationError("foreign-key orphan verification failed")
    if any(uniqueness_checks.values()):
        raise MigrationError("critical active uniqueness verification failed")
    return {
        "mode": "migrate",
        "tables": report_tables,
        "schema_checks": {
            "source_model_tables_present": True,
            "foreign_key_orphans": orphan_checks,
            "critical_active_duplicates": uniqueness_checks,
            "mysql_generated_constraints": generated_checks,
            "auto_increment_next": auto_increment,
            "foreign_keys_disabled": False,
        },
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", required=True, help="SQLite SQLAlchemy URL")
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--target-env", help="name of environment variable containing MySQL URL")
    target.add_argument("--target-file", type=Path, help="owner-only file containing MySQL URL")
    parser.add_argument(
        "--reset-empty-destination",
        action="store_true",
        help="explicitly drop model tables before migration (destructive)",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="inspect source and emit report only"
    )
    parser.add_argument("--report-file", type=Path, help="also write the secret-free JSON report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        target_url = load_target_url(args.target_env, args.target_file)
        source_url, target_url = validate_urls(args.source_url, target_url)
        from cloudbrowser.database import create_database_engine
        from cloudbrowser.models import Base
        from cloudbrowser.schema import migrate_mysql_active_uniqueness

        source = create_engine(source_url)
        target = create_database_engine(target_url.render_as_string(hide_password=False))
        try:
            report = migrate_engines(
                source,
                target,
                Base.metadata,
                reset_empty_destination=args.reset_empty_destination,
                dry_run=args.dry_run,
                prepare_target=migrate_mysql_active_uniqueness,
            )
        finally:
            source.dispose()
            target.dispose()
        rendered = json.dumps(report, sort_keys=True, separators=(",", ":"))
        if args.report_file:
            args.report_file.write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 0
    except MigrationError as exc:
        print(json.dumps({"error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    except Exception:  # noqa: BLE001 -- fail closed without leaking driver URLs/parameters
        # Driver exceptions commonly embed credential-bearing URLs. Fail closed.
        print(
            json.dumps({"error": "migration failed; see protected operational logs"}),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
