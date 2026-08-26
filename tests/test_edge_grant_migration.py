from pathlib import Path

from sqlalchemy import create_engine, inspect, select

from cloudbrowser.app import create_app
from cloudbrowser.models import UserEdgeNodeGrant
from cloudbrowser.runner import FakeBrowserRunner


def test_sqlite_grant_migration_is_idempotent_unique_and_seeds_no_member_grants(tmp_path: Path):
    database = tmp_path / "legacy.db"
    database_url = f"sqlite:///{database}"
    first = create_app(
        database_url=database_url,
        secret_key="grant-migration-test-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
    )
    second = create_app(
        database_url=database_url,
        secret_key="grant-migration-test-secret-long-enough",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
    )

    schema = inspect(create_engine(database_url))
    assert "user_edge_node_grants" in schema.get_table_names()
    assert {
        tuple(item["column_names"])
        for item in schema.get_unique_constraints("user_edge_node_grants")
    } == {("user_id", "edge_node_id")}
    with first.state.db() as db:
        assert db.scalars(select(UserEdgeNodeGrant)).all() == []
    with second.state.db() as db:
        assert db.scalars(select(UserEdgeNodeGrant)).all() == []
