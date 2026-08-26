from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cloudbrowser.app import create_app
from cloudbrowser.models import EdgeNode
from cloudbrowser.runner import FakeBrowserRunner
from tests.example_topology import EXAMPLE_TOPOLOGY


@pytest.fixture()
def system(tmp_path: Path):
    runner = FakeBrowserRunner(egress_ip="203.0.113.10")
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        secret_key="test-secret-that-is-long-enough",
        runner=runner,
        bootstrap_admin=("admin", "Admin-password-123"),
        bootstrap_topology=EXAMPLE_TOPOLOGY,
        cloud_video_enabled=True,
    )
    with app.state.db() as db:
        for node in db.scalars(select(EdgeNode)).all():
            node.health_status = "online"
        db.commit()
    with TestClient(app) as client:
        yield client, runner
