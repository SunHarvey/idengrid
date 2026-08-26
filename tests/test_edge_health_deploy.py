from __future__ import annotations

from pathlib import Path

from scripts.monitor_edge_health import default_database_url

ROOT = Path(__file__).parents[1]


def test_monitor_script_defaults_to_runtime_database_without_needing_app_secret(
    monkeypatch,
) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATA_DIR", "/tmp/edge-health-runtime")
    monkeypatch.delenv("SECRET_KEY", raising=False)

    assert default_database_url() == "sqlite:////tmp/edge-health-runtime/cloudbrowser.db"


def test_systemd_oneshot_and_timer_run_health_monitor_every_thirty_seconds() -> None:
    service = (ROOT / "deploy" / "idengrid-edge-health.service").read_text()
    timer = (ROOT / "deploy" / "idengrid-edge-health.timer").read_text()

    assert "Type=oneshot" in service
    assert "User=idengrid-control" in service
    assert "scripts/monitor_edge_health.py" in service
    assert "EnvironmentFile=/etc/idengrid/control.env" in service
    assert "OnUnitActiveSec=30s" in timer
    assert "Persistent=true" in timer
    assert "WantedBy=timers.target" in timer
