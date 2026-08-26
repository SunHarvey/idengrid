import json
from types import SimpleNamespace

import pytest
from edge_tunnel import __main__
from edge_tunnel.app import SETTINGS


def test_main_binds_loopback_by_default(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setattr("sys.argv", ["edge-tunnel"])
    monkeypatch.setattr(__main__.platform, "system", lambda: "Linux")
    called = {}

    def run_app(app, *, host, port, access_log):
        called.update(host=host, port=port, access_log=access_log)

    monkeypatch.setattr(__main__.web, "run_app", run_app)

    __main__.main()

    assert called == {"host": "127.0.0.1", "port": 8787, "access_log": None}


def test_main_loads_windows_secret_only_from_config_and_binds_loopback(tmp_path, monkeypatch):
    config_secret = "c" * 32
    path = tmp_path / "edge.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "node_id": "edge-windows-01",
                "ticket_secret": config_secret,
                "max_connections": 64,
                "max_frame_bytes": 1_048_576,
                "max_bytes_per_connection": 67_108_864,
                "idle_timeout": 60,
                "max_connection_seconds": 600,
                "connect_timeout": 10,
                "ticket_max_ttl": 60,
            }
        ),
        encoding="utf-8",
    )
    path.chmod(0o600)
    monkeypatch.setenv("EDGE_NODE_ID", "environment-node")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "e" * 32)
    monkeypatch.setattr("sys.argv", ["edge-tunnel", "--config", str(path)])
    monkeypatch.setattr(__main__.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        "edge_tunnel.resources.importlib.import_module", lambda name: SimpleNamespace()
    )
    called = {}

    def run_app(app, *, host, port, access_log):
        called.update(
            host=host,
            port=port,
            access_log=access_log,
            node=app[SETTINGS].node_id,
            secret=app[SETTINGS].ticket_secret,
        )

    monkeypatch.setattr(__main__.web, "run_app", run_app)

    __main__.main()

    assert called == {
        "host": "127.0.0.1",
        "port": 8787,
        "access_log": None,
        "node": "edge-windows-01",
        "secret": config_secret.encode(),
    }


def test_main_requires_config_on_windows_instead_of_reading_environment(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "environment-node")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "e" * 32)
    monkeypatch.setattr("sys.argv", ["edge-tunnel"])
    monkeypatch.setattr(__main__.platform, "system", lambda: "Windows")

    with pytest.raises(SystemExit) as error:
        __main__.main()

    assert error.value.code == 2
