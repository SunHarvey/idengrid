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


def test_main_loads_windows_secret_only_from_config_and_binds_loopback(monkeypatch):
    config_secret = b"c" * 32
    config_path = r"C:\ProgramData\IdenGrid\edge.json"
    settings = __main__.Settings(node_id="edge-windows-01", ticket_secret=config_secret)
    monkeypatch.setenv("EDGE_NODE_ID", "environment-node")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "e" * 32)
    monkeypatch.setattr("sys.argv", ["edge-tunnel", "--config", config_path])
    monkeypatch.setattr(__main__.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        __main__.Settings,
        "from_file",
        lambda path: settings if path == config_path else pytest.fail("unexpected config path"),
    )
    monkeypatch.setattr(
        __main__.Settings,
        "from_env",
        lambda: pytest.fail("Windows must not read secret environment variables"),
    )
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
        "secret": config_secret,
    }


def test_main_requires_config_on_windows_instead_of_reading_environment(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "environment-node")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "e" * 32)
    monkeypatch.setattr("sys.argv", ["edge-tunnel"])
    monkeypatch.setattr(__main__.platform, "system", lambda: "Windows")

    with pytest.raises(SystemExit) as error:
        __main__.main()

    assert error.value.code == 2


def test_main_rejects_config_on_linux_without_opening_file(monkeypatch):
    monkeypatch.setattr("sys.argv", ["edge-tunnel", "--config", "/tmp/edge.json"])
    monkeypatch.setattr(__main__.platform, "system", lambda: "Linux")
    monkeypatch.setattr(
        __main__.Settings,
        "from_file",
        lambda path: pytest.fail("Linux must not open a config file"),
    )

    with pytest.raises(SystemExit) as error:
        __main__.main()

    assert error.value.code == 2
