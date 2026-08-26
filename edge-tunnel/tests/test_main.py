from edge_tunnel import __main__


def test_main_binds_loopback_by_default(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setattr("sys.argv", ["edge-tunnel"])
    called = {}

    def run_app(app, *, host, port, access_log):
        called.update(host=host, port=port, access_log=access_log)

    monkeypatch.setattr(__main__.web, "run_app", run_app)

    __main__.main()

    assert called == {"host": "127.0.0.1", "port": 8787, "access_log": None}
