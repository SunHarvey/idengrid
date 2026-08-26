import pytest
from edge_tunnel.app import Settings


def test_settings_load_required_identity_and_limits_from_environment(monkeypatch):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv("EDGE_MAX_CONNECTIONS", "12")

    settings = Settings.from_env()

    assert settings.node_id == "edge-sg01"
    assert settings.ticket_secret == b"x" * 32
    assert settings.max_connections == 12


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("EDGE_MAX_CONNECTIONS", "0"),
        ("EDGE_MAX_FRAME_BYTES", "0"),
        ("EDGE_MAX_BYTES", "0"),
        ("EDGE_IDLE_TIMEOUT", "0"),
        ("EDGE_MAX_DURATION", "0"),
        ("EDGE_CONNECT_TIMEOUT", "0"),
        ("EDGE_TICKET_MAX_TTL", "0"),
        ("EDGE_MAX_CONNECTIONS", "not-an-int"),
    ],
)
def test_settings_fail_closed_on_invalid_limits(monkeypatch, name, value):
    monkeypatch.setenv("EDGE_NODE_ID", "edge-sg01")
    monkeypatch.setenv("EDGE_TICKET_SECRET", "x" * 32)
    monkeypatch.setenv(name, value)

    with pytest.raises(RuntimeError, match="invalid edge configuration"):
        Settings.from_env()


@pytest.mark.parametrize(
    ("node", "secret"), [("", "x" * 32), ("edge-sg01", "short"), ("bad/node", "x" * 32)]
)
def test_settings_reject_missing_or_unsafe_identity(monkeypatch, node, secret):
    monkeypatch.setenv("EDGE_NODE_ID", node)
    monkeypatch.setenv("EDGE_TICKET_SECRET", secret)

    with pytest.raises(RuntimeError):
        Settings.from_env()
