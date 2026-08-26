from __future__ import annotations

import importlib.util
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from cloudbrowser.app import create_app
from cloudbrowser.runner import FakeBrowserRunner

MODULE_PATH = Path("cloudbrowser/local_tunnel.py")


def load_module():
    assert MODULE_PATH.exists(), "local HTTPS/WSS tunnel policy is missing"
    spec = importlib.util.spec_from_file_location("local_tunnel", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def resolver_with(*addresses: str):
    def resolve(host: str, port: int):
        del host
        return [
            (
                socket.AF_INET6 if ":" in address else socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                (address, port),
            )
            for address in addresses
        ]

    return resolve


def test_tunnel_accepts_only_public_http_targets() -> None:
    module = load_module()
    policy = module.PublicTargetPolicy(resolver=resolver_with("93.184.216.34"))

    target = policy.resolve("example.com", 443)

    assert target.host == "example.com"
    assert target.port == 443
    assert target.address == "93.184.216.34"


@pytest.mark.parametrize(
    "addresses",
    [
        ("127.0.0.1",),
        ("10.0.0.1",),
        ("169.254.169.254",),
        ("::1",),
        ("93.184.216.34", "10.0.0.1"),
    ],
)
def test_tunnel_rejects_private_or_mixed_dns_answers(addresses: tuple[str, ...]) -> None:
    module = load_module()
    policy = module.PublicTargetPolicy(resolver=resolver_with(*addresses))

    with pytest.raises(module.TunnelTargetDenied):
        policy.resolve("untrusted.example", 443)


def test_tunnel_rejects_non_web_ports() -> None:
    module = load_module()
    policy = module.PublicTargetPolicy(resolver=resolver_with("93.184.216.34"))

    with pytest.raises(module.TunnelTargetDenied):
        policy.resolve("example.com", 22)


def tunnel_test_app(tmp_path: Path):
    return create_app(
        database_url=f"sqlite:///{tmp_path / 'tunnel.db'}",
        secret_key="local-tunnel-test-secret-key-at-least-32-characters",
        runner=FakeBrowserRunner(),
        bootstrap_admin=("admin", "Admin-password-123"),
        secure_cookies=False,
        public_origin="https://cloud.example.test",
        local_environment={
            "environment_id": "sg-default-v1",
            "timezone": "Asia/Singapore",
            "locale": "en-SG",
            "accept_languages": ["en-SG", "en"],
            "expected_egress_ips": ["192.0.2.10"],
            "geolocation": "block",
            "quic": "disable",
        },
    )


def test_local_tunnel_requires_bearer_token(tmp_path: Path) -> None:
    with (
        TestClient(tunnel_test_app(tmp_path)) as client,
        pytest.raises(WebSocketDisconnect) as exc,
        client.websocket_connect("/api/local-tunnel") as websocket,
    ):
        websocket.receive_json()

    assert exc.value.code == 4401


def test_local_tunnel_authenticates_then_rejects_private_target(tmp_path: Path) -> None:
    with TestClient(tunnel_test_app(tmp_path)) as client:
        login = client.post(
            "/api/login", json={"username": "admin", "password": "Admin-password-123"}
        )
        token = login.json()["access_token"]
        with client.websocket_connect(
            "/api/local-tunnel", headers={"Authorization": f"Bearer {token}"}
        ) as websocket:
            websocket.send_json({"host": "127.0.0.1", "port": 443})
            response = websocket.receive_json()

    assert response == {"status": "error", "message": "target denied"}


def test_local_environment_policy_requires_login_and_returns_sg_defaults(tmp_path: Path) -> None:
    with TestClient(tunnel_test_app(tmp_path)) as client:
        denied = client.get("/api/local-browser/environment")
        login = client.post(
            "/api/login", json={"username": "admin", "password": "Admin-password-123"}
        )
        token = login.json()["access_token"]
        response = client.get(
            "/api/local-browser/environment",
            headers={"Authorization": f"Bearer {token}"},
        )

    assert denied.status_code == 401
    assert response.status_code == 200
    assert response.json() == {
        "environment_id": "sg-default-v1",
        "timezone": "Asia/Singapore",
        "locale": "en-SG",
        "accept_languages": ["en-SG", "en"],
        "expected_egress_ips": ["192.0.2.10"],
        "geolocation": "block",
        "quic": "disable",
    }
    serialized = response.text.lower()
    assert "password" not in serialized
    assert "127.0.0.1" not in serialized


def test_history_and_tabs_merge_across_devices_without_overwriting_snapshots(
    tmp_path: Path,
) -> None:
    with TestClient(tunnel_test_app(tmp_path)) as client:
        login = client.post(
            "/api/login", json={"username": "admin", "password": "Admin-password-123"}
        )
        headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        first = client.post(
            "/api/local-browser/sync",
            headers=headers,
            json={
                "device_id": "macbook-a",
                "history": [
                    {
                        "url": "https://example.com/a",
                        "title": "Old title",
                        "last_visit_ms": 1000,
                        "visit_count": 2,
                    }
                ],
                "tabs": [{"url": "https://example.com/a", "title": "A"}],
            },
        )
        second = client.post(
            "/api/local-browser/sync",
            headers=headers,
            json={
                "device_id": "macbook-b",
                "history": [
                    {
                        "url": "https://example.com/a",
                        "title": "New title",
                        "last_visit_ms": 2000,
                        "visit_count": 3,
                    },
                    {
                        "url": "https://example.com/b",
                        "title": "B",
                        "last_visit_ms": 1500,
                        "visit_count": 1,
                    },
                ],
                "tabs": [{"url": "https://example.com/b", "title": "B"}],
            },
        )

    assert first.status_code == 200
    assert second.status_code == 200
    data = second.json()
    assert data["history"] == [
        {
            "url": "https://example.com/a",
            "title": "New title",
            "last_visit_ms": 2000,
            "visit_count": 3,
        },
        {
            "url": "https://example.com/b",
            "title": "B",
            "last_visit_ms": 1500,
            "visit_count": 1,
        },
    ]
    assert data["tabs_by_device"] == {
        "macbook-a": [{"url": "https://example.com/a", "title": "A"}],
        "macbook-b": [{"url": "https://example.com/b", "title": "B"}],
    }
