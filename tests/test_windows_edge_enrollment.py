from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi import HTTPException
from fastapi.testclient import TestClient

import cloudbrowser.app as app_module
from cloudbrowser.app import create_app
from cloudbrowser.models import EdgeNode, NodeRegistrationRequest
from cloudbrowser.runner import FakeBrowserRunner
from tests.test_node_registration import (
    admin_auth,
    claim_body,
    key_material,
    prove,
    register,
    registration_auth,
)

pytest_plugins = ["tests.test_node_registration"]

ROOT = Path(__file__).parents[1]


def test_registration_source_returns_trusted_global_ipv4(registration_system):
    response = registration_system.get("/api/node-registration-source")

    assert response.status_code == 200
    assert response.json() == {"public_ipv4": "8.8.8.8"}
    assert response.headers["cache-control"] == "no-store"


def test_xff_is_used_only_for_loopback_proxy_and_production_allowlist_is_explicit(tmp_path):
    app = create_app(
        database_url=f"sqlite:///{tmp_path / 'xff.db'}",
        secret_key="xff-topology-test-secret",
        runner=FakeBrowserRunner(),
    )
    with TestClient(app, client=("127.0.0.1", 50000)) as loopback:
        trusted = loopback.get(
            "/api/node-registration-source", headers={"X-Forwarded-For": "8.8.8.8"}
        )
    with TestClient(app, client=("8.8.4.4", 50000)) as direct:
        forged = direct.get(
            "/api/node-registration-source", headers={"X-Forwarded-For": "1.1.1.1"}
        )

    assert trusted.json() == {"public_ipv4": "8.8.8.8"}
    assert forged.json() == {"public_ipv4": "8.8.4.4"}
    service = (ROOT / "deploy/idengrid-control.service").read_text()
    launcher = (ROOT / "scripts/web_up.sh").read_text()
    assert "--forwarded-allow-ips 127.0.0.1" in service
    assert "--forwarded-allow-ips 127.0.0.1" in launcher


def test_admin_ui_displays_registration_and_node_platforms():
    source = (ROOT / "cloudbrowser/templates/index.html").read_text()
    assert "平台：${item.platform}" in source
    assert "平台：${node.platform}" in source


def _approved_windows_request(client):
    private, public_pem = key_material()
    response = register(
        client,
        public_pem,
        platform="windows",
        os_name="Windows Server 2025",
        reported_hostname="windows-edge",
    )
    assert response.status_code == 201, response.text
    created = response.json()
    assert prove(client, created, private).status_code == 200
    accepted = client.post(
        f"/api/admin/node-registration-requests/{created['request_id']}/accept",
        headers=admin_auth(client),
        json={
            "node_name": "edge-windows-01",
            "endpoint": "https://edge-windows-01.example.com",
            "expected_public_ipv4": "8.8.8.8",
        },
    )
    assert accepted.status_code == 200, accepted.text
    created["_private"] = private
    return created


def configure_signed_release(tmp_path: Path, monkeypatch, version: str = "1.2.3"):
    package = tmp_path / f"IdenGrid-Edge-Windows-Server-2025-x64-v{version}.zip"
    package.write_bytes(b"signed-versioned-package")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()
    manifest = tmp_path / "release-manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "package": {
                    "filename": package.name,
                    "sha256": digest,
                    "size": package.stat().st_size,
                    "version": version,
                },
            },
            separators=(",", ":"),
        ),
        encoding="ascii",
    )
    signature = tmp_path / "release-manifest.json.sig"
    signature.write_text("detached-signature-fixture\n", encoding="ascii")
    monkeypatch.setattr(app_module, "WINDOWS_EDGE_RELEASE_MANIFEST_PATH", manifest)
    monkeypatch.setattr(app_module, "WINDOWS_EDGE_RELEASE_SIGNATURE_PATH", signature)
    return package, digest, manifest, signature


def test_windows_signed_release_routes_and_security_headers(
    registration_system, tmp_path: Path, monkeypatch
):
    installer = tmp_path / "Install-IdenGridEdge.ps1"
    installer.write_text("Write-Output 'public example installer'\n")
    monkeypatch.setattr(app_module, "WINDOWS_EDGE_INSTALLER_PATH", installer)
    package, _, manifest, signature = configure_signed_release(tmp_path, monkeypatch)

    responses = [
        registration_system.get("/bootstrap/Install-IdenGridEdge.ps1"),
        registration_system.get("/edge-package/release-manifest.json"),
        registration_system.get("/edge-package/release-manifest.json.sig"),
        registration_system.get(f"/edge-package/{package.name}"),
    ]

    assert [response.status_code for response in responses] == [200, 200, 200, 200]
    assert responses[0].content == installer.read_bytes()
    assert responses[1].content == manifest.read_bytes()
    assert responses[2].content == signature.read_bytes()
    assert responses[3].content == package.read_bytes()
    for response in responses:
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-content-type-options"] == "nosniff"


def test_windows_release_routes_fail_closed_for_missing_or_mismatched_package(
    registration_system, tmp_path: Path, monkeypatch
):
    package, _, manifest, _ = configure_signed_release(tmp_path, monkeypatch)
    package.unlink()
    assert registration_system.get("/edge-package/release-manifest.json").status_code == 503

    package.write_bytes(b"tampered")
    assert registration_system.get(f"/edge-package/{package.name}").status_code == 503
    assert manifest.is_file()


def test_verified_edge_package_rejects_unknown_platform_explicitly():
    try:
        app_module.verified_edge_package("darwin")
    except HTTPException as exc:
        assert exc.status_code == 503
        assert exc.detail == "Edge package unavailable"
    else:
        raise AssertionError("unknown platform must fail closed")


def test_windows_claim_is_bound_to_approved_platform_and_signed_release(
    registration_system, tmp_path: Path, monkeypatch
):
    package, digest, _, _ = configure_signed_release(tmp_path, monkeypatch)
    created = _approved_windows_request(registration_system)
    response = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
        json={
            **claim_body(registration_system, created, created["_private"]),
            "platform": "linux",
        },
    )

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["package_url"].endswith(f"/edge-package/{package.name}")
    assert result["package_sha256"] == digest
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        node = db.get(EdgeNode, item.edge_node_id)
        assert item.platform == node.platform == "windows"


def test_windows_claim_fails_closed_without_signed_release(
    registration_system, tmp_path: Path, monkeypatch
):
    monkeypatch.setattr(
        app_module, "WINDOWS_EDGE_RELEASE_MANIFEST_PATH", tmp_path / "missing-manifest.json"
    )
    monkeypatch.setattr(
        app_module, "WINDOWS_EDGE_RELEASE_SIGNATURE_PATH", tmp_path / "missing-manifest.sig"
    )
    created = _approved_windows_request(registration_system)

    response = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
        json=claim_body(registration_system, created, created["_private"]),
    )

    assert response.status_code == 503
    assert "edge-tunnel.tar.gz" not in response.text
    with registration_system.app.state.db() as db:
        item = db.get(NodeRegistrationRequest, created["request_id"])
        assert item.status == "approved"
        assert item.registration_token_hash is not None


def test_install_reports_accept_legacy_caddy_and_platform_neutral_gateway_service(
    registration_system, tmp_path: Path, monkeypatch
):
    configure_signed_release(tmp_path, monkeypatch)
    created = _approved_windows_request(registration_system)
    claimed = registration_system.post(
        f"/api/node-registration-requests/{created['request_id']}/claim-approved",
        headers=registration_auth(created),
        json=claim_body(registration_system, created, created["_private"]),
    ).json()
    headers = {"Authorization": f"Report {claimed['report_token']}"}

    for phase in ("caddy", "gateway", "service"):
        response = registration_system.post(
            "/api/edge-enrollments/report", headers=headers, json={"phase": phase}
        )
        assert response.status_code == 200, (phase, response.text)
        assert response.json()["phase"] == phase
