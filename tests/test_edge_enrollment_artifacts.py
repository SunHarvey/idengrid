from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_package_build_is_deterministic_and_checksum_matches(tmp_path):
    script = ROOT / "scripts" / "build_edge_package.py"
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"
    subprocess.run(
        [str(ROOT / ".venv/bin/python"), str(script), "--output", str(first)], check=True
    )
    subprocess.run(
        [str(ROOT / ".venv/bin/python"), str(script), "--output", str(second)], check=True
    )
    assert first.read_bytes() == second.read_bytes()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    assert first.with_suffix(first.suffix + ".sha256").read_text().split()[0] == digest
    assert b"EDGE_TICKET_SECRET=" not in first.read_bytes()


def test_installer_has_safe_dry_run_and_never_echoes_secrets():
    installer = ROOT / "scripts" / "install-edge.sh"
    subprocess.run(["bash", "-n", str(installer)], check=True)
    token = "id.one-time-super-secret"
    result = subprocess.run(
        [
            "bash",
            str(installer),
            "--dry-run",
            "--server",
            "https://central.example",
            "--node-name",
            "edge-test",
            "--token",
            token,
            "--public-ip",
            "8.8.8.8",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    output = result.stdout + result.stderr
    assert "dry-run" in output.lower()
    assert token not in output
    assert "one-time-super-secret" not in output
    source = installer.read_text()
    assert "curl | bash" not in source
    assert "EDGE_TICKET_SECRET" in source
    assert "chmod 0600" in source or "install -m 0600" in source
    assert "sha256sum -c" in source
    assert "trap '" in source
    assert "--remove-service=cockpit" in source
    assert "PasswordAuthentication no" in source
    assert "PermitRootLogin prohibit-password" in source
    assert "SystemMaxUse=100M" in source
    for phase in (
        "installing",
        "dependencies",
        "configuring",
        "caddy",
        "starting",
        "ready",
        "failed",
    ):
        assert phase in source


def test_generic_installer_is_tokenless_signed_and_safe_in_dry_run():
    installer = ROOT / "scripts" / "edge-install.sh"
    subprocess.run(["bash", "-n", str(installer)], check=True)
    result = subprocess.run(
        [
            "bash",
            str(installer),
            "--dry-run",
            "--server",
            "https://central.example",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    output = result.stdout + result.stderr
    assert "dry-run" in output.lower()
    assert "PRIVATE KEY" not in output
    source = installer.read_text()
    assert "--token" not in source
    assert "node-registration-requests" in source
    assert "openssl genpkey -algorithm ED25519" in source
    assert "chmod 0600" in source or "install -m 0600" in source
    assert "openssl pkeyutl -sign -rawin" in source
    assert "hermes-node-registration-v1" in source
    assert "claim-approved" in source
    assert "sha256sum -c" in source
    assert "POLL_TIMEOUT_SECONDS=${POLL_TIMEOUT_SECONDS:-7200}" in source
    assert "--install-admin-ssh-key" in source
    assert "/bootstrap/admin-ssh.pub" in source
    assert "authorized_keys" in source
    assert "install -d -m 0700" in source
    assert "chmod 0600" in source
    assert "INSTALL_ADMIN_SSH_KEY=0" in source


def test_node_installers_brand_visible_completion_output_only():
    legacy_installer = (ROOT / "scripts" / "install-edge.sh").read_text()
    generic_installer = (ROOT / "scripts" / "edge-install.sh").read_text()

    assert "IdenGrid Edge enrollment completed." in legacy_installer
    assert "IdenGrid Edge installation completed." in generic_installer
    assert "edge-tunnel@$NODE_NAME.service" in legacy_installer
    assert "edge-tunnel@$NODE_NAME.service" in generic_installer
