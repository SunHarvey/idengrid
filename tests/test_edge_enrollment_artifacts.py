from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]


def load_windows_package_builder():
    path = ROOT / "scripts" / "build_windows_edge_package.py"
    spec = importlib.util.spec_from_file_location("windows_package_builder", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


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
    assert '"platform":"linux"' in source
    assert "openssl genpkey -algorithm ED25519" in source
    assert "chmod 0600" in source or "install -m 0600" in source
    assert "openssl pkeyutl -sign -rawin" in source
    assert "hermes-node-registration-v1" in source
    assert "hermes-node-claim-v1" in source
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


def test_windows_package_build_is_allowlisted_reproducible_and_secret_free(tmp_path):
    builder = load_windows_package_builder()
    source = tmp_path / "staging"
    runtime_files = {
        "runtime/python.exe": b"python-runtime",
        "runtime/_ssl.pyd": b"ssl-extension",
        "runtime/libcrypto-3.dll": b"crypto-runtime",
    }
    files = {relative: (relative + "\n").encode() for relative in builder.ALLOWED_FILES}
    files.update(runtime_files)
    for relative, data in files.items():
        path = source / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    expected = tmp_path / "runtime-expected.json"
    expected.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "files": [
                    {"path": path, "sha256": hashlib.sha256(data).hexdigest()}
                    for path, data in sorted(runtime_files.items())
                ],
            }
        ),
        encoding="utf-8",
    )
    script = ROOT / "scripts" / "build_windows_edge_package.py"
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    for output in (first, second):
        subprocess.run(
            [
                str(ROOT / ".venv/bin/python"),
                str(script),
                "--source",
                str(source),
                "--output",
                str(output),
                "--expected-runtime-manifest",
                str(expected),
            ],
            check=True,
        )

    assert first.read_bytes() == second.read_bytes()
    digest = hashlib.sha256(first.read_bytes()).hexdigest()
    assert first.with_suffix(".zip.sha256").read_text().split()[0] == digest
    with zipfile.ZipFile(first) as archive:
        assert archive.namelist() == sorted(files)
        assert all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in archive.infolist())
        assert not any(b"PRIVATE KEY" in archive.read(name) for name in archive.namelist())


def test_windows_package_build_rejects_non_allowlisted_or_secret_files(tmp_path):
    source = tmp_path / "unsafe"
    (source / "runtime").mkdir(parents=True)
    (source / "runtime/python.exe").write_bytes(b"runtime")
    (source / ".env").write_text("EDGE_TICKET_SECRET=production-value\n")
    result = subprocess.run(
        [
            str(ROOT / ".venv/bin/python"),
            str(ROOT / "scripts" / "build_windows_edge_package.py"),
            "--source",
            str(source),
            "--output",
            str(tmp_path / "unsafe.zip"),
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "production-value" not in result.stdout + result.stderr


def test_windows_package_build_rejects_unknown_files_inside_allowed_roots(tmp_path):
    script = ROOT / "scripts" / "build_windows_edge_package.py"
    for relative in (
        "runtime/credentials.txt",
        "runtime/Lib/site-packages/credentials.py",
        "app/edge_tunnel/debug.log",
        "scripts/Unexpected.ps1",
        "gateway/helper.exe",
    ):
        source = tmp_path / relative.replace("/", "-")
        (source / "runtime").mkdir(parents=True)
        (source / "runtime/python.exe").write_bytes(b"runtime")
        unexpected = source / relative
        unexpected.parent.mkdir(parents=True, exist_ok=True)
        unexpected.write_bytes(b"not approved")
        result = subprocess.run(
            [
                str(ROOT / ".venv/bin/python"),
                str(script),
                "--source",
                str(source),
                "--output",
                str(tmp_path / f"{source.name}.zip"),
            ],
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0, relative


def test_windows_package_build_rejects_allowlist_prefix_and_dll_probes(tmp_path):
    script = ROOT / "scripts" / "build_windows_edge_package.py"
    for relative in (
        "runtime/Lib/site-packages/aiohttp-3.14.3.dist-infoEVIL/payload.py",
        "runtime/DLLs/unexpected_payload.pyd",
        "runtime/Lib/site-packages/aiohttp/unexpected_payload.pyd",
    ):
        source = tmp_path / relative.replace("/", "-")
        (source / "runtime").mkdir(parents=True)
        (source / "runtime/python.exe").write_bytes(b"runtime")
        probe = source / relative
        probe.parent.mkdir(parents=True, exist_ok=True)
        probe.write_bytes(b"probe")
        result = subprocess.run(
            [str(ROOT / ".venv/bin/python"), str(script), "--source", str(source),
             "--output", str(tmp_path / f"{source.name}.zip")],
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0, relative


def test_formal_windows_builder_uses_shared_validator_and_versioned_artifact_name():
    source = (ROOT / "windows-edge/scripts/Build-WindowsEdge.ps1").read_text()

    assert "build_windows_edge_package.py" in source
    assert 'IdenGrid-Edge-Windows-Server-2025-x64-v$Version.zip' in source
    assert "release-manifest.json" not in source  # signing is an isolated post-build step


def test_windows_package_runtime_allowlist_rejects_injected_python_at_manifest_stage(tmp_path):
    builder = load_windows_package_builder()
    source = tmp_path / "stage"
    injected = source / "runtime/Lib/site-packages/aiohttp/injected_backdoor.py"
    injected.parent.mkdir(parents=True)
    injected.write_bytes(b"raise SystemExit('backdoor')\n")
    expected = tmp_path / "runtime-expected.json"
    expected.write_text(json.dumps({"schema_version": 1, "files": []}), encoding="utf-8")

    with pytest.raises(builder.PackageBuildError, match="runtime file set"):
        builder.collect_files(source, expected)


def test_windows_package_requires_complete_exact_stage(tmp_path):
    builder = load_windows_package_builder()
    source = tmp_path / "stage"
    source.mkdir()
    (source / "manifest.json").write_text('{"schema_version":1}\n', encoding="ascii")
    expected = tmp_path / "runtime-expected.json"
    expected.write_text(json.dumps({"schema_version": 1, "files": []}), encoding="utf-8")

    with pytest.raises(builder.PackageBuildError, match="package file set"):
        builder.collect_files(source, expected)
