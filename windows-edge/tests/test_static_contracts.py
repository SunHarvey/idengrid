#!/usr/bin/env python3
"""Linux fallback contract tests for the Windows PowerShell package."""

from __future__ import annotations

import base64
import importlib.util
import json
import re
import subprocess
import tempfile
import tomllib
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROJECT_ROOT = ROOT.parent


class WindowsEdgeContracts(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_required_surface_exists(self) -> None:
        required = [
            "README.md",
            "manifests/windows-x64-runtime.schema.json",
            "manifests/windows-x64-runtime.json",
            "manifests/windows-x64-runtime.example.json",
            "scripts/Build-WindowsEdge.ps1",
            "scripts/Install-IdenGridEdge.ps1",
            "scripts/Upgrade-IdenGridEdge.ps1",
            "scripts/Uninstall-IdenGridEdge.ps1",
            "scripts/Get-IdenGridEdgeStatus.ps1",
            "tools/sign_release_manifest.py",
            "bootstrap/register.py",
            "service/IdenGridEdgeService.xml",
            "service/IdenGridEdgeGateway.xml",
            "templates/Caddyfile.template",
            "templates/edge.json.example",
            "tests/Static.Tests.ps1",
        ]
        self.assertEqual([], [path for path in required if not (ROOT / path).is_file()])

    def test_runtime_manifest_is_pinned_and_https_only(self) -> None:
        manifest = json.loads(self.text("manifests/windows-x64-runtime.example.json"))
        self.assertEqual(manifest, json.loads(self.text("manifests/windows-x64-runtime.json")))
        self.assertEqual(1, manifest["schema_version"])
        self.assertEqual("windows", manifest["platform"])
        self.assertEqual("x86_64", manifest["architecture"])
        artifacts = manifest["artifacts"]
        self.assertGreaterEqual(len(artifacts), 8)
        for artifact in artifacts:
            self.assertRegex(artifact["url"], r"^https://")
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("example.com", artifact["url"])
        self.assertIn("cpython", {item["kind"] for item in artifacts})
        self.assertIn("caddy", {item["kind"] for item in artifacts})
        self.assertIn("winsw", {item["kind"] for item in artifacts})
        self.assertIn("psutil", {item["name"] for item in artifacts})
        self.assertIn("aiohttp", {item["name"] for item in artifacts})
        self.assertIn("cryptography", {item["name"] for item in artifacts})
        self.assertIn("cffi", {item["name"] for item in artifacts})
        self.assertIn("pycparser", {item["name"] for item in artifacts})
        self.assertEqual(len(artifacts), len({item["name"] for item in artifacts}))
        self.assertEqual(len(artifacts), len({item["filename"] for item in artifacts}))

    def test_runtime_manifest_matches_edge_platform_dependencies(self) -> None:
        project = tomllib.loads((PROJECT_ROOT / "edge-tunnel/pyproject.toml").read_text())
        dependencies = project["project"]["dependencies"]
        psutil_dependency = next(item for item in dependencies if item.startswith("psutil=="))
        expected_version = psutil_dependency.split("==", 1)[1].split(";", 1)[0].strip()
        manifest = json.loads(self.text("manifests/windows-x64-runtime.json"))
        actual_version = next(
            item["version"] for item in manifest["artifacts"] if item["name"] == "psutil"
        )
        self.assertEqual(expected_version, actual_version)

    def test_control_plane_serves_checked_in_windows_installer(self) -> None:
        app = (PROJECT_ROOT / "cloudbrowser/app.py").read_text()
        self.assertIn(
            'WINDOWS_EDGE_INSTALLER_PATH = Path("/data/windows-edge/scripts/Install-IdenGridEdge.ps1")',
            app,
        )

    def test_services_are_low_privilege_and_secret_free(self) -> None:
        edge_text = self.text("service/IdenGridEdgeService.xml")
        gateway_text = self.text("service/IdenGridEdgeGateway.xml")
        edge = ET.fromstring(edge_text)
        gateway = ET.fromstring(gateway_text)
        self.assertEqual(
            "NT AUTHORITY\\LocalService",
            edge.findtext("serviceaccount/domain") + "\\" + edge.findtext("serviceaccount/user"),
        )
        self.assertEqual(
            "NT AUTHORITY\\NetworkService",
            gateway.findtext("serviceaccount/domain")
            + "\\"
            + gateway.findtext("serviceaccount/user"),
        )
        self.assertIn("--config", edge.findtext("arguments", ""))
        self.assertIn("--port 8787", edge.findtext("arguments", ""))
        self.assertNotIn("ticket_secret", (edge_text + gateway_text).lower())
        self.assertNotIn("%EDGE_", edge_text)
        gateway_env = {item.attrib["name"]: item.attrib["value"] for item in gateway.findall("env")}
        self.assertIn("XDG_DATA_HOME", gateway_env)
        self.assertIn("ProgramData", gateway_env["XDG_DATA_HOME"])

    def test_gateway_is_loopback_only_and_access_log_is_disabled(self) -> None:
        caddy = self.text("templates/Caddyfile.template")
        self.assertIn("127.0.0.1:8787", caddy)
        self.assertNotRegex(caddy, r"(?m)^\s*log\s*\{")
        self.assertRegex(caddy, r"(?m)^\s*-Server\s*$")
        self.assertIn("Strict-Transport-Security", caddy)

    def test_lifecycle_security_contracts(self) -> None:
        install = self.text("scripts/Install-IdenGridEdge.ps1")
        upgrade = self.text("scripts/Upgrade-IdenGridEdge.ps1")
        uninstall = self.text("scripts/Uninstall-IdenGridEdge.ps1")
        build = self.text("scripts/Build-WindowsEdge.ps1")
        combined = install + upgrade + build
        self.assertIn("New-NetFirewallRule", install)
        self.assertIn("IdenGrid Edge HTTP", install)
        self.assertIn("IdenGrid Edge HTTPS", install)
        self.assertNotRegex(install, r"LocalPort\s+8787")
        self.assertIn("New-Item -ItemType Junction", install + upgrade)
        self.assertIn("function Invoke-Icacls", install)
        self.assertIn("function Expand-VerifiedBundle", install)
        self.assertIn("function Invoke-InstallRollback", install)
        self.assertIn("Remove-NetFirewallRule", install)
        self.assertIn("$gatewayWrapper uninstall", install)
        self.assertIn("$edgeWrapper uninstall", install)
        self.assertIn("$programDataExisted", install)
        self.assertIn("GetFullPath", install)
        self.assertIn("function Expand-VerifiedBundle", upgrade)
        self.assertIn("GetFullPath", upgrade)
        self.assertIn("Wait-PublicHealth", install)
        self.assertRegex(upgrade, r"(?i)rollback")
        self.assertIn("$oldMoved", upgrade)
        self.assertIn("Wait-PublicHealth", upgrade)
        self.assertRegex(upgrade, r"(?i)sha256")
        self.assertIn("PurgeData", uninstall)
        purge_guard = uninstall.index("if ($PurgeData)")
        data_delete = uninstall.index("Remove-Item -LiteralPath $ProgramDataRoot")
        self.assertGreater(data_delete, purge_guard)
        self.assertEqual(1, uninstall.count("ShouldProcess("))
        self.assertRegex(combined, r"(?i)https")
        self.assertRegex(combined, r"(?i)Get-FileHash[^\r\n]*SHA256")
        self.assertNotRegex(combined, r"(?i)Invoke-Expression|\biex\b")
        status = self.text("scripts/Get-IdenGridEdgeStatus.ps1")
        self.assertIn("config_acl", status)
        self.assertIn("certificate_earliest_expiry", status)
        self.assertIn("$edgeListeners.Count -gt 0", status)

    def test_formal_installer_bootstrap_contract(self) -> None:
        install = self.text("scripts/Install-IdenGridEdge.ps1")
        self.assertRegex(install, r"ParameterSetName='Server'")
        self.assertRegex(install, r"ParameterSetName='LabConfig'")
        self.assertRegex(install, r"\[string\]\$Server")
        self.assertRegex(install, r"\[string\]\$PackageUrl")
        self.assertIn("release-manifest.json", install)
        self.assertIn("release-manifest.json.sig", install)
        self.assertIn("Test-Ed25519Signature", install)
        self.assertIn("Wf/s6zRs0+FjSCqM1BQb5vXIpyv4Ivxm5nAS2wWZGxk=", install)
        self.assertNotIn("REPLACE_WITH_PRODUCTION", install)
        self.assertIn("bootstrap\\register.py", install)
        self.assertIn("package_sha256", install)
        self.assertIn("Assert-Sha256 $bundle $claimPackageSha256", install)
        self.assertIn("Remove-Variable claimJson", install)
        self.assertIn("throw ('Installation failed: ' + $normalized)", install)
        self.assertNotIn("$_.Exception.Message", install)
        self.assertNotRegex(install, r"(?i)\$env:.*(?:token|secret)|--(?:token|secret|private-key)")
        for phase in ("gateway", "service", "ready"):
            self.assertIn("Report-InstallPhase '" + phase + "'", install)

    def test_strict_bundle_manifest_contract(self) -> None:
        for name in ("Install-IdenGridEdge.ps1", "Upgrade-IdenGridEdge.ps1"):
            text = self.text("scripts/" + name)
            for contract in (
                "Bundle contains an unlisted file",
                "Bundle manifest contains a duplicate path",
                "Bundle path contains an NTFS alternate data stream",
                "Bundle manifest file size is invalid",
                "Bundle manifest file SHA256 is malformed",
                "Bundle is missing a required file",
                "Bundle version does not match the requested version",
            ):
                self.assertIn(contract, text, name)
            self.assertIn("OrdinalIgnoreCase", text)

    def test_build_hardening_contract(self) -> None:
        build = self.text("scripts/Build-WindowsEdge.ps1")
        self.assertIn("function Assert-RuntimeManifestSchema", build)
        self.assertIn("runtime manifest schema validation failed", build)
        self.assertIn("GetFileName($artifact.filename)", build)
        self.assertIn("ResponseUri.Scheme", build)
        self.assertIn("function Expand-SafeZip", build)
        self.assertNotIn("ExtractToDirectory", build)
        self.assertIn("$ApprovedRuntimeManifestSha256", build)
        self.assertIn("Runtime manifest is not on the production allowlist", build)
        parameter_block = build.split("Set-StrictMode", 1)[0]
        self.assertNotIn("$PSScriptRoot", parameter_block)
        self.assertIn("$MyInvocation.MyCommand.Path", build)

    def test_firewall_uninstall_and_transaction_contracts(self) -> None:
        install = self.text("scripts/Install-IdenGridEdge.ps1")
        uninstall = self.text("scripts/Uninstall-IdenGridEdge.ps1")
        self.assertIn("IdenGrid Edge Managed Rules", install)
        self.assertIn("Managed exclusively by IdenGrid Edge", install)
        self.assertIn("Assert-FirewallRule", install)
        self.assertIn("install-state.json", uninstall)
        self.assertIn("firewall_rules", install)
        self.assertIn("Assert-FirewallRuleMatchesState", uninstall)
        self.assertIn("Assert-AllowedRoot", uninstall)
        self.assertNotRegex(uninstall, r"\[string\]\$Program(?:Data)?Root")
        self.assertEqual(1, uninstall.count("ShouldProcess("))
        self.assertIn("if ($LASTEXITCODE -ne 0)", uninstall)
        self.assertIn("programDataBackup", install)
        self.assertIn("Restore-ProgramDataBackup", install)
        self.assertIn("robocopy.exe", install)
        self.assertIn("Assert-ServiceNamesAvailable", install)
        self.assertIn("ImagePath", install)

    def test_config_owner_and_claim_closed_shape_match_runtime(self) -> None:
        install = self.text("scripts/Install-IdenGridEdge.ps1")
        self.assertGreaterEqual(install.count("/setowner','*S-1-5-18'"), 2)
        self.assertIn("Assert-ExactConfigAcl", install)
        self.assertIn("$Claim.PSObject.Properties.Name", install)
        self.assertIn("$Claim.resources.PSObject.Properties.Name", install)
        self.assertIn("$Claim.node_name.Length -gt 64", install)
        for value in ("65535", "67108864", "1099511627776", "300"):
            self.assertIn(value, install)

    def test_upgrade_uses_signed_server_release_and_safe_junctions(self) -> None:
        upgrade = self.text("scripts/Upgrade-IdenGridEdge.ps1")
        self.assertRegex(upgrade, r"ParameterSetName='Server'.*\[string\]\$Server")
        self.assertNotIn("PackageUrl", upgrade)
        self.assertIn("ParameterSetName='LabConfig'", upgrade)
        self.assertIn("Read-StrictReleaseManifest", upgrade)
        self.assertIn("RequestUri.Scheme -ne 'https'", upgrade)
        self.assertIn("Compare-SemanticVersion", upgrade)
        self.assertIn("Refusing version downgrade", upgrade)
        self.assertIn("Assert-ManagedVersionJunction", upgrade)
        self.assertGreaterEqual(upgrade.count("Assert-BundleManifest"), 3)

    def test_release_public_key_and_rfc8032_contract(self) -> None:
        install = self.text("scripts/Install-IdenGridEdge.ps1")
        upgrade = self.text("scripts/Upgrade-IdenGridEdge.ps1")
        app = (PROJECT_ROOT / "cloudbrowser/app.py").read_text()
        key = "Wf/s6zRs0+FjSCqM1BQb5vXIpyv4Ivxm5nAS2wWZGxk="  # gitleaks:allow
        self.assertIn(key, install)
        self.assertIn(key, upgrade)
        self.assertIn(key, app)
        self.assertIn("d75a980182b10ab7d54bfed3c964073a", install)
        self.assertIn("e5564300c360ac729086e2cc806e828a", install)

    def test_upgrade_rollback_contracts(self) -> None:
        upgrade = self.text("scripts/Upgrade-IdenGridEdge.ps1")
        self.assertIn("$bundleManifest.version -ne $Version", upgrade)
        self.assertIn("Remove-Item -LiteralPath $newTarget -Recurse -Force", upgrade)
        self.assertIn("Wait-PublicHealth $publicHostname", upgrade[upgrade.index("catch {"):])
        self.assertIn("$previousBackup", upgrade)
        self.assertIn("$stateOriginal", upgrade)
        self.assertIn("WriteAllBytes($statePath,$stateOriginal)", upgrade)

    def test_claim_has_secondary_type_and_length_validation(self) -> None:
        install = self.text("scripts/Install-IdenGridEdge.ps1")
        self.assertIn("function Assert-Claim", install)
        self.assertIn("Claim response exceeds 65536 bytes", install)
        for field in ("node_name", "edge_ticket_secret", "domain", "report_token", "resources"):
            self.assertIn(field, install)

    def test_release_manifest_signing_tool_and_format(self) -> None:
        tool = ROOT / "tools/sign_release_manifest.py"
        self.assertNotIn("--private-key-base64", tool.read_text())
        self.assertIn("--private-key-file", tool.read_text())
        seed = bytes(range(32))
        with tempfile.TemporaryDirectory() as td:
            package = Path(td) / "IdenGrid-Edge-Windows-Server-2025-x64-v1.2.3.zip"
            package.write_bytes(b"signed package fixture")
            manifest = Path(td) / "release-manifest.json"
            signature = Path(td) / "release-manifest.json.sig"
            key_file = Path(td) / "release-key.bin"
            key_file.write_bytes(seed)
            key_file.chmod(0o600)
            result = subprocess.run(
                ["python3", str(tool), "--package", str(package), "--version", "1.2.3",
                 "--private-key-file", str(key_file),
                 "--manifest", str(manifest), "--signature", str(signature)],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            document = json.loads(manifest.read_text(encoding="ascii"))
            self.assertEqual(1, document["schema_version"])
            self.assertEqual(package.name, document["package"]["filename"])
            self.assertRegex(document["package"]["sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(package.stat().st_size, document["package"]["size"])
            self.assertEqual("1.2.3", document["package"]["version"])
            self.assertEqual(64, len(base64.b64decode(signature.read_text(encoding="ascii"))))

            verify = subprocess.run(
                ["python3", str(tool), "--verify", "--manifest", str(manifest),
                 "--signature", str(signature), "--public-key-base64", result.stdout.strip()],
                text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, verify.returncode, verify.stderr)
            document["package"]["size"] += 1
            manifest.write_text(json.dumps(document), encoding="ascii")
            rejected = subprocess.run(
                ["python3", str(tool), "--verify", "--manifest", str(manifest),
                 "--signature", str(signature), "--public-key-base64", result.stdout.strip()],
                text=True, capture_output=True, check=False,
            )
            self.assertNotEqual(0, rejected.returncode)

    def test_release_manifest_rejects_malicious_shapes(self) -> None:
        path = ROOT / "tools/sign_release_manifest.py"
        spec = importlib.util.spec_from_file_location("release_signer", path)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        valid = {"schema_version": 1, "package": {"filename": "IdenGrid-Edge-Windows-Server-2025-x64-v1.2.3.zip", "sha256": "a" * 64, "size": 1, "version": "1.2.3"}}
        attacks = [
            {**valid, "unexpected": True},
            {**valid, "schema_version": "1"},
            {**valid, "package": {**valid["package"], "filename": "../edge.zip"}},
            {**valid, "package": {**valid["package"], "filename": "C:edge.zip"}},
            {**valid, "package": {**valid["package"], "sha256": "A" * 64}},
            {**valid, "package": {**valid["package"], "size": -1}},
            {**valid, "package": {**valid["package"], "size": 1.0}},
            {**valid, "package": {**valid["package"], "version": "1.2.4"}},
        ]
        for attack in attacks:
            with self.subTest(attack=attack), self.assertRaises(ValueError):
                module.validate_manifest(json.dumps(attack).encode("ascii"))

    def test_powershell_contains_malicious_bundle_guards(self) -> None:
        combined = self.text("scripts/Install-IdenGridEdge.ps1") + self.text("scripts/Upgrade-IdenGridEdge.ps1")
        for guard in ("Contains(':')", "StartsWith('/')", "IsPathRooted", "TrimEnd('/')", "manifest.json", "OrdinalIgnoreCase"):
            self.assertIn(guard, combined)

    def test_scripts_target_windows_powershell_51(self) -> None:
        for script in (ROOT / "scripts").glob("*.ps1"):
            text = script.read_text(encoding="utf-8")
            self.assertIn("#requires -Version 5.1", text, script.name)
            for forbidden in (
                "ForEach-Object -Parallel",
                "ConvertFrom-Json -AsHashtable",
                "$IsWindows",
                "??",
            ):
                self.assertNotIn(forbidden, text, script.name)

    def test_examples_have_no_production_values_or_secrets(self) -> None:
        text_suffixes = {".md", ".json", ".ps1", ".xml", ".template"}
        text_files = [
            path
            for path in ROOT.rglob("*")
            if path.is_file()
            and path.suffix.lower() in text_suffixes
            and "__pycache__" not in path.parts
        ]
        all_text = "\n".join(path.read_text(encoding="utf-8") for path in text_files)
        self.assertNotRegex(
            all_text, r"(?i)ticket_secret\"\s*:\s*\"(?!REPLACE_WITH_|\[REDACTED\])[^\"]+"
        )
        addresses = set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", all_text))
        self.assertLessEqual(addresses, {"127.0.0.1"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
