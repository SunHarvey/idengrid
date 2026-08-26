# IdenGrid Edge for Windows Server 2025 (x64)

This directory is the packaging and lifecycle framework for a **headless, self-contained** Windows Edge. It adds no GUI and does not modify `edge-tunnel` or `cloudbrowser`.

## Security and operating model

- Target: Windows Server 2025 x64 (build 26100 or newer).
- The target server needs no Python, pip, PowerShell 7, Rust, Node, or build tools.
- Edge runs as `NT AUTHORITY\LocalService`; Caddy runs separately as `NT AUTHORITY\NetworkService`.
- Edge listens only on `127.0.0.1:8787`. Only the named inbound firewall rules `IdenGrid Edge HTTP` (80/TCP) and `IdenGrid Edge HTTPS` (443/TCP) are created.
- The Node Secret is read only from `C:\ProgramData\IdenGrid\Edge\config\edge.json`. It is never accepted as a script parameter and never appears in service arguments, environment variables, XML, or normal logs.
- Caddy access logging is disabled by omission. WinSW stdout/stderr logs are bounded and old logs are compressed.
- Every network download is HTTPS (including its final redirect target) and is accepted only after SHA-256 verification. Formal installs additionally require a detached Ed25519 signature rooted in the public key embedded in the installer.

No production hostname, address, credential, token, or certificate is stored in this tree.

## Layout

```text
C:\Program Files\IdenGrid Edge\
  current -> versions\X.Y.Z       (directory junction)
  previous -> versions\W.X.Y      (upgrade rollback junction)
  versions\X.Y.Z\runtime|app|gateway|service|scripts|templates
C:\ProgramData\IdenGrid\Edge\
  config\edge.json
  caddy\Caddyfile|data|config
  logs\edge|gateway
  registration
  state\install-state.json
```

Versions are immutable. Configuration, logs, and ACME state are outside the version tree and survive upgrades. Uninstall preserves ProgramData unless `-PurgeData` is explicitly supplied and confirmed.

## Runtime manifest

`manifests/windows-x64-runtime.schema.json` defines the closed manifest shape. `windows-x64-runtime.json` is the build input and `windows-x64-runtime.example.json` is its reviewable example. Both pin CPython 3.11, all offline wheels, Caddy, and WinSW. Hashes were calculated from the referenced upstream HTTPS artifacts; review and refresh them deliberately when versions change.

The build machine is the only machine that downloads individual runtime dependencies. The target downloads only the final ZIP plus a small detached signed release manifest. A same-origin SHA sidecar is reproducibility metadata, not the formal install trust root.

## Build (Windows PowerShell 5.1)

From an x64 Windows build host with network access:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows-edge\scripts\Build-WindowsEdge.ps1 -Version 1.0.0
```

The builder verifies every download, expands wheels without pip, configures the embeddable runtime path, runs isolated import/CLI checks, emits a per-file `manifest.json`, and creates:

```text
windows-edge\dist\IdenGrid-Edge-Windows-Server-2025-x64.zip
windows-edge\dist\IdenGrid-Edge-Windows-Server-2025-x64.zip.sha256
```

The ZIP writer sorts paths and fixes entry timestamps for reproducibility. Build twice from the same clean commit and compare SHA-256 values.

The production builder accepts only the checked-in runtime manifest digest embedded in `Build-WindowsEdge.ps1`; changing dependencies requires an explicit review and allowlist update. It validates the runtime schema, safe artifact basenames, final HTTPS redirect target, and every ZIP entry. After building, a release operator signs the exact canonical release manifest with an offline raw 32-byte Ed25519 private-key file:

```powershell
python windows-edge\tools\sign_release_manifest.py `
  --package windows-edge\dist\IdenGrid-Edge-Windows-Server-2025-x64-v1.0.0.zip `
  --version 1.0.0 --private-key-file C:\Secure\idengrid-edge-release.key `
  --manifest windows-edge\dist\release-manifest.json `
  --signature windows-edge\dist\release-manifest.json.sig
```

Never commit the private-key file. Keep it outside the repository with restrictive ACLs and use an isolated signing runner. Replace the installer's `REPLACE_WITH_PRODUCTION_ED25519_PUBLIC_KEY` placeholder during release engineering. The placeholder deliberately fails closed.

> Integration prerequisite: the packaged `edge_tunnel` CLI must implement the planned Windows `--config` protected-file entry point before service runtime acceptance. This branch intentionally does not alter the core.

## Provision config without exposing the secret

Create `edge.json` through a protected provisioning channel, based on `templates/edge.json.example`. Do not put its content in a command line, environment variable, transcript, or ticket. The installer accepts only the **path** to this already-protected temporary file, copies it, applies an inheritance-disabled ACL for SYSTEM and LocalService, and deletes only its own non-secret working directory. The provisioning system remains responsible for securely deleting its source file.

## Install

Run elevated Windows PowerShell 5.1. For the formal approval flow, the target operator supplies only the control-plane HTTPS origin:

```powershell
.\Install-IdenGridEdge.ps1 -Server 'https://control-plane.invalid'
```

The installer first downloads `release-manifest.json` and its detached signature, verifies the raw manifest with its embedded Ed25519 release public key, and only then downloads and opens the named ZIP. It verifies signed filename, size, version, and SHA-256 before extracting or running the bundled registration helper. It then waits for administrator approval and requires the claimed package SHA to match the signed digest. The `.invalid` origin is documentation-only.

For isolated experiments, retain the explicit `-LabConfig` path. Obtain the package SHA-256 independently and provision `edge.json` through a protected channel:

```powershell
.\Install-IdenGridEdge.ps1 -LabConfig -PackagePath C:\Staging\IdenGrid-Edge.zip `
  -PackageSha256 '<64-hex-sha256>' -Version 1.0.0 `
  -Hostname 'edge-hostname.invalid' -ProtectedConfigPath C:\SecureStaging\edge.json
```

For remote lab delivery, replace `-PackagePath` with an HTTPS `-PackageUrl`. The installer validates administrator rights, Server/x64 build, package SHA-256, safe ZIP paths, and every internal file hash before installing services. It checks every ACL command, creates the current junction, starts Edge first, waits for loopback health, starts Caddy, and requires public TLS health before reporting success.

## Upgrade and rollback

```powershell
.\Upgrade-IdenGridEdge.ps1 -PackagePath C:\Staging\IdenGrid-Edge-new.zip `
  -PackageSha256 '<64-hex-sha256>' -Version 1.1.0
```

Upgrade extracts into a new immutable version, enforces manifest/version identity, verifies the closed file set and all hashes, and runs an offline import/CLI self-check before stopping services. It preserves the prior rollback junction while switching `current`. Failure removes the new version, restores the old junction, and requires both loopback Edge and public TLS Gateway health. ProgramData is never overwritten.

## Status

```powershell
.\Get-IdenGridEdgeStatus.ps1
.\Get-IdenGridEdgeStatus.ps1 -PublicHealthUrl 'https://edge-hostname.invalid/healthz'
```

Output is JSON containing service state/accounts, relevant listeners, loopback binding posture, named firewall rules, local/public health, bundle hash verification, and state presence. It never reads or emits config content.

## Uninstall

```powershell
.\Uninstall-IdenGridEdge.ps1                 # retains ProgramData
.\Uninstall-IdenGridEdge.ps1 -PurgeData      # confirmation required
```

Only rules carrying the fixed IdenGrid product group, description, and internal names are removed. Install and uninstall paths are fixed to the documented Program Files and ProgramData roots; custom roots are intentionally unsupported because service XML paths are fixed. Every uninstall side effect honors `ShouldProcess`, and WinSW failures stop deletion. The scripts do not alter RDP, SSH, Defender, Windows Update, or unrelated firewall policy.

## Tests

On Windows PowerShell 5.1:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\windows-edge\tests\Static.Tests.ps1
```

On Linux where PowerShell is unavailable:

```bash
python3 windows-edge/tests/test_static_contracts.py
```

Static tests validate the manifest, XML accounts/secret boundaries, loopback gateway, access-log omission, firewall scope, junction rollback, explicit purge, and PowerShell 5.1 feature contract. Final release still requires clean Windows Server 2025 runtime, SCM, ACL, firewall, Defender, TLS/WSS, reboot, upgrade fault-injection, and rollback acceptance.
