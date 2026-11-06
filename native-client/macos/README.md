# IdenGrid native macOS client

SwiftUI management client for **macOS 13+ on Apple Silicon**. `Package.swift` declares Swift tools **6.0**; use an Apple Silicon Mac with a compatible Swift toolchain, macOS SDK/Command Line Tools and Rust. Xcode can open the package but is not required for the command-line development build. The current app has a `WindowGroup`, **not** a menu-bar controller. It uses native `URLSession` routes under `/v1/native`, Keychain for the refresh token/device session, one bundled Agent per running store and a separately bundled browser.

## User flow and isolation

Open IdenGrid, log in, select/search a store, and press **启动**. Users do not need Terminal, ports or scripts. Login password is cleared after each attempt; persistent credentials belong in Keychain. Each store has an exclusive lock, runtime and downloads directories, independent Profile and Agent. Existing legacy `IdenGrid/Profiles/<store>/Profile` directories are used in place, not moved; new profiles use `IdenGrid/Stores/<store>/Profile`. Do not share one live Profile between devices or versions.

The management client writes a short-lived Agent configuration to a mode-`0600` file and launches `idengrid-agent --config <path>` (Unix-only file option); it removes this config after authenticated readiness. It sends newline-delimited JSON `status`/`shutdown`/`update_token` requests with a control capability over a mode-`0600` Unix socket. There is **no** `GET /v1/status` HTTP endpoint. Status includes `status`, `socks_host`, `socks_port`, `store_id`, `device_id` and optional `edge_latency`; the client constructs its local SOCKS URL from host/port, verifies the expected exit IP, then launches its bundled browser with isolated Profile, proxy, extension, QUIC and WebRTC flags. The SOCKS port is OS-selected (`local_port: 0`) and not exposed to the user.

## Bundle and inputs

From the repository root, `native-client/release/scripts/build-arm64.sh` assembles (but does **not** sign) `native-client/release/build/IdenGrid.app`, including:

- `Contents/MacOS/IdenGrid` and `Contents/MacOS/idengrid-agent`
- `Contents/Frameworks/IdenGrid Browser.app` and `Sparkle.framework`
- `Contents/Resources/Extension`, `Brand` and injected `client-config.json`

The checked-in `native-client/release/chromium-manifest.json` currently contains a concrete arm64 revision, HTTPS URL and SHA-256; it is **not** a placeholder. Review its provenance, digest, security currency and distribution rights before a new release rather than replacing it blindly. `fetch-chromium.sh` refuses placeholder/zero digests, non-arm64 hosts/binaries and hash mismatches. No Chromium binary or DMG is committed.

For a **local-only ad-hoc signed development app**, set a non-secret `IDENGRID_API_BASE_URL` build input and run from the repository root:

```bash
native-client/release/scripts/verify-on-apple-silicon.sh
IDENGRID_API_BASE_URL=https://control.example.invalid/ native-client/release/scripts/build-dev-arm64.sh
```

The first script checks host/toolchain, builds/tests the Agent and Swift client; the second builds the Agent and app, signs ad-hoc and leaves `native-client/release/build/IdenGrid-dev.app`. Its generated Sparkle public key is **not** a production update key. `build-dev-arm64.sh` refuses to replace a running development app. Confirm the resulting bundle version, architecture, code signature and exact path before calling it usable; this development app is neither notarized nor a distributable DMG.

For a **formal release**, use protected build inputs for the Apple Silicon Agent (`IDENGRID_AGENT_BINARY`), HTTPS API origin, update feed, real Sparkle public update key and Developer ID identity. The ordered entry points are `build-arm64.sh` (assemble), `check-licenses-sbom.sh <app>` (license/SBOM gate; requires `syft`), `sign-nested.sh <app>` (nested signing with `DEVELOPER_ID_APPLICATION`), then `notarize-staple-dmg.sh <signed-app>` (requires notary key **path**, key ID and issuer ID). Review each script's prerequisites before use. Do not pass private-key contents in commands or commit them. The notarization script creates, submits, staples and validates an actual DMG, but its success alone does not replace a clean-device launch or browser/Agent/egress acceptance. See [release acceptance](../../docs/RELEASE-ACCEPTANCE.md).

## Static and runtime verification

From the repository root, with Python test dependencies installed:

```bash
python3 -m pytest -q native-client/macos/Tests/Static
bash native-client/macos/Tests/Static/check_contract.sh
```

Run the shell contract **before creating** `native-client/release/build/IdenGrid.dmg`: it intentionally asserts that this default-path DMG does not exist. The source compile/contract entry point is `native-client/release/scripts/verify-on-apple-silicon.sh` on an Apple Silicon Mac. Static checks and compiler success are not proof of login, Profile isolation, fixed exit, leak prevention, token refresh or Fail Closed; verify those on the exact packaged app and record the result separately.
