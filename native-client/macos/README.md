# IdenGrid native macOS client

SwiftUI management client for **macOS 13+ on Apple Silicon only**. The package opens directly in Xcode 15+ (`open Package.swift`) and builds from the command line with Swift 5.9. It uses native `URLSession` endpoints under `/v1/native`, Security.framework Keychain storage, a menu-bar controller, one bundled Agent per running store, and a separately bundled Chromium app.

## User flow

Open IdenGrid, log in, select/search a store, and press **启动**. Users never need Terminal, ports, certificates, or scripts. The entered password exists only in the view model long enough to submit login and is cleared after every attempt. Only refresh token and device-session identifier enter Keychain.

## Runtime bundle contract

`build-arm64.sh` assembles (but does not sign) this bundle:

- `Contents/MacOS/IdenGrid`
- `Contents/MacOS/idengrid-agent`
- `Contents/Frameworks/IdenGrid Browser.app`
- `Contents/Frameworks/Sparkle.framework`
- `Contents/Resources/Extension`

The Agent config contains the short-lived access credential/control secret and is atomically written mode `0600`. Control readiness and egress status are requested over its authenticated Unix-domain socket; no user-visible TCP port is allocated. Every store gets an exclusive lock, runtime directory, downloads directory, and profile. If the declared or canonical legacy `IdenGrid/Profiles/<store>/Profile` already exists, it is used in place and is never moved. New profiles use `IdenGrid/Stores/<store>/Profile`.

The expected Agent contract is `idengrid-agent --config <path>` and authenticated `GET /v1/status`, returning readiness, authentication, egress IP, and a loopback `proxyURL`. The config requests an ephemeral loopback proxy (`127.0.0.1:0`); the selected port is internal and never shown in the UI. Chromium is launched only from the nested app bundle with isolated profile/download locations, that verified Agent proxy, managed-policy directory, and bundled extension.

## Release prerequisites

1. Replace every placeholder in `release/chromium-manifest.json` with a pinned arm64 artifact revision, HTTPS URL, and real SHA-256. The fetcher intentionally refuses the committed placeholder, zero checksum, non-arm64 host, and non-arm64 binary.
2. Supply a separately built arm64 Agent through `IDENGRID_AGENT_BINARY`.
3. Set `IDENGRID_API_BASE_URL`, `IDENGRID_UPDATE_FEED_URL`, and `SPARKLE_PUBLIC_ED_KEY` for the build.
4. Run the release scripts on Apple Silicon macOS. The build rejects Intel hosts rather than emitting a universal or Intel build.

No Chromium binary or DMG is committed. The notarization script creates a real compressed DMG only after it has a signed app and credentials, submits it, then staples and validates it.

## Verification

Linux static checks: `uv run --with pytest pytest -q Tests/Static/test_source_contract.py && Tests/Static/check_contract.sh`.
macOS source tests: `swift test --arch arm64`. Full release: `release/scripts/build-arm64.sh`, signing, compliance, then notarization scripts.
