#!/bin/bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
RELEASE="$ROOT/release"
AGENT="$ROOT/agent-rs/target/aarch64-apple-darwin/release/idengrid-agent"
DEV_APP="$RELEASE/build/IdenGrid-dev.app"
DEV_MAIN="$DEV_APP/Contents/MacOS/IdenGrid"
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || {
  echo "Development app build requires Apple Silicon macOS" >&2
  exit 2
}

if pgrep -f "^${DEV_MAIN}$" >/dev/null 2>&1; then
  echo "Refusing to replace a running development app. Quit IdenGrid Dev first." >&2
  exit 3
fi

cd "$ROOT/agent-rs"
cargo build --locked --release --target aarch64-apple-darwin
[[ "$(lipo -archs "$AGENT")" == arm64 ]] || { echo "Agent must be arm64-only" >&2; exit 2; }

export IDENGRID_AGENT_BINARY="$AGENT"
export SPARKLE_PUBLIC_ED_KEY="$(openssl rand -base64 32 | tr -d '\n')"
export VERSION="${VERSION:-0.6.7-dev}"
export BUILD_NUMBER="${BUILD_NUMBER:-1}"

"$RELEASE/scripts/build-arm64.sh"
APP="$RELEASE/build/IdenGrid.app"
rm -rf "$DEV_APP"
mv "$APP" "$DEV_APP"
plutil -replace CFBundleDisplayName -string "澜序 Dev" "$DEV_APP/Contents/Info.plist"
plutil -replace SUEnableAutomaticChecks -bool false "$DEV_APP/Contents/Info.plist"
plutil -insert IDGDevelopmentBuild -bool true "$DEV_APP/Contents/Info.plist"

export DEVELOPER_ID_APPLICATION=-
"$RELEASE/scripts/sign-nested.sh" "$DEV_APP"
codesign --verify --deep --strict --verbose=2 "$DEV_APP"

echo "Development app built: $DEV_APP"
echo "This build is ad-hoc signed for local testing only; it is not notarized or distributable."
