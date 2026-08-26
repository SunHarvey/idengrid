#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
MACOS="$ROOT/macos"; RELEASE="$ROOT/release"; OUT="$RELEASE/build"; APP="$OUT/IdenGrid.app"
export ARCHS=arm64 ONLY_ACTIVE_ARCH=YES
[[ "$(uname -s)" == Darwin && "$(uname -m)" == arm64 ]] || { echo "Build requires Apple Silicon macOS" >&2; exit 1; }
: "${IDENGRID_AGENT_BINARY:?Set IDENGRID_AGENT_BINARY to the arm64 idengrid-agent artifact}"
: "${SPARKLE_PUBLIC_ED_KEY:?Set SPARKLE_PUBLIC_ED_KEY to the Sparkle Ed25519 public key}"
: "${IDENGRID_API_BASE_URL:?Set IDENGRID_API_BASE_URL to the HTTPS control origin}"
[[ "$IDENGRID_API_BASE_URL" == https://* ]] || { echo "IDENGRID_API_BASE_URL must use HTTPS" >&2; exit 1; }
[[ -x "$IDENGRID_AGENT_BINARY" ]] || { echo "Agent binary is not executable" >&2; exit 1; }
[[ "$(lipo -archs "$IDENGRID_AGENT_BINARY")" == arm64 ]] || { echo "Agent must be arm64-only" >&2; exit 1; }
"$RELEASE/scripts/fetch-chromium.sh"
"$RELEASE/scripts/build-app-icon.sh" "$MACOS/Resources/Brand" "$OUT/AppIcon.icns"
cd "$MACOS"
swift build -c release --arch arm64 -Xswiftc -warnings-as-errors
rm -rf "$APP"; mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$APP/Contents/Frameworks"
CLIENT_CONFIG="$OUT/client-config.json"
rm -f "$CLIENT_CONFIG"
plutil -create json "$CLIENT_CONFIG"
plutil -insert api_base_url -string "$IDENGRID_API_BASE_URL" "$CLIENT_CONFIG"
cp "$CLIENT_CONFIG" "$APP/Contents/Resources/client-config.json"
cp "$MACOS/.build/arm64-apple-macosx/release/IdenGrid" "$APP/Contents/MacOS/IdenGrid"
cp "$IDENGRID_AGENT_BINARY" "$APP/Contents/MacOS/idengrid-agent"
cp "$MACOS/Resources/Info.plist" "$APP/Contents/Info.plist"
plutil -replace SUPublicEDKey -string "$SPARKLE_PUBLIC_ED_KEY" "$APP/Contents/Info.plist"
plutil -replace SUFeedURL -string "${IDENGRID_UPDATE_FEED_URL:-${IDENGRID_API_BASE_URL%/}/updates/macos-arm64/appcast.xml}" "$APP/Contents/Info.plist"
ditto "$MACOS/Resources/Extension" "$APP/Contents/Resources/Extension"
ditto "$MACOS/Resources/Brand" "$APP/Contents/Resources/Brand"
cp "$OUT/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
cp "$MACOS/Resources/THIRD_PARTY_NOTICES.txt" "$APP/Contents/Resources/THIRD_PARTY_NOTICES.txt"
ditto "$RELEASE/build/chromium/IdenGrid Browser.app" "$APP/Contents/Frameworks/IdenGrid Browser.app"
SPARKLE="$(find "$MACOS/.build" -type d -name Sparkle.framework -print -quit)"
[[ -n "$SPARKLE" ]] || { echo "Sparkle.framework missing from build" >&2; exit 1; }
ditto "$SPARKLE" "$APP/Contents/Frameworks/Sparkle.framework"
MAIN_BINARY="$APP/Contents/MacOS/IdenGrid"
if ! otool -l "$MAIN_BINARY" | grep -Fq '@executable_path/../Frameworks'; then
  install_name_tool -add_rpath '@executable_path/../Frameworks' "$MAIN_BINARY"
fi
# Sparkle's macOS framework slice may be universal; ship arm64 code only.
while IFS= read -r -d '' binary; do
  if file "$binary" | grep -q 'Mach-O'; then
    ARCH_LIST="$(lipo -archs "$binary")"
    [[ " $ARCH_LIST " == *' arm64 '* ]] || { echo "Non-arm64 Sparkle component: $binary" >&2; exit 1; }
    if [[ "$ARCH_LIST" != arm64 ]]; then MODE="$(stat -f '%Lp' "$binary")"; lipo "$binary" -thin arm64 -output "$binary.thin"; chmod "$MODE" "$binary.thin"; mv "$binary.thin" "$binary"; fi
  fi
done < <(find "$APP/Contents/Frameworks/Sparkle.framework" -type f -print0)
plutil -replace CFBundleShortVersionString -string "${VERSION:-1.0.0}" "$APP/Contents/Info.plist"
plutil -replace CFBundleVersion -string "${BUILD_NUMBER:-1}" "$APP/Contents/Info.plist"
file "$APP/Contents/MacOS/IdenGrid" | grep -q 'arm64' || { echo "Main binary is not arm64" >&2; exit 1; }
[[ "$(lipo -archs "$APP/Contents/MacOS/IdenGrid")" == arm64 ]] || { echo "Main binary must be arm64-only" >&2; exit 1; }
echo "$APP"
