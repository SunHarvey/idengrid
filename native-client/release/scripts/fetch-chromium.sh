#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="${1:-$ROOT/chromium-manifest.json}"
OUT="${2:-$ROOT/build/chromium}"
[[ "$(uname -s)" == Darwin ]] || { echo "Chromium fetch requires macOS" >&2; exit 1; }
[[ "$(uname -m)" == arm64 ]] || { echo "wrong architecture: host must be arm64" >&2; exit 1; }
read_key() { /usr/libexec/PlistBuddy -c "Print :$1" /dev/stdin <<<"$(plutil -convert xml1 -o - "$MANIFEST")"; }
ARCH="$(read_key architecture)"; REVISION="$(read_key revision)"; URL="$(read_key url)"; SHA="$(read_key sha256)"; ARCHIVE_ROOT="$(read_key archiveRoot)"; EXECUTABLE="$(read_key executable)"
[[ "$ARCH" == arm64 ]] || { echo "wrong architecture in manifest" >&2; exit 1; }
[[ -n "$REVISION" && "$REVISION" != REPLACE_* && "$REVISION" != *PLACEHOLDER* ]] || { echo "PLACEHOLDER revision must be updated" >&2; exit 1; }
[[ "$URL" == https://* && "$URL" != *REPLACE_* && "$URL" != *PLACEHOLDER* ]] || { echo "PLACEHOLDER URL must be updated" >&2; exit 1; }
[[ "$SHA" =~ ^[0-9a-fA-F]{64}$ && "$SHA" != 0000000000000000000000000000000000000000000000000000000000000000 ]] || { echo "missing/zero checksum" >&2; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
curl --fail --location --proto '=https' --tlsv1.2 "$URL" -o "$TMP/chromium.zip"
printf '%s  %s
' "$SHA" "$TMP/chromium.zip" | shasum -a 256 -c -
rm -rf "$OUT"; mkdir -p "$OUT"; ditto -x -k "$TMP/chromium.zip" "$OUT"
BIN="$OUT/$EXECUTABLE"; [[ -x "$BIN" ]] || { echo "manifest executable missing" >&2; exit 1; }
ARCHS="$(lipo -archs "$BIN")"; [[ "$ARCHS" == arm64 ]] || { echo "wrong architecture in Chromium: $ARCHS" >&2; exit 1; }
SOURCE_APP="$OUT/$ARCHIVE_ROOT"; [[ -d "$SOURCE_APP" ]] || { echo "manifest app root missing" >&2; exit 1; }
while IFS= read -r -d '' binary; do
  if file "$binary" | grep -q 'Mach-O'; then
    ARCHS="$(lipo -archs "$binary")"; [[ "$ARCHS" == arm64 ]] || { echo "wrong architecture in Chromium component: $binary ($ARCHS)" >&2; exit 1; }
  fi
done < <(find "$SOURCE_APP" -type f -print0)
FINAL_APP="$OUT/IdenGrid Browser.app"
rm -rf "$FINAL_APP"; mv "$SOURCE_APP" "$FINAL_APP"
plutil -replace CFBundleName -string "IdenGrid Browser" "$FINAL_APP/Contents/Info.plist"
plutil -replace CFBundleDisplayName -string "IdenGrid Browser" "$FINAL_APP/Contents/Info.plist"
echo "Fetched pinned Chromium revision $REVISION ($ARCHS)"
