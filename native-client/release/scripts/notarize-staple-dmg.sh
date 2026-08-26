#!/bin/bash
set -euo pipefail
APP="${1:?usage: notarize-staple-dmg.sh IdenGrid.app [output.dmg]}"; OUT="${2:-$(dirname "$APP")/IdenGrid.dmg}"
: "${APPLE_KEY_ID:?Set APPLE_KEY_ID}"; : "${APPLE_ISSUER_ID:?Set APPLE_ISSUER_ID}"; : "${APPLE_PRIVATE_KEY:?Set APPLE_PRIVATE_KEY path}"
[[ -d "$APP" ]] || { echo "Signed app not found" >&2; exit 1; }
codesign --verify --strict --verbose=2 "$APP"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
ditto "$APP" "$TMP/IdenGrid.app"; ln -s /Applications "$TMP/Applications"
rm -f "$OUT"; hdiutil create -volname IdenGrid -srcfolder "$TMP" -format UDZO -ov "$OUT"
xcrun notarytool submit "$OUT" --key "$APPLE_PRIVATE_KEY" --key-id "$APPLE_KEY_ID" --issuer "$APPLE_ISSUER_ID" --wait
xcrun stapler staple "$APP"; xcrun stapler validate "$APP"
xcrun stapler staple "$OUT"; xcrun stapler validate "$OUT"
spctl --assess --type open --context context:primary-signature --verbose=2 "$OUT"
echo "$OUT"
