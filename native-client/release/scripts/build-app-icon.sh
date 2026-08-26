#!/bin/bash
set -euo pipefail

SOURCE="${1:?usage: build-app-icon.sh BRAND_DIR OUTPUT.icns}"
OUTPUT="${2:?usage: build-app-icon.sh BRAND_DIR OUTPUT.icns}"
for command in sips iconutil; do
  command -v "$command" >/dev/null || { echo "$command is required (included with macOS Command Line Tools)" >&2; exit 1; }
done

require_square_png() {
  local size="$1" file="$SOURCE/idengrid-$1.png" width height
  [[ -f "$file" ]] || { echo "Missing deterministic icon source: $file" >&2; exit 1; }
  width="$(sips -g pixelWidth "$file" | tr -dc '0-9\n' | tail -n 1)"
  height="$(sips -g pixelHeight "$file" | tr -dc '0-9\n' | tail -n 1)"
  [[ "$width" == "$size" && "$height" == "$size" ]] || {
    echo "Invalid icon dimensions for $file: ${width}x${height}, expected ${size}x${size}" >&2
    exit 1
  }
}
for size in 32 64 128 256 512 1024; do require_square_png "$size"; done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
ICONSET="$TMP/AppIcon.iconset"
mkdir -p "$ICONSET" "$(dirname "$OUTPUT")"

# The kit provides every Retina source deterministically; only 16px is downsampled.
sips -z 16 16 "$SOURCE/idengrid-32.png" --out "$ICONSET/icon_16x16.png" >/dev/null
cp "$SOURCE/idengrid-32.png" "$ICONSET/icon_16x16@2x.png"
cp "$SOURCE/idengrid-32.png" "$ICONSET/icon_32x32.png"
cp "$SOURCE/idengrid-64.png" "$ICONSET/icon_32x32@2x.png"
cp "$SOURCE/idengrid-128.png" "$ICONSET/icon_128x128.png"
cp "$SOURCE/idengrid-256.png" "$ICONSET/icon_128x128@2x.png"
cp "$SOURCE/idengrid-256.png" "$ICONSET/icon_256x256.png"
cp "$SOURCE/idengrid-512.png" "$ICONSET/icon_256x256@2x.png"
cp "$SOURCE/idengrid-512.png" "$ICONSET/icon_512x512.png"
cp "$SOURCE/idengrid-1024.png" "$ICONSET/icon_512x512@2x.png"

iconutil -c icns "$ICONSET" -o "$OUTPUT"
[[ -s "$OUTPUT" ]] || { echo "iconutil did not create $OUTPUT" >&2; exit 1; }
