#!/bin/bash
set -euo pipefail
APP="${1:?usage: sign-nested.sh IdenGrid.app}"
: "${DEVELOPER_ID_APPLICATION:?Set DEVELOPER_ID_APPLICATION}"
ENTITLEMENTS="$(cd "$(dirname "$0")/../../macos/Resources" && pwd)/IdenGrid.entitlements"
sign() {
  if [[ "$DEVELOPER_ID_APPLICATION" == "-" ]]; then
    codesign --force --sign - "$@"
  else
    codesign --force --timestamp --options runtime --sign "$DEVELOPER_ID_APPLICATION" "$@"
  fi
}
# Innermost Chromium helpers/libraries first, then frameworks and nested app.
while IFS= read -r -d '' item; do sign "$item"; done < <(find "$APP/Contents/Frameworks/IdenGrid Browser.app/Contents" -type f \( -perm -111 -o -name '*.dylib' \) -print0)
while IFS= read -r bundle; do sign "$bundle"; done < <(find -d "$APP/Contents/Frameworks/IdenGrid Browser.app/Contents" -type d \( -name '*.framework' -o -name '*.xpc' -o -name '*.app' \))
sign "$APP/Contents/Frameworks/IdenGrid Browser.app"
# Sparkle contains XPC services and helpers; sign deepest code before its framework.
while IFS= read -r -d '' item; do sign "$item"; done < <(find "$APP/Contents/Frameworks/Sparkle.framework" -type f -perm -111 -print0)
while IFS= read -r service; do sign "$service"; done < <(find -d "$APP/Contents/Frameworks/Sparkle.framework" -type d \( -name '*.xpc' -o -name '*.app' \))
sign "$APP/Contents/Frameworks/Sparkle.framework"
sign "$APP/Contents/MacOS/idengrid-agent"
sign --entitlements "$ENTITLEMENTS" "$APP/Contents/MacOS/IdenGrid"
sign --entitlements "$ENTITLEMENTS" "$APP"
codesign --verify --strict --verbose=2 "$APP"
