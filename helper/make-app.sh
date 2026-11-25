#!/bin/sh
# make-app.sh [IDENTITY]: build nod.app in .build/ and print its path.
#
# With no IDENTITY the app is signed ad hoc (for trying it on this Mac).
# With a Developer ID Application identity it is signed for distribution
# (hardened runtime, secure timestamp); notarize it next, see the README.
set -eu
cd "$(dirname "$0")"
swift build -c release >&2
app=.build/nod.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS"
cp .build/release/nod "$app/Contents/MacOS/nod"
build=$(git rev-list --count HEAD 2>/dev/null || echo 1)
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key><string>dev.istando.nod</string>
  <key>CFBundleName</key><string>nod</string>
  <key>CFBundleDisplayName</key><string>nod</string>
  <key>CFBundleExecutable</key><string>nod</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleShortVersionString</key><string>0.2.0</string>
  <key>CFBundleVersion</key><string>$build</string>
  <key>LSMinimumSystemVersion</key><string>14.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
PLIST
if [ -n "${1:-}" ]; then
  codesign --force --sign "$1" --options runtime --timestamp "$app"
else
  codesign --force --sign - "$app"
fi
codesign --verify --strict --verbose=2 "$app" >&2
echo "$PWD/$app"
