#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

# Render docs/social/netevd-preview.html to docs/assets/social-preview.png (1568x784, Apple dark).
# Needs Google Chrome and macOS `sips`.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
[[ -x "$CHROME" ]] || { echo "Google Chrome not found (set CHROME=...)" >&2; exit 1; }
TMP="$(mktemp -d "${TMPDIR:-/tmp}/preview.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
"$CHROME" --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1568,784 --screenshot="$TMP/p.png" "file://$HERE/netevd-preview.html" >/dev/null 2>&1
sips -s format png "$TMP/p.png" --out "$HERE/../assets/social-preview.png" >/dev/null
echo "wrote docs/assets/social-preview.png"
