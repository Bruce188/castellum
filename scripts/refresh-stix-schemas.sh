#!/usr/bin/env bash
set -euo pipefail
REPO="https://github.com/oasis-open/cti-stix2-json-schemas.git"
TAG="stix2.1"
DEST="backend/src/test/resources/schemas/stix-2.1"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
git clone --depth 1 --branch "$TAG" "$REPO" "$TMP/repo"
SHA="$(git -C "$TMP/repo" rev-parse HEAD)"
rm -rf "$DEST/sdos" "$DEST/common" "$DEST/bundle.json"
mkdir -p "$DEST/sdos" "$DEST/common"
cp "$TMP/repo/schemas/bundle.json" "$DEST/bundle.json"
cp "$TMP/repo/schemas/sdos/"*.json "$DEST/sdos/" 2>/dev/null || true
cp "$TMP/repo/schemas/common/"*.json "$DEST/common/" 2>/dev/null || true
sed -i "s|^Pinned commit SHA: .*|Pinned commit SHA: $SHA|" "$DEST/README.md"
sed -i "s|^Last refreshed: .*|Last refreshed: $(date -u +%Y-%m-%d)|" "$DEST/README.md"
echo "Refreshed schemas at $SHA"
