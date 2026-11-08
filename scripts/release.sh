#!/bin/sh
# Cuts a release locally: builds, writes SHA256SUMS and prints the files to
# attach to a GitHub release (CI does the same on a v* tag).
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

scripts/build.sh

VERSION=${1:-manual}
{
  echo "# dexvm-wasm $VERSION"
  sha256sum dist/dexvm_bridge.wasm dexvm-host.js
} > dist/SHA256SUMS

{
  echo "built: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "wasm: $(wc -c < dist/dexvm_bridge.wasm) bytes"
  echo "dexvm: 0.2.0 (patched, see patches/)"
} > dist/BUILDINFO

cat dist/SHA256SUMS dist/BUILDINFO
echo
echo "attach dist/dexvm_bridge.wasm, dexvm-host.js, dist/SHA256SUMS, dist/BUILDINFO"
