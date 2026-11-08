#!/bin/sh
# Builds dist/dexvm_bridge.wasm (and dist/dexvm_bridge.raw.wasm).
#
# Requires: rustup + wasm32-wasip1 target, a host C compiler for build scripts
# (gcc/clang), and optionally wasm-opt (binaryen) for the -Oz pass.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

export PATH="$HOME/.cargo/bin:$PATH"
TARGET=wasm32-wasip1
CRATE=dexvm-bridge

if ! rustup target list --installed | grep -qx "$TARGET"; then
  rustup target add "$TARGET"
fi

# Some sandboxed or shared filesystems cannot host rustc's dep-info files.
# Keep the build directory off them when the default location looks risky.
case "$ROOT" in
  /var/minis/*) export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/dexvm-wasm-target}" ;;
esac

cargo build --release --target "$TARGET" --manifest-path "$CRATE/Cargo.toml"

OUTDIR="${CARGO_TARGET_DIR:-$CRATE/target}"
WASM="$OUTDIR/$TARGET/release/dexvm_bridge.wasm"
[ -f "$WASM" ] || { echo "build output not found: $WASM" >&2; exit 1; }

mkdir -p dist
cp "$WASM" dist/dexvm_bridge.raw.wasm

if command -v wasm-opt >/dev/null 2>&1; then
  wasm-opt -Oz --strip-debug --strip-producers \
    dist/dexvm_bridge.raw.wasm -o dist/dexvm_bridge.wasm
else
  echo "warning: wasm-opt not found, using the unoptimised binary" >&2
  cp dist/dexvm_bridge.raw.wasm dist/dexvm_bridge.wasm
fi

echo
ls -l dist/dexvm_bridge.raw.wasm dist/dexvm_bridge.wasm
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum dist/dexvm_bridge.wasm dexvm-host.js
fi
