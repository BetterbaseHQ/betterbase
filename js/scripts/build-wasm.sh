#!/usr/bin/env bash
# Build the WASM packages for the JS SDK.
#
# On macOS the host ar/ranlib (Mach-O only) silently drop wasm32 object files
# from static archives, which breaks sqlite-wasm-rs (undefined sqlite3_*
# symbols at link time). Force LLVM's tools when we can find them.
set -e

if [ "$(uname -s)" = "Darwin" ]; then
    if [ -x /opt/homebrew/opt/llvm/bin/llvm-ar ]; then
        LLVM_BIN=/opt/homebrew/opt/llvm/bin
    elif command -v llvm-ar >/dev/null 2>&1; then
        LLVM_BIN="$(dirname "$(command -v llvm-ar)")"
    fi
    if [ -n "${LLVM_BIN:-}" ]; then
        export TARGET_AR="$LLVM_BIN/llvm-ar"
        export TARGET_RANLIB="$LLVM_BIN/llvm-ranlib"
    else
        echo "warning: llvm-ar not found (brew install llvm); the macOS ar will likely fail to archive wasm objects" >&2
    fi
fi

wasm-pack build --target bundler ../crates/betterbase-wasm "$@"
wasm-pack build --target bundler ../crates/betterbase-db-wasm "$@"
