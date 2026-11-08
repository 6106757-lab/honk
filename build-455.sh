#!/bin/bash
# Full build for src-follow-455 (clean 455 + follow 4 files + slim observation patch B).
# Step 1 builds the eBPF object; step 2 builds the musl honk-core with native-ui.
# Derived from build-612.sh; only SRC/LOG changed. build-612.sh is left untouched.
set -e
export RUSTUP_HOME=/root/.rustup
export CARGO_HOME=/opt/openclaw/honk-dev/cargo
export PATH=/opt/cargo/bin:/opt/openclaw/honk-dev/tools/zig:$PATH

SRC=/opt/openclaw/honk-dev/src-follow-455
DOONA=/opt/openclaw/honk-dev/ui/doona
CHANNEL=nightly-2026-10-20
LOG=$SRC/build-455.log

exec > >(tee -a "$LOG") 2>&1

echo "[$(date)] === STEP 1: eBPF object (top-level $CHANNEL) ==="
echo "[$(date)] host CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-<unset>}"
cd "$SRC/crates/honk-ebpf"
# honk-core/build.rs looks for the object inside the ebpf crate's own target
# dir; pin it here so STEP 2 does not rebuild (or embed a stale global object).
CARGO_TARGET_DIR="$SRC/crates/honk-ebpf/target" \
cargo +$CHANNEL build --release -Zbuild-std=core --target bpfel-unknown-none

OBJ="$SRC/crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf"
echo "[$(date)] verify .BTF section"
if readelf -S "$OBJ" | grep -q "\.BTF"; then echo "BTF_OK"; else echo "NO_BTF_ABORT"; exit 1; fi
printf "%s" "$CHANNEL" > "$OBJ.toolchain"
touch "$OBJ" "$OBJ.toolchain"
echo "[$(date)] marker=$(cat "$OBJ.toolchain") bytes=$(wc -c < "$OBJ.toolchain")"

echo "[$(date)] === STEP 2: musl honk-core with native-ui ==="
cd "$SRC"
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl="$SRC/ci/zigcc" \
CXX_x86_64_unknown_linux_musl="$SRC/ci/zigcxx" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$SRC/ci/zigcc" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$($SRC/ci/zig-bindgen-env x86_64-linux-musl)" \
HONK_DOONA_DIR="$DOONA" \
cargo build --release -p honk-core --features "ebpf,native-ui" --target x86_64-unknown-linux-musl

OUT="${CARGO_TARGET_DIR:-$SRC/target}"
BIN="$OUT/x86_64-unknown-linux-musl/release/honk-core"
echo "[$(date)] === DONE ==="
ls -la "$BIN"
sha256sum "$BIN"
file "$BIN" 2>/dev/null || true
