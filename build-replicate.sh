#!/bin/bash
# Replicates src-follow's proven build (Justfile: build-ebpf + build-musl "ebpf,native-ui").
# Step 1 builds the eBPF object at top level (cargo +nightly works here);
# Step 2 builds the musl honk-core with native-ui and SKIPS nested eBPF (prebuilt+marker present).
set -e
export RUSTUP_HOME=/root/.rustup
export CARGO_HOME=/opt/openclaw/honk-dev/cargo
export PATH=/opt/cargo/bin:/opt/openclaw/honk-dev/tools/zig:$PATH

SRC=/opt/openclaw/honk-dev/src-follow-66
DOONA=/opt/openclaw/honk-dev/ui/doona
CHANNEL=nightly-2026-10-20
LOG=/opt/openclaw/honk-dev/src-follow-66/build-replicate.log

exec > >(tee -a "$LOG") 2>&1

echo "[$(date)] === STEP 1: eBPF object (top-level $CHANNEL) ==="
cd "$SRC/crates/honk-ebpf"
cargo +$CHANNEL build --release -Zbuild-std=core --target bpfel-unknown-none

OBJ="$SRC/crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf"
echo "[$(date)] verify .BTF section"
if readelf -S "$OBJ" | grep -q "\.BTF"; then echo "BTF_OK"; else echo "NO_BTF_ABORT"; exit 1; fi
# Write marker exactly like build.rs: std::fs::write(path, channel) -> no trailing newline
printf "%s" "$CHANNEL" > "$OBJ.toolchain"
touch "$OBJ" "$OBJ.toolchain"
echo "[$(date)] marker=$(cat "$OBJ.toolchain") bytes=$(wc -c < "$OBJ.toolchain")"

echo "[$(date)] === STEP 2: musl honk-core with native-ui ==="
cd "$SRC"
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl="$SRC/ci/zigcc" \
CXX_x86_64_unknown_linux_musl="$SRC/ci/zigcxx" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$SRC/ci/zigcc" \
BINDGEN_EXTRA_CLANG_ARGS="$($SRC/ci/zig-bindgen-env x86_64-linux-musl)" \
HONK_DOONA_DIR="$DOONA" \
cargo build --release -p honk-core --features "ebpf,native-ui" --target x86_64-unknown-linux-musl

BIN="$SRC/target/x86_64-unknown-linux-musl/release/honk-core"
echo "[$(date)] === DONE ==="
ls -la "$BIN"
file "$BIN" 2>/dev/null || true
