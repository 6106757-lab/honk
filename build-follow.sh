#!/bin/bash
# Portable build for the 6.12 / 455 follow branch.
# Proven on 128 as build-455.sh; SRC/DOONA made relocatable here.
# Override HONK_DOONA_DIR, CARGO_HOME, RUSTUP_HOME as needed.
set -e
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export RUSTUP_HOME="${RUSTUP_HOME:-$HOME/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
for p in /opt/cargo/bin /opt/openclaw/honk-dev/tools/zig; do
  [ -d "$p" ] && PATH="$p:$PATH"
done
export PATH
CHANNEL=nightly-2026-10-20
DOONA="${HONK_DOONA_DIR:-$SRC/../ui/doona}"

echo "[$(date)] === STEP 1: eBPF object ($CHANNEL) ==="
cd "$SRC/crates/honk-ebpf"
# honk-core/build.rs looks here; keep the object inside the ebpf crate.
CARGO_TARGET_DIR="$SRC/crates/honk-ebpf/target" \
  cargo +$CHANNEL build --release -Zbuild-std=core --target bpfel-unknown-none
OBJ="$SRC/crates/honk-ebpf/target/bpfel-unknown-none/release/honk-ebpf"
readelf -S "$OBJ" | grep -q '\.BTF' || { echo "NO_BTF_ABORT"; exit 1; }
printf "%s" "$CHANNEL" > "$OBJ.toolchain"
touch "$OBJ" "$OBJ.toolchain"
echo "BTF_OK ($(wc -c < "$OBJ") bytes)"

echo "[$(date)] === STEP 2: musl honk-core (ebpf,native-ui) ==="
cd "$SRC"
[ -d "$DOONA" ] || echo "WARN: doona dir not found: $DOONA (set HONK_DOONA_DIR)"
ZIGCC_TARGET=x86_64-linux-musl \
CC_x86_64_unknown_linux_musl="$SRC/ci/zigcc" \
CXX_x86_64_unknown_linux_musl="$SRC/ci/zigcxx" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER="$SRC/ci/zigcc" \
CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="-C link-self-contained=no" \
BINDGEN_EXTRA_CLANG_ARGS="$($SRC/ci/zig-bindgen-env x86_64-linux-musl)" \
HONK_DOONA_DIR="$DOONA" \
cargo build --release -p honk-core --features "ebpf,native-ui" --target x86_64-unknown-linux-musl

echo "[$(date)] === DONE ==="
ls -la "$SRC/target/x86_64-unknown-linux-musl/release/honk-core"
sha256sum "$SRC/target/x86_64-unknown-linux-musl/release/honk-core"
