#!/bin/bash
# zycast-mipsel-build.sh — build conwrt-zycast for mipsel_24kc (NR7101) inside
# the digest-pinned openwrt/sdk image (#109 lane; docs/toolchain-lane-2026-10-22.md).
#
# Why docker+SDK and not rustup: upstream rust demoted mipsel-unknown-linux-musl
# std to tier 3, and rustup marks the component unavailable on EVERY channel
# (1.85.0 included — verified 2026-10-22). The SDK's feed-built rustc is the
# only compiler that ships mipsel musl std. Same pipeline the firmware's own
# Rust packages build with (tollgate build-package.yml pattern).
#
# Stages (all idempotent):
#   preflight   resolve image ref from scripts/openwrt-toolchain.json, check
#               free disk / volume state, print the plan — no docker pull
#   bootstrap   the long pole (HOURS on first run): feeds + lang/rust compiled
#               into the named docker volume, paid once and cached there
#   build       cargo build --release -p conwrt-zycast (static musl) using the
#               SDK's rustc + mipsel-openwrt-linux-musl toolchain from the
#               volume; binary lands in data/bin/ with sha256
#
# Usage:
#   scripts/zycast-mipsel-build.sh preflight
#   scripts/zycast-mipsel-build.sh bootstrap   # run detached, see below
#   scripts/zycast-mipsel-build.sh build
#   scripts/zycast-mipsel-build.sh             # bootstrap-if-needed + build
#
# Host discipline (AGENTS.md):
#   - refuses to start below MIN_FREE_GB (25G bootstrap / 8G build) — the
#     rust bootstrap needs 10-20G and a full disk is a shared-host outage
#   - container is named (docker ps shows the holder), volume is named —
#     colliding sessions see this lane instead of mystery disk usage
#   - bootstrap is long: launch detached, never rely on a pane surviving it:
#       mkdir -p data/sdk-lane
#       setsid nohup scripts/zycast-mipsel-build.sh bootstrap \
#         >data/sdk-lane/bootstrap.log 2>&1 < /dev/null &
#       echo $! > /tmp/opencode/<session>/pids/zycast-bootstrap.pid
#
# Stage-2 caveat: the exact env OpenWrt's feed rust needs (std location in
# staging, RUSTFLAGS) is probed at runtime; expect to tune on the FIRST
# successful bootstrap. The probe fails loudly rather than guessing.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MANIFEST="$REPO_ROOT/scripts/openwrt-toolchain.json"
ERA="${CONWRT_SDK_ERA:-apk}"                       # apk = 25.12 lane, ipk = 24.10
CONTAINER_NAME="conwrt-zycast-mipsel-build"
VOLUME_NAME="conwrt-sdk-ramips-mt7621"
BOOTSTRAP_MIN_FREE_GB="${CONWRT_SDK_BOOTSTRAP_MIN_GB:-25}"
BUILD_MIN_FREE_GB="${CONWRT_SDK_BUILD_MIN_GB:-8}"

die() { printf 'zycast-mipsel-build: ERROR: %s\n' "$1" >&2; exit 1; }

free_gb() { df -BG --output=avail / | tail -1 | tr -dc '0-9'; }

image_ref() {
  python3 - "$MANIFEST" "$ERA" <<'PY'
import json, sys
manifest, era = sys.argv[1], sys.argv[2]
sdk = json.load(open(manifest))["openwrt_sdk"]
rel = sdk["releases"][era]
missing = [k for k in ("target", "release", "digest") if not rel.get(k)]
if not sdk.get("image"):
    missing.insert(0, "image (openwrt_sdk level)")
if missing:
    sys.exit(f"manifest era {era!r} missing: {', '.join(missing)}")
print(f"{sdk['image']}:{rel['target']}-{rel['release']}@{rel['digest']}")
PY
}

name_taken() { [ "$(docker ps -aq --filter name="^${CONTAINER_NAME}$" | wc -l)" -ne 0 ]; }

docker_run() {  # named volume at /builder: first mount seeds the SDK from the
  docker run --rm --name "$CONTAINER_NAME" -w /builder \
    -v "$VOLUME_NAME:/builder" \
    -v "$REPO_ROOT:/src:ro" \
    "$@" "$(image_ref)"
}

need_free() { # $1=min GB $2=stage
  [ "$(free_gb)" -ge "$1" ] || die "$2 needs >= ${1}G free, have $(free_gb)G — \
free space first (dev-session.sh sweep; idle-lane target/ dirs), then retry"
}

stage_preflight() {
  echo "image      : $(image_ref)"
  echo "volume     : $VOLUME_NAME ($(docker volume ls -q --filter name="^${VOLUME_NAME}$" | wc -l) present)"
  echo "free disk  : $(free_gb)G (bootstrap needs >= ${BOOTSTRAP_MIN_FREE_GB}G, build >= ${BUILD_MIN_FREE_GB}G)"
  name_taken && echo "container  : $CONTAINER_NAME TAKEN (holder visible in: docker ps -a --filter name=$CONTAINER_NAME)" \
              || echo "container  : $CONTAINER_NAME (free)"
  echo "rust pins  : $(python3 "$REPO_ROOT/scripts/sdk_rust_version.py" check)"
}

stage_bootstrap() {
  need_free "$BOOTSTRAP_MIN_FREE_GB" bootstrap
  name_taken && die "container name taken — holder visible in: docker ps -a --filter name=$CONTAINER_NAME"
  docker_run bash -euo pipefail -c '
    cd /builder
    ./scripts/feeds update -a
    ./scripts/feeds install rust
    make defconfig
    # host toolchain build: hours on first run, cached in the volume afterwards
    make -j"$(nproc)" package/rust/compile
    echo "BOOTSTRAP DONE: $(ls staging_dir/hostpkg/bin/ | grep -E "^(cargo|rustc)$" | tr "\n" " ")"
  '
}

stage_build() {
  need_free "$BUILD_MIN_FREE_GB" build
  docker_run bash -euo pipefail -c '
    RUST_TARGET=mipsel-unknown-linux-musl
    CRATE=conwrt-zycast
    STAGING=/builder/staging_dir
    # Feed facts (lang/rust Makefile, openwrt-25.12): rust installs to
    # $(STAGING_DIR)/host — bin/ and lib/rustlib/ (NOT hostpkg); consumer
    # env mirrors rust-values.mk CARGO_PKG_CONFIG_VARS; std is built with
    # crt-static=false (dynamic-musl default — fine on-device; try
    # -C target-feature=+crt-static as a follow-up experiment only).
    GCC="$(ls "$STAGING"/toolchain-*/bin/mipsel-openwrt-linux-musl-gcc | head -1)"
    [ -x "$GCC" ] || { echo "no mipsel gcc under $STAGING/toolchain-*" >&2; exit 1; }
    [ -x "$STAGING/host/bin/cargo" ] || { echo "host cargo missing — run bootstrap first ($STAGING/host/bin/cargo)" >&2; exit 1; }
    STD_DIR="$STAGING/host/lib/rustlib/$RUST_TARGET"
    [ -d "$STD_DIR" ] || { echo "mipsel std missing at $STD_DIR — bootstrap incomplete?" >&2; exit 1; }
    export PATH="$STAGING/host/bin:$PATH"
    export CARGO_HOME=/builder/dl/cargo
    export CARGO_TARGET_DIR=/builder/build_dir/conwrt-zycast-target
    export CARGO_BUILD_TARGET="$RUST_TARGET"
    export CARGO_TARGET_MIPSEL_UNKNOWN_LINUX_MUSL_LINKER="$GCC"
    cd /src
    cargo build --release --locked -p "$CRATE"
    BIN="$CARGO_TARGET_DIR/$RUST_TARGET/release/$CRATE"
    file "$BIN" | grep -qE "ELF 32-bit LSB .* MIPS" \
      || { echo "WARNING: not a mipsel ELF — check linking" >&2; }
    "$STAGING"/toolchain-*/bin/mipsel-openwrt-linux-musl-strip "$BIN" || true
    sha256sum "$BIN"
  ' < /dev/null
  mkdir -p "$REPO_ROOT/data/bin"
  docker run --rm -v "$VOLUME_NAME:/builder" -v "$REPO_ROOT/data/bin:/out" \
    "$(image_ref)" \
    cp "/builder/build_dir/conwrt-zycast-target/mipsel-unknown-linux-musl/release/conwrt-zycast" \
       "/out/conwrt-zycast-mipsel" || die "binary copy-out failed"
  file "$REPO_ROOT/data/bin/conwrt-zycast-mipsel"
  sha256sum "$REPO_ROOT/data/bin/conwrt-zycast-mipsel"
  echo "ARTIFACT: $REPO_ROOT/data/bin/conwrt-zycast-mipsel"
}

case "${1:-all}" in
  preflight) stage_preflight ;;
  bootstrap) stage_bootstrap ;;
  build)     stage_build ;;
  all)       stage_preflight; stage_bootstrap; stage_build ;;
  *)         sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
