#!/bin/sh
# build-agent-apk.sh — Package conwrt-agent as an OpenWrt apk package (mipsel_24kc)
#
# Usage:
#   ./scripts/build-agent-apk.sh [--output DIR]
#
# Produces: conwrt-agent-<version>[-g<short-sha>]_mipsel_24kc.apk in dist/
#   (or --output DIR); the commit SHA is also embedded as the package's
#   repo-commit info field (unique build identity, #458)
#
# Requires: git, curl, make, gcc, pkg-config,
#   libssl-dev zlib1g-dev libzstd-dev lua5.3 liblua5.3-dev
#   plus rustup nightly + rust-src (via scripts/cross-mipsel.sh, invoked below).
#
# Background (live-verified on COVR-X1860 A1 / OpenWrt 25.12.5 / apk-tools
# 3.0.5, 2026-10-14) — OpenWrt 25.12.x uses apk-tools 3 (APKv3/ADB format),
# NOT opkg/ipk:
#   - legacy .ipk (ar + control.tar.gz + data.tar.gz):
#     "file format is invalid or inconsistent"
#   - hand-crafted v2 apk (gzip tar + .PKGINFO): "v2 package format error"
#     (the v2 reader demands an embedded data-checksum/signature structure)
# The reliable path: build apk-tools 3 from source on the host and use its
# `apk mkpkg` (ADBv3 writer). Packages built by apk-tools 3.0.8 install fine
# on device apk-tools 3.0.5. On-device install of the unsigned result:
#   apk add --no-network --allow-untrusted --force-non-repository <pkg>.apk
#
# apk-tools source-build quirks (handled below):
#   - src/genhelp.lua needs +x and its shebang wants /usr/bin/lua5.3
#   - the lua/ bindings need liblua5.3-dev (runtime lua5.3 alone lacks lua.h)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

OUTPUT_DIR=""
while [ $# -gt 0 ]; do
    case "$1" in
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done
: "${OUTPUT_DIR:=$ROOT/dist}"

CACHE="${CONWRT_APK_CACHE:-$HOME/.cache/conwrt/apk}"
APK_TOOLS="$CACHE/apk-tools"
APK_BIN="$APK_TOOLS/src/apk"
APK_TOOLS_STAMP="$CACHE/apk-tools.built-sha"

# Pin apk-tools to the tag the compatibility claim is validated against
# (header above: 3.0.8-built packages install on device apk-tools 3.0.5).
# APK_TOOLS_SHA is the PEELED tag commit — rev-parse HEAD must match it,
# which verifies the pin offline, without re-fetching the tag.
APK_TOOLS_REF="${CONWRT_APK_TOOLS_REF:-v3.0.8}"
APK_TOOLS_SHA="${CONWRT_APK_TOOLS_SHA:-44dcdfc255c26a4e19a4a27f66a54169cce5ca72}"

ensure_apk_tools_checkout() {
    # #458: an interrupted first run used to wedge the cache forever — a
    # cloned-but-unbuilt tree fails the src/apk guard, and re-entering the
    # block `git clone`s into the nonempty directory. Reuse an existing
    # checkout via fetch/checkout; only when that fails, clean the partial
    # cache and reclone.
    if [ -d "$APK_TOOLS/.git" ]; then
        git -C "$APK_TOOLS" fetch --depth 1 --force origin \
            "refs/tags/$APK_TOOLS_REF:refs/tags/$APK_TOOLS_REF" \
        && git -C "$APK_TOOLS" checkout -q --force "$APK_TOOLS_REF" \
        && return 0
        echo "==> cached apk-tools checkout unusable — recloning" >&2
        rm -rf "$APK_TOOLS"
    fi
    git clone --depth 1 --branch "$APK_TOOLS_REF" \
        https://gitlab.alpinelinux.org/alpine/apk-tools.git "$APK_TOOLS"
}

# ── 1. Ensure host-built apk-tools (mkpkg), pinned ───────────────────
if [ ! -x "$APK_BIN" ] || [ "$(cat "$APK_TOOLS_STAMP" 2>/dev/null)" != "$APK_TOOLS_SHA" ]; then
    echo "==> building apk-tools $APK_TOOLS_REF (pinned $APK_TOOLS_SHA) — cached in $CACHE"
    mkdir -p "$CACHE"
    ensure_apk_tools_checkout \
        || { echo "error: apk-tools checkout failed" >&2; exit 1; }
    actual_sha="$(git -C "$APK_TOOLS" rev-parse HEAD)"
    [ "$actual_sha" = "$APK_TOOLS_SHA" ] \
        || { echo "error: apk-tools $APK_TOOLS_REF is $actual_sha, expected $APK_TOOLS_SHA (pinned)" >&2; exit 1; }
    chmod +x "$APK_TOOLS"/src/*.lua
    make -C "$APK_TOOLS" -j"$(nproc)"
    echo "$APK_TOOLS_SHA" > "$APK_TOOLS_STAMP"
fi

# ── 2. Cross-build the agent (stripped, static, soft-float) ──────────
if [ -n "${CONWRT_AGENT_BIN:-}" ] && [ -f "$CONWRT_AGENT_BIN" ]; then
    AGENT_BIN="$CONWRT_AGENT_BIN"
else
    "$SCRIPT_DIR/cross-mipsel.sh"
    AGENT_BIN="${CARGO_TARGET_DIR:-$ROOT/target}/mipsel-unknown-linux-musl/release/conwrt-agent"
fi
[ -f "$AGENT_BIN" ] || { echo "error: agent binary not found: $AGENT_BIN" >&2; exit 1; }

# ── 3. Version from git ──────────────────────────────────────────────
# apk-tools 3 validates versions strictly: numeric dotted components plus
# an optional '-r<digits>' release. Letter runs ('-alpha760', '_p760')
# and '+' are rejected, so a git hash cannot be embedded in the version.
# #458: commit height alone is NOT a unique identity — sibling branches
# share heights and shallow clones misreport. The unique revision is the
# commit SHA: embedded as the package's repo-commit info field (schema
# field, hex) and carried in the filename; the -r<height> stays numeric
# so apk accepts it and sorts builds correctly.
CARGO_VER="$(sed -n 's/^version *= *"\(.*\)"/\1/p' "$ROOT/Cargo.toml" | head -1)"
: "${CARGO_VER:=0.0.0}"
COMMIT_SHA=""
if git -C "$ROOT" rev-parse HEAD >/dev/null 2>&1; then
    COMMIT_HEIGHT="$(git -C "$ROOT" rev-list --count HEAD)"
    COMMIT_SHA="$(git -C "$ROOT" rev-parse HEAD)"
    VERSION="${CARGO_VER}-r${COMMIT_HEIGHT}"
else
    COMMIT_HEIGHT=0
    VERSION="${CARGO_VER}-r0"
fi

# ── 4. Stage and pack ────────────────────────────────────────────────
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
mkdir -p "$STAGING/usr/bin"
cp "$AGENT_BIN" "$STAGING/usr/bin/conwrt-agent"

mkdir -p "$OUTPUT_DIR"
if [ -n "$COMMIT_SHA" ]; then
    SHORT_SHA="$(printf %s "$COMMIT_SHA" | cut -c1-7)"
    OUT_APK="$OUTPUT_DIR/conwrt-agent-${VERSION}-g${SHORT_SHA}_mipsel_24kc.apk"
else
    OUT_APK="$OUTPUT_DIR/conwrt-agent-${VERSION}_mipsel_24kc.apk"
fi

set -- mkpkg \
    -F "$STAGING" \
    -o "$OUT_APK" \
    -I name:conwrt-agent \
    -I "version:${VERSION}" \
    -I arch:mipsel_24kc \
    -I "description:Conwrt on-device agent (postcard-rpc over COBS/TCP)" \
    -I license:MIT \
    -I origin:conwrt
if [ -n "$COMMIT_SHA" ]; then
    set -- "$@" -I "repo-commit:${COMMIT_SHA}"
fi

LD_LIBRARY_PATH="$APK_TOOLS/src" "$APK_BIN" "$@"

# ── 5. Report ────────────────────────────────────────────────────────
echo "==> built: $OUT_APK"
ls -la "$OUT_APK" | awk '{print "    size: " $5 " bytes"}'
sha256sum "$OUT_APK" | awk '{print "    sha256: " $1}'
echo "install on device (offline bench):"
echo "  scp -O '$OUT_APK' root@<device>:/tmp/"
echo "  apk add --no-network --allow-untrusted --force-non-repository /tmp/$(basename "$OUT_APK")"
