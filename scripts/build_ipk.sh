#!/bin/sh
# build_ipk.sh — Build architecture-independent conwrt ipk for OpenWrt
#
# Produces: conwrt_VERSION_all.ipk (e.g. conwrt_0.1.0-alpha.127+8ec5342_all.ipk)
#
# Usage:
#   ./scripts/build_ipk.sh [--output DIR]
#
# Requires: tar, ar (GNU ar or macOS ar), git
# No OpenWrt SDK needed — pure Python, arch-independent.
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${1:-}"

# ── Version from git ─────────────────────────────────────────────────
if [ -d "$ROOT/.git" ]; then
    COMMIT_HEIGHT="$(git -C "$ROOT" rev-list --count HEAD)"
    SHORT_HASH="$(git -C "$ROOT" rev-parse --short HEAD)"
    VERSION="0.0.0-alpha.${COMMIT_HEIGHT}+${SHORT_HASH}"
else
    VERSION="0.0.0-alpha.0+unknown"
fi

# Parse --output flag
while [ $# -gt 0 ]; do
    case "$1" in
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        *) shift ;;
    esac
done

: "${OUTPUT_DIR:=$ROOT/dist}"

PKG_NAME="conwrt"
PKG_VERSION="$VERSION"
IPK_FILENAME="${PKG_NAME}_${PKG_VERSION}_all.ipk"

echo "==> Building ${IPK_FILENAME}"

# ── Staging directory ────────────────────────────────────────────────
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT

DATA_DIR="$STAGING/data"
CTRL_DIR="$STAGING/control"

mkdir -p "$DATA_DIR/usr/share/conwrt"
mkdir -p "$DATA_DIR/usr/bin"
mkdir -p "$DATA_DIR/etc/conwrt/models"
mkdir -p "$CTRL_DIR"

# ── Install Python files ─────────────────────────────────────────────
# Core scripts
for f in "$SCRIPT_DIR"/*.py; do
    [ -f "$f" ] && cp "$f" "$DATA_DIR/usr/share/conwrt/"
done

# Sub-packages
for pkg in flash profile use_cases lib; do
    if [ -d "$SCRIPT_DIR/$pkg" ]; then
        mkdir -p "$DATA_DIR/usr/share/conwrt/$pkg"
        # Copy .py files only (no __pycache__)
        for f in "$SCRIPT_DIR/$pkg"/*.py; do
            [ -f "$f" ] && cp "$f" "$DATA_DIR/usr/share/conwrt/$pkg/"
        done
    fi
done

# Model definitions
if [ -d "$ROOT/models" ]; then
    for f in "$ROOT/models"/*.json; do
        [ -f "$f" ] && cp "$f" "$DATA_DIR/etc/conwrt/models/"
    done
fi

# openwrt-requirements.txt (for reference)
if [ -f "$SCRIPT_DIR/openwrt-requirements.txt" ]; then
    cp "$SCRIPT_DIR/openwrt-requirements.txt" "$DATA_DIR/usr/share/conwrt/"
fi

# ── Wrapper script ───────────────────────────────────────────────────
cat > "$DATA_DIR/usr/bin/conwrt" << 'WRAPPER'
#!/bin/sh
exec python3 /usr/share/conwrt/conwrt.py "$@"
WRAPPER
chmod 755 "$DATA_DIR/usr/bin/conwrt"

# ── Strip files not needed on router ─────────────────────────────────
# Remove dev/test/helper scripts that aren't core runtime
for skip in validate_models.py generate_matrix.py dlink_sge_sign.py \
            gs1920-repack-firmware.py gs1920-validate-zynos-openwrt.py \
            extreme_ap391x_analyze.py configure-stock-switch.py; do
    rm -f "$DATA_DIR/usr/share/conwrt/$skip"
done

# ── Control file ─────────────────────────────────────────────────────
# opkg dependencies — matches openwrt-requirements.txt
DEPENDS="python3-base, python3-light, python3-codecs, python3-ctypes, python3-email, python3-fcntl, python3-json, python3-logging, python3-openssl, python3-struct, python3-urllib, curl"

cat > "$CTRL_DIR/control" << EOF
Package: ${PKG_NAME}
Version: ${PKG_VERSION}
Depends: ${DEPENDS}
Source: https://github.com/Amperstrand/conwrt
Section: net
Priority: optional
Architecture: all
Installed-Size: $(du -sk "$DATA_DIR" | cut -f1)
Maintainer: Amperstrand <conwrt@amperstrand.no>
Description: OpenWrt router flashing, profiling, and device discovery.
 Runs on macOS and OpenWrt. Pure Python, no native compilation.
 Models in /etc/conwrt/models/ define supported devices.
EOF

# ── Post-install script ──────────────────────────────────────────────
cat > "$CTRL_DIR/postinst" << 'POSTINST'
#!/bin/sh
# Ensure wrapper is executable
[ -x /usr/bin/conwrt ] && chmod 755 /usr/bin/conwrt
# Ensure model files are readable
chmod -R a+rX /etc/conwrt/models/ 2>/dev/null
POSTINST
chmod 755 "$CTRL_DIR/postinst"

# ── Build ipk ────────────────────────────────────────────────────────
echo "2.0" > "$STAGING/debian-binary"

# control.tar.gz
(cd "$STAGING" && tar czf control.tar.gz -C "$CTRL_DIR" .)

# data.tar.gz
(cd "$STAGING" && tar czf data.tar.gz -C "$DATA_DIR" .)

# Assemble ipk (ar archive)
IPK_PATH="$OUTPUT_DIR/$IPK_FILENAME"
mkdir -p "$OUTPUT_DIR"
(cd "$STAGING" && ar rcs "$IPK_PATH" debian-binary control.tar.gz data.tar.gz)

# ── Summary ──────────────────────────────────────────────────────────
SIZE=$(du -sk "$IPK_PATH" | cut -f1)
FILE_COUNT=$(find "$DATA_DIR" -type f | wc -l | tr -d ' ')
echo ""
echo "==> Built: $IPK_PATH"
echo "    Version: $PKG_VERSION"
echo "    Size:    ${SIZE}KB"
echo "    Files:   $FILE_COUNT"
echo ""
echo "Install on OpenWrt:"
echo "  scp -O $IPK_PATH root@<router>:/tmp/"
echo "  ssh root@<router> 'opkg install /tmp/${IPK_FILENAME}'"
echo ""
echo "Or from GitHub Release:"
echo "  curl -L <release-url> -o /tmp/conwrt.ipk"
echo "  opkg install /tmp/conwrt.ipk"
