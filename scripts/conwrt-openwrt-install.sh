#!/bin/sh
# conwrt-openwrt-install — Deploy conwrt to an OpenWrt router
#
# Usage:
#   From a computer with conwrt source:
#     ./scripts/conwrt-openwrt-install.sh root@192.168.1.1 [/tmp/conwrt]
#
#   Or copy this script to the router and run locally:
#     sh conwrt-openwrt-install.sh
#
# The script:
#   1. Installs Python dependencies via opkg
#   2. Copies scripts/ and models/ to the target
#   3. Verifies the installation with a smoke test

set -e

TARGET="${1:-}"
INSTALL_DIR="${2:-/tmp/conwrt}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REQUIREMENTS="$SCRIPT_DIR/openwrt-requirements.txt"

# If TARGET contains @, it's a remote host — deploy via scp/ssh
if echo "$TARGET" | grep -q '@'; then
    REMOTE="$TARGET"

    echo "==> Installing dependencies on $REMOTE..."
    ssh "$REMOTE" "opkg update && opkg install \$(grep -v '^#' /dev/stdin | grep -v '^$')" < "$REQUIREMENTS"

    echo "==> Copying conwrt to $REMOTE:$INSTALL_DIR..."
    ssh "$REMOTE" "mkdir -p $INSTALL_DIR"
    scp -r "$SCRIPT_DIR/" "$REMOTE:$INSTALL_DIR/scripts/"
    scp -r "$SCRIPT_DIR/../models/" "$REMOTE:$INSTALL_DIR/models/"

    echo "==> Verifying installation..."
    ssh "$REMOTE" "cd $INSTALL_DIR/scripts && python3 conwrt.py list"
    echo ""
    echo "Installed to $REMOTE:$INSTALL_DIR"
    echo "Run: ssh $REMOTE"
    echo "Then: cd $INSTALL_DIR/scripts && python3 conwrt.py flash --model-id <model> --image /tmp/firmware.bin --no-voice"
    exit 0
fi

# Local installation (running on the router itself)
echo "==> Installing dependencies..."
opkg update
opkg install $(grep -v '^#' "$REQUIREMENTS" | grep -v '^')

echo "==> Files should be in $INSTALL_DIR"
echo "==> Verifying..."
cd "$INSTALL_DIR/scripts"
python3 conwrt.py list

echo ""
echo "Ready. Run: python3 conwrt.py flash --model-id <model> --image /tmp/firmware.bin --no-voice"
