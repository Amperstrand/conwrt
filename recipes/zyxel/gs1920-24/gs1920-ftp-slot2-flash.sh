#!/usr/bin/env bash
# gs1920-ftp-slot2-flash.sh
#
# Flash stock ZyXel firmware to slot 2 of a GS1920-24 via FTP.
# Bypasses the web CGI "occupancy gate" that blocks re-uploading to
# occupied non-active firmware slots.
#
# WHY THIS EXISTS:
#   The web upload handler (/Forms/fwUpgrade_2) has an implicit occupancy
#   gate: it reads the target slot's flash partition, validates the firmware
#   header (signature + checksum), and silently rejects (no HTTP response)
#   if the slot has valid firmware AND is not the active boot slot.
#   This gate cannot be reset — it checks flash content, not a flag.
#
#   The FTP upload handler is a completely separate code path with different
#   validation (length, checksum, model/version, downgrade). It writes
#   directly to ras-0/ras-1 flash targets and likely does NOT check
#   slot occupancy.
#
# PREREQUISITES:
#   - Switch at 192.168.1.1, admin:1234, running (slot 1 = V4.10)
#   - Stock firmware: stock-v450.bin in project root (3,677,044 bytes)
#   - curl with FTP support
#
# USAGE:
#   ./recipes/zyxel/gs1920-ftp-slot2-flash.sh
#
# RISK: LOW for this step (FTP upload to slot 2).
#   Slot 2 is non-active. Even if upload fails, slot 1 still boots.
#   Slot 2 is already non-booting, so worst case = no change.
#
# AFTER UPLOAD:
#   - Verify on fwUpgrade.html that slot 2 shows new version
#   - Stock V4.50 has mmap_addr=0xb40e0000 (slot 1's address)
#   - BootBase may still reject booting from slot 2 due to mmap_addr mismatch
#   - The GOAL of this step is to confirm FTP bypasses the occupancy gate
#     and get known-good firmware onto slot 2

set -euo pipefail

SWITCH_IP="${SWITCH_IP:-192.168.1.1}"
SWITCH_USER="${SWITCH_USER:-admin}"
SWITCH_PASS="${SWITCH_PASS:-1234}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
FIRMWARE="${FIRMWARE:-$PROJECT_ROOT/stock-v450.bin}"
TARGET_FILE="${TARGET_FILE:-ras-1}"  # ras-0 = slot 1, ras-1 = slot 2

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[-]${NC} $*"; }

# --- Pre-flight checks ---

if [[ ! -f "$FIRMWARE" ]]; then
    err "Firmware not found: $FIRMWARE"
    err "Set FIRMWARE= path or place stock-v450.bin in project root"
    exit 1
fi

SIZE=$(wc -c < "$FIRMWARE")
log "Firmware: $FIRMWARE ($SIZE bytes)"

if ! curl -s --connect-timeout 5 "http://$SWITCH_IP/" > /dev/null 2>&1; then
    err "Switch not reachable at http://$SWITCH_IP/"
    err "Connect the switch and verify IP"
    exit 1
fi
log "Switch reachable at $SWITCH_IP"

# --- Step 1: Enable FTP via Access Service page ---

log "Step 1: Enabling FTP on the switch..."

# Login first to get a session cookie
LOGIN_COOKIE="/tmp/gs1920-ftp-cookie.txt"
curl -s -c "$LOGIN_COOKIE" -b "$LOGIN_COOKIE" \
    -X POST \
    "http://$SWITCH_IP/Forms/login_standalone_1" \
    -d "Username=$SWITCH_USER" \
    -d "Password=$SWITCH_PASS" \
    -d "Login=Login" \
    -L \
    -o /dev/null \
    -w "%{http_code}" || true

# Enable FTP via Access Service form
# RpAccessSv_ChkFTP=on enables the FTP service
HTTP_CODE=$(curl -s -b "$LOGIN_COOKIE" \
    -X POST \
    "http://$SWITCH_IP/Forms/rpaccessservice_1" \
    -d "RpAccessSv_ChkFTP=on" \
    -d "RpGeneral_IptTextFTPPort=21" \
    -d "RpAccessSv_ChkTelnet=on" \
    -d "RpGeneral_IptTextTelnetPort=23" \
    -d "RpAccessSv_ChkWeb=on" \
    -d "RpAccessSv_ChkSNMP=on" \
    -d "RpAccessSv_BtnApply=Apply" \
    -o /dev/null \
    -w "%{http_code}" || true)

if [[ "$HTTP_CODE" == "303" || "$HTTP_CODE" == "200" ]]; then
    log "FTP service enabled (HTTP $HTTP_CODE)"
else
    warn "Unexpected HTTP $HTTP_CODE when enabling FTP (continuing anyway)"
fi

# --- Step 2: Verify FTP is accessible ---

log "Step 2: Testing FTP connection..."

sleep 2  # Give the FTP service time to start

if curl -s --ftp-port "${FTP_ACTIVE_IP:--}" --connect-timeout 5 "ftp://$SWITCH_USER:$SWITCH_PASS@$SWITCH_IP:21/" > /tmp/gs1920-ftp-dir.txt 2>&1; then
    log "FTP connection successful. Directory listing:"
    cat /tmp/gs1920-ftp-dir.txt
else
    err "FTP connection failed!"
    err "The FTP service may not have started. Try accessing /rpaccessservice.html manually."
    err "Falling back to direct FTP attempt..."
fi

# --- Step 3: Upload firmware to slot 2 via FTP ---

log "Step 3: Uploading firmware to slot 2 ($TARGET_FILE) via FTP..."
log "Firmware: $FIRMWARE ($SIZE bytes)"
log "Target: ftp://$SWITCH_IP/$TARGET_FILE"
echo ""

# The FTP PUT writes directly to the ras-1 flash target
# The FTP handler validates: length, checksum, product model/version
# It does NOT appear to have the occupancy gate
set +e
UPLOAD_RESULT=$(curl -v \
    -T "$FIRMWARE" \
    "ftp://$SWITCH_USER:$SWITCH_PASS@$SWITCH_IP:21/$TARGET_FILE" \
    --ftp-port "${FTP_ACTIVE_IP:--}" \
    --connect-timeout 10 \
    --max-time 300 \
    2>&1)
UPLOAD_STATUS=$?
set -e

echo "$UPLOAD_RESULT"

if [[ "$UPLOAD_STATUS" -eq 0 ]] && echo "$UPLOAD_RESULT" | grep -qi "226 File received OK\|transfer complete\|uploaded\|successful"; then
    log "UPLOAD SUCCESSFUL!"
    echo ""
    log "Next steps:"
    log "  1. Check http://$SWITCH_IP/fwUpgrade.html to verify slot 2 firmware version"
    log "  2. If slot 2 shows V4.50(AAOB.3), the FTP path bypasses the occupancy gate"
    log "  3. Test boot from slot 2:"
    log "     curl -b cookie -X POST http://$SWITCH_IP/Forms/fwUpgrade_1 \\"
    log "       -d 'Rpconfig_boot_image_Text=2' -d 'RpConfig_image_HidBtnNum=1'"
    log "     curl -b cookie -X POST http://$SWITCH_IP/Forms/rpmaintain_1 \\"
    log "       -d 'RpMaintain_HidRebootSys=1'"
    log ""
    warn "NOTE: Stock V4.50 has mmap_addr=0xb40e0000 (slot 1 address)."
    warn "      BootBase may still reject booting from slot 2."
    warn "      The key outcome is confirming FTP upload works to occupied slot 2."
else
    err "UPLOAD FAILED"
    echo ""
    err "FTP error output above. curl exit status: $UPLOAD_STATUS"
    err ""
    err "Possible causes:"
    err "  - FTP service not enabled (check /rpaccessservice.html)"
    err "  - Wrong credentials (default: admin/1234)"
    err "  - Firmware rejected by FTP handler (checksum, model mismatch)"
    err "  - FTP handler has its own occupancy gate (unknown)"
    echo ""
    err "Try manual FTP:"
    err "  ftp $SWITCH_IP"
    err "  Name: $SWITCH_USER  Password: $SWITCH_PASS"
    err "  ftp> bin"
    err "  ftp> put $FIRMWARE $TARGET_FILE"
fi

# Cleanup
rm -f "$LOGIN_COOKIE" /tmp/gs1920-ftp-dir.txt /tmp/gs1920-ftp-cookie.txt
