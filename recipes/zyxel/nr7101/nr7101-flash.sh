#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# ═══════════════════════════════════════════════════════════════════════════════
# nr7101-flash.sh — Flash OpenWrt onto a Zyxel NR7101 via serial-triggered zycast
#
# This is the all-in-one script for the NR7101 flash procedure. Each section is
# self-contained and documented inline. You can either run the whole script or
# copy-paste individual sections.
#
# PREREQUISITES:
#   - USB-serial adapter (FTDI FT232R, CP2102, or CH340) at 3.3V
#   - Ethernet cable + 802.3at PoE injector
#   - Mac with USB GigE adapter
#   - NR7101 case opened, serial header J5 exposed
#   - OpenWrt initramfs-recovery image downloaded to images/
#
# NR7101 SERIAL HEADER (J5):
#   Pin 1: GND  ──── adapter GND
#   Pin 2: (key — no pin)
#   Pin 3: RX   ──── adapter TX
#   Pin 4: TX   ──── adapter RX
#   Pin 5: 3.3V ──── DO NOT CONNECT (PoE powers the device)
#
# BAUD RATE: 57600 8N1 (NOT 115200 — confirmed from OpenWrt device tree)
#
# WHAT THIS SCRIPT DOES:
#   1. Verifies prerequisites (adapter, firmware, interface)
#   2. Runs adapter health diagnostics
#   3. Starts serial monitor (logs to serial/<session>/)
#   4. Starts zycast multicast sender
#   5. Waits for user to power on device + send Escape at Z-Loader
#   6. Monitors for device boot at 192.168.1.1
#   7. Kills zycast when device appears
#   8. Verifies SSH, runs conwrt configure
#
# WHAT ZYCAST OVERWRITES:
#   - mtd3 (Kernel) and mtd5 (Kernel2) — both slots overwritten
#   - mtd2 (Factory) — NOT touched (MAC, serial, calibration preserved)
#   Stock firmware cannot be recovered after flash.
#
# ═══════════════════════════════════════════════════════════════════════════════

# --- Paths and defaults ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERIAL_PORT="${SERIAL_PORT:-}"
INTERFACE="${INTERFACE:-en8}"
BAUD=57600
TARGET_IP="192.168.1.1"
FIRMWARE="${FIRMWARE:-$SCRIPT_DIR/images/openwrt-25.12.4-ramips-mt7621-zyxel_nr7101-initramfs-recovery.bin}"
SESSION="nr7101-flash-$(date +%Y%m%d-%H%M%S)"

# --- Colors ---
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BOLD='\033[1m'; BLUE='\033[0;34m'; RESET='\033[0m'
else
    RED='' GREEN='' YELLOW='' BOLD='' BLUE='' RESET=''
fi

step()  { echo -e "\n${BLUE}═══${RESET} ${BOLD}$*${RESET} ${BLUE}═══${RESET}"; }
ok()    { echo -e "  ${GREEN}✓${RESET} $*"; }
warn()  { echo -e "  ${YELLOW}⚠${RESET} $*"; }
fail()  { echo -e "  ${RED}✗${RESET} $*" >&2; exit 1; }
info()  { echo -e "  $*"; }

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Flash OpenWrt onto a Zyxel NR7101 via serial-triggered zycast.

Options:
    --port PATH        Serial port (auto-detected if omitted)
    --interface IFACE  Ethernet interface (default: en8)
    --firmware PATH    Path to initramfs-recovery .bin
    --session NAME     Session name for logs (default: nr7101-flash-<timestamp>)
    --diagnose-only    Run adapter diagnostics and exit
    --skip-diagnose    Skip adapter diagnostics
    --help, -h         Show this message

Environment variables:
    SERIAL_PORT        Same as --port
    INTERFACE          Same as --interface
    FIRMWARE           Same as --firmware

EOF
    exit 0
}

# ─── Parse arguments ──────────────────────────────────────────────────────────
DIAGNOSE_ONLY=false
SKIP_DIAGNOSE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)        SERIAL_PORT="$2"; shift 2 ;;
        --interface)   INTERFACE="$2"; shift 2 ;;
        --firmware)    FIRMWARE="$2"; shift 2 ;;
        --session)     SESSION="$2"; shift 2 ;;
        --diagnose-only) DIAGNOSE_ONLY=true; shift ;;
        --skip-diagnose) SKIP_DIAGNOSE=true; shift ;;
        --help|-h)     usage ;;
        *)             fail "Unknown option: $1" ;;
    esac
done

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1: PREREQUISITES
# Verify the firmware image exists, the serial port is available, and the
# ethernet interface is up. Missing any of these means the flash will fail.
# ═══════════════════════════════════════════════════════════════════════════════
step "1/8 — Prerequisites"

# Check firmware image exists
if [[ ! -f "$FIRMWARE" ]]; then
    fail "Firmware not found: $FIRMWARE"
fi
FW_SIZE=$(stat -f%z "$FIRMWARE" 2>/dev/null || stat -c%s "$FIRMWARE" 2>/dev/null)
ok "Firmware: $FIRMWARE ($((FW_SIZE / 1024 / 1024))MB)"

# Verify firmware is an initramfs-recovery image (not sysupgrade)
if [[ "$FIRMWARE" != *"initramfs"* ]]; then
    fail "Firmware must be initramfs-recovery, not sysupgrade. Expected: *-initramfs-recovery.bin"
fi
ok "Firmware type: initramfs-recovery"

# Verify firmware checksum
FW_HASH=$(shasum -a 256 "$FIRMWARE" 2>/dev/null | awk '{print $1}' || md5sum "$FIRMWARE" 2>/dev/null | awk '{print $1}')
ok "Checksum: ${FW_HASH:0:16}..."

# Auto-detect serial port if not specified
if [[ -z "$SERIAL_PORT" ]]; then
    info "Auto-detecting serial port..."
    SERIAL_PORT=$("$SCRIPT_DIR/.venv/bin/python3" "$SCRIPT_DIR/scripts/serial-console.py" --list 2>&1 \
        | grep "usbserial" | head -1 | awk '{print $2}' | sed 's/\.$//')
    if [[ -z "$SERIAL_PORT" ]]; then
        fail "No serial port found. Connect adapter and retry, or use --port"
    fi
    warn "Auto-detected: $SERIAL_PORT (override with --port)"
else
    ok "Serial port: $SERIAL_PORT"
fi

# Check ethernet interface is up
IFACE_STATUS=$(ifconfig "$INTERFACE" 2>/dev/null | grep "status:" | awk '{print $2}')
if [[ "$IFACE_STATUS" != "active" ]]; then
    warn "Interface $INTERFACE not active (status: ${IFACE_STATUS:-missing})"
    warn "Connect ethernet cable + PoE injector before continuing"
else
    ok "Interface $INTERFACE: active"
fi

[[ "$DIAGNOSE_ONLY" == "true" ]] && exit 0

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2: ADAPTER DIAGNOSTICS
# Run serial-console.py --diagnose to verify the adapter is healthy before
# connecting to the device. This checks chip type, signal lines, and noise.
# ═══════════════════════════════════════════════════════════════════════════════
step "2/8 — Adapter Diagnostics"

if [[ "$SKIP_DIAGNOSE" == "true" ]]; then
    warn "Skipping diagnostics (--skip-diagnose)"
else
    "$SCRIPT_DIR/.venv/bin/python3" "$SCRIPT_DIR/scripts/serial-console.py" --diagnose "$SERIAL_PORT" 2>&1 || true
    echo ""
    info "If diagnostics show problems, fix them before continuing."
    info "For loopback test: bridge TX→RX and run:"
    info "  serial-console.py $SERIAL_PORT --loopback"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3: NETWORK SETUP
# Configure the Mac's ethernet interface with IP aliases for zycast sending
# and post-flash access. Add a host route so 192.168.1.1 goes via enX, not WiFi.
# ═══════════════════════════════════════════════════════════════════════════════
step "3/8 — Network Setup"

# Add IP alias for zycast multicast source
if ! ifconfig "$INTERFACE" | grep -q "192.168.2.10" 2>/dev/null; then
    sudo ifconfig "$INTERFACE" inet 192.168.2.10/24 alias && ok "Added 192.168.2.10 to $INTERFACE" \
        || warn "Could not add IP alias (may already exist)"
else
    ok "192.168.2.10 already on $INTERFACE"
fi

# Add host route for post-flash access (192.168.1.1 via enX, not WiFi)
if ! route -n get "$TARGET_IP" 2>/dev/null | grep -q "interface: $INTERFACE"; then
    sudo route add -host "$TARGET_IP" -interface "$INTERFACE" 2>/dev/null \
        && ok "Route: $TARGET_IP via $INTERFACE" || warn "Route may already exist"
else
    ok "Route: $TARGET_IP via $INTERFACE (already set)"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 4: START SERIAL MONITOR
# Launch serial-console.py in tmux to capture all boot output. The monitor
# logs to serial/<session>/ with dual logging (human-readable + raw bytes).
# Boot stage detection automatically flags Z-Loader, kernel, OpenWrt stages.
# ═══════════════════════════════════════════════════════════════════════════════
step "4/8 — Start Serial Monitor"

tmux kill-session -t serial 2>/dev/null || true
tmux new-session -d -s serial -x 200 -y 50 \
    "cd $SCRIPT_DIR && .venv/bin/python3 scripts/serial-console.py \
        $SERIAL_PORT --baud $BAUD --monitor --session $SESSION 2>&1; \
     echo 'Serial monitor exited'; sleep 999999"

ok "Serial monitor running in tmux:serial (baud: $BAUD)"
info "View:    tmux attach -t serial"
info "Send ESC: printf 'ESCAPE' > /tmp/conwrt-serial-cmd"
info "Logs:    serial/$SESSION/"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 5: START ZYCAST SENDER
# Launch zycast_macos.py to continuously send firmware via multicast on
# 225.0.0.0:5631. The bootloader receives this when Z-Loader is active.
# Each loop takes ~75s. The bootloader needs 2-3 complete loops.
# ═══════════════════════════════════════════════════════════════════════════════
step "5/8 — Start Zycast Sender"

tmux kill-session -t zycast 2>/dev/null || true
tmux new-session -d -s zycast -x 200 -y 25 \
    "cd $SCRIPT_DIR && .venv/bin/python3 scripts/zycast_macos.py \
        '$FIRMWARE' 192.168.2.10 2>&1; \
     echo 'Zycast exited'; sleep 999999"

sleep 2
ZYCAST_PID=$(pgrep -f zycast_macos || true)
if [[ -n "$ZYCAST_PID" ]]; then
    ok "Zycast running in tmux:zycast (PID: $ZYCAST_PID)"
    info "View: tmux attach -t zycast"
else
    fail "Zycast failed to start"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 6: POWER ON + ENTER Z-LOADER
# This is the critical manual step. Power on the NR7101 and immediately
# watch the serial monitor for the Z-Loader banner. When you see
# "Press any key" or "Z-LOADER", send Escape via the command FIFO.
#
# The bootloader only listens for multicast WHEN Z-LOADER IS ACTIVE.
# Without this step, zycast multicast is completely ignored.
# ═══════════════════════════════════════════════════════════════════════════════
step "6/8 — Power On + Enter Z-Loader"

echo ""
echo -e "  ${BOLD}━━━ MANUAL ACTION REQUIRED ━━━${RESET}"
echo ""
echo -e "  1. ${BOLD}Power on the NR7101${RESET} (plug in PoE injector power)"
echo -e "  2. Watch tmux:serial for boot output:"
echo -e "     ${BLUE}tmux attach -t serial${RESET}"
echo -e "  3. When you see ${BOLD}\"Z-LOADER\"${RESET} or ${BOLD}\"Press any key\"${RESET}:"
echo -e "     ${BLUE}printf 'ESCAPE' > /tmp/conwrt-serial-cmd${RESET}"
echo -e "  4. Z-Loader should show ${BOLD}\"Multiboot Listening...\"${RESET}"
echo -e "  5. Zycast delivers firmware (~3 min for 2-3 loops)"
echo -e "  6. Watch for ${BOLD}kernel boot${RESET} on serial — flash succeeded"
echo ""
echo -e "  ${BOLD}━━━ PRESS ENTER WHEN DEVICE RESPONDS AT $TARGET_IP ━━━${RESET}"
echo -e "  (timeout: 10 min, or Ctrl-C to abort)"
echo ""

# Auto-detect device boot while waiting for manual confirmation
DETECTED=false
for i in $(seq 1 600); do
    if ping -c 1 -t 1 "$TARGET_IP" >/dev/null 2>&1; then
        DETECTED=true
        ok "Device detected at $TARGET_IP after ${i}s!"
        break
    fi
    if ! read -t 1 -r 2>/dev/null && [[ "$DETECTED" == "false" ]]; then
        continue
    else
        DETECTED=true
        break
    fi
done

[[ "$DETECTED" == "false" ]] && fail "Timeout waiting for device at $TARGET_IP"

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 7: VERIFY DEVICE + KILL ZYCAST
# Once the device responds at 192.168.1.1, the flash succeeded. Kill zycast
# IMMEDIATELY — the bootloader listens on every Z-Loader entry, and a running
# zycast will reflash on any reboot that enters Z-Loader.
# ═══════════════════════════════════════════════════════════════════════════════
step "7/8 — Verify Device + Kill Zycast"

# Check if device responds
if ping -c 1 -t 3 "$TARGET_IP" >/dev/null 2>&1; then
    MAC=$(arp -i "$INTERFACE" "$TARGET_IP" 2>/dev/null | awk '{print $4}')
    ok "Device responding at $TARGET_IP (MAC: ${MAC:-unknown})"
else
    fail "Device not responding at $TARGET_IP. Check serial output."
fi

# KILL ZYCAST — critical safety step
echo ""
warn "Killing zycast (bootloader listens on every Z-Loader entry!)"
tmux kill-session -t zycast 2>/dev/null || pkill -f zycast_macos 2>/dev/null || true
ok "Zycast killed"

# Verify no zycast processes remain
sleep 1
if pgrep -f zycast_macos >/dev/null 2>&1; then
    fail "Zycast still running! Kill manually: pkill -9 -f zycast_macos"
fi
ok "No zycast processes remaining"

# Wait for device to fully boot (SSH may take 30-60s after first ping)
info "Waiting for SSH to come up (up to 90s)..."
SSH_READY=false
for i in $(seq 1 45); do
    if ssh -o ConnectTimeout=2 -o StrictHostKeyChecking=no \
          -o PasswordAuthentication=no \
          "root@$TARGET_IP" "true" 2>/dev/null; then
        SSH_READY=true
        ok "SSH ready after ${i}x2s"
        break
    fi
    sleep 2
done

if [[ "$SSH_READY" == "true" ]]; then
    ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
        -o PasswordAuthentication=no \
        "root@$TARGET_IP" "cat /etc/openwrt_release; echo; uname -a" 2>/dev/null
    ok "SSH verified — OpenWrt is running!"
else
    warn "SSH not ready after 90s — device may still be booting"
    warn "Retry in 30s: ssh root@$TARGET_IP"
fi

# ═══════════════════════════════════════════════════════════════════════════════
# STEP 8: CONWRT CONFIGURE
# Run conwrt configure to set up the device with MAC-hash deterministic IP,
# WiFi/AP configuration, and operator profile. This is the post-flash setup
# that makes the device production-ready.
# ═══════════════════════════════════════════════════════════════════════════════
step "8/8 — conwrt configure"

echo ""
info "Run conwrt configure with MAC-hash IP:"
echo ""
echo -e "  ${BLUE}cd $SCRIPT_DIR${RESET}"
echo -e "  ${BLUE}.venv/bin/python3 scripts/conwrt.py configure \\${RESET}"
echo -e "    ${BLUE}--model-id zyxel-nr7101 \\${RESET}"
echo -e "    ${BLUE}--interface $INTERFACE \\${RESET}"
echo -e "    ${BLUE}--ip $TARGET_IP \\${RESET}"
echo -e "    ${BLUE}--lan-ip-mode mac-hash \\${RESET}"
echo -e "    ${BLUE}--wifi-disable${RESET}"
echo ""

# Stop serial monitor
tmux kill-session -t serial 2>/dev/null || true
ok "Serial monitor stopped"

echo ""
ok "═══ Flash complete! ═══"
info "Serial logs: serial/$SESSION/"
info "Inventory: data/inventory.jsonl"
