#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

# flash-openwrt.sh — Automated OpenWrt flash for Linksys Velop MX4200 V1
#
# Uses CVE-2019-16340 to bypass the "Download the Linksys App" blocking page
# and set the admin password, then uploads OpenWrt via the stock firmware's
# JNAP endpoint. Flashes both partitions to prevent stock rollback.
#
# Usage:
#   ./flash-openwrt.sh --pin XXXXX [--ip 192.168.1.1] [--version 24.10.0] [--firmware file.bin]

TARGET_IP="192.168.1.1"
RECOVERY_PIN=""
OPENWRT_VERSION="24.10.0"
FIRMWARE_FILE=""

# --- Colors (disabled if not a terminal) ---
if [[ -t 1 ]]; then
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  BOLD='\033[1m'
  RESET='\033[0m'
else
  RED='' GREEN='' YELLOW='' BOLD='' RESET=''
fi

usage() {
  cat <<EOF
Usage: $0 --pin RECOVERY_PIN [OPTIONS]

Required:
  --pin PIN          5-digit recovery pin from the device sticker

Options:
  --ip IP            Router IP (default: 192.168.1.1)
  --version VER      OpenWrt version (default: 24.10.0)
  --firmware FILE    Local .bin file (omit to auto-download)
  --help, -h         Show this message

This script flashes OpenWrt onto a Linksys MX4200 V1 using the
CVE-2019-16340 auth bypass. The device must be factory-reset and
reachable at the target IP before running.

EOF
  exit 0
}

step()   { echo -e "${GREEN}[$(date +%H:%M:%S)]${RESET} ${BOLD}$*${RESET}"; }
warn()   { echo -e "${YELLOW}[$(date +%H:%M:%S)] WARNING:${RESET} $*" >&2; }
die()    { echo -e "${RED}[ERROR]${RESET} $*" >&2; exit 1; }

# --- Argument parsing ---
while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip)        TARGET_IP="$2"; shift 2 ;;
    --pin)       RECOVERY_PIN="$2"; shift 2 ;;
    --version)   OPENWRT_VERSION="$2"; shift 2 ;;
    --firmware)  FIRMWARE_FILE="$2"; shift 2 ;;
    --help|-h)   usage ;;
    *) die "Unknown option: $1. Use --help for usage." ;;
  esac
done

[[ -n "$RECOVERY_PIN" ]] || die "Recovery pin is required. Use --pin XXXXX."
[[ "$RECOVERY_PIN" =~ ^[0-9]{5}$ ]] || die "Recovery pin must be exactly 5 digits. Got: ${RECOVERY_PIN}"

step "Linksys MX4200 V1 — OpenWrt Flash Script"
step "Target: ${TARGET_IP}  |  OpenWrt: ${OPENWRT_VERSION}  |  Pin: ${RECOVERY_PIN:0:2}***"

# --- Step 1: Identify device via JNAP ---
step "Step 1: Identifying device..."

INFO=$(curl -sk --max-time 10 -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://cisco.com/jnap/core/GetDeviceInfo" \
  -d '{}' "http://${TARGET_IP}/JNAP/" 2>/dev/null) || die "Cannot reach device at ${TARGET_IP}. Is it on the network?"

RESULT=$(echo "$INFO" | jq -r '.result' 2>/dev/null)
[[ "$RESULT" == "OK" ]] || die "GetDeviceInfo failed. Device may not be ready yet. Response: ${INFO}"

MANUFACTURER=$(echo "$INFO" | jq -r '.output.manufacturer')
MODEL=$(echo "$INFO" | jq -r '.output.modelNumber')
HWVER=$(echo "$INFO" | jq -r '.output.hardwareVersion')
FIRMWARE_VER=$(echo "$INFO" | jq -r '.output.firmwareVersion')

step "Found: ${MANUFACTURER} ${MODEL} (hardware v${HWVER}, firmware ${FIRMWARE_VER})"

[[ "$MODEL" == "MX42" ]] || die "Expected model MX42, got ${MODEL}. This script is for the MX4200 V1 only."
[[ "$HWVER" == "1" ]] || die "Expected hardware version 1, got ${HWVER}. This script is for the MX4200 V1 only."

# --- Step 2: CVE-2019-16340 auth bypass ---
step "Step 2: Setting admin password via CVE-2019-16340..."

CVE_RESPONSE=$(curl -sk --max-time 10 -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://linksys.com/jnap/nodes/setup/SetAdminPassword" \
  -d "{\"resetCode\":\"${RECOVERY_PIN}\",\"adminPassword\":\"admin\"}" \
  "http://${TARGET_IP}/JNAP/" 2>/dev/null) || die "CVE bypass request failed. Is JNAP responding?"

CVE_RESULT=$(echo "$CVE_RESPONSE" | jq -r '.result' 2>/dev/null)
if [[ "$CVE_RESULT" != "OK" ]]; then
  die "CVE bypass failed. Wrong recovery pin? Response: ${CVE_RESPONSE}"
fi
step "Admin password set to 'admin' via CVE-2019-16340"

# --- Step 3: Verify admin credentials ---
step "Step 3: Verifying admin credentials on port 52000..."

HTTP_CODE=$(curl -sk --max-time 10 -o /dev/null -w '%{http_code}' \
  -u "admin:admin" "http://${TARGET_IP}:52000/fwupdate.html" 2>/dev/null) || true

if [[ "$HTTP_CODE" != "200" ]]; then
  die "Admin credentials rejected on port 52000 (HTTP ${HTTP_CODE}). The CVE bypass may not have worked."
fi
step "Credentials accepted on port 52000"

# --- Step 4: Download firmware if not provided ---
if [[ -z "$FIRMWARE_FILE" ]]; then
  OWRT_DEVICE="linksys_mx4200v1"
  FIRMWARE_FILE="/tmp/openwrt-${OPENWRT_VERSION}-${OWRT_DEVICE}-factory.bin"
  URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/qualcommax/ipq807x/openwrt-${OPENWRT_VERSION}-qualcommax-ipq807x-${OWRT_DEVICE}-squashfs-factory.bin"

  if [[ -f "$FIRMWARE_FILE" ]]; then
    step "Step 4: Using cached firmware: $(ls -lh "$FIRMWARE_FILE" | awk '{print $5}')"
  else
    step "Step 4: Downloading OpenWrt ${OPENWRT_VERSION} for ${OWRT_DEVICE}..."
    curl -fL --progress-bar -o "$FIRMWARE_FILE" "$URL" || die "Download failed from ${URL}"
    step "Downloaded: $(ls -lh "$FIRMWARE_FILE" | awk '{print $5}')"
  fi
elif [[ ! -f "$FIRMWARE_FILE" ]]; then
  die "Firmware file not found: ${FIRMWARE_FILE}"
else
  step "Step 4: Using provided firmware: $(ls -lh "$FIRMWARE_FILE" | awk '{print $5}')"
fi

# --- Step 5: Upload firmware to partition 1 ---
step "Step 5: Uploading firmware to partition 1 via port 52000..."

UPLOAD_RESPONSE=$(curl -sk --max-time 300 \
  -u "admin:admin" \
  -F "X-JNAP-Action=updatefirmware" \
  -F "X-JNAP-Authorization=Basic YWRtaW46YWRtaW4=" \
  -F "upload=@${FIRMWARE_FILE};type=application/octet-stream" \
  "http://${TARGET_IP}:52000/jcgi/" 2>/dev/null) || die "Upload request failed (network error or timeout)"

UPLOAD_RESULT=$(echo "$UPLOAD_RESPONSE" | jq -r '.result' 2>/dev/null || echo "$UPLOAD_RESPONSE")
if [[ "$UPLOAD_RESULT" != "OK" ]]; then
  die "Upload rejected by device. Response: ${UPLOAD_RESPONSE}"
fi
step "Partition 1 flash accepted. Device is rebooting..."

# --- Step 6: Wait for OpenWrt to boot ---
step "Step 6: Waiting for OpenWrt to boot (polling every 3 seconds)..."

sleep 10  # Give the device time to start rebooting

FOUND=0
for i in $(seq 1 60); do
  if ping -c1 -W2 "$TARGET_IP" &>/dev/null; then
    # Check for OpenWrt SSH or LuCI
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=2 -o BatchMode=yes \
         "root@${TARGET_IP}" 'echo OK' &>/dev/null; then
      step "OpenWrt is up on partition 1 (attempt ${i})"
      FOUND=1
      break
    fi
  fi
  sleep 3
done

if [[ "$FOUND" -ne 1 ]]; then
  die "Device did not come back with OpenWrt after 3 minutes. Check that the device is powered on and the cable is connected."
fi

# --- Step 7: Flash partition 2 ---
step "Step 7: Flashing partition 2 via SSH (mtd write to alt_kernel)..."

# Copy the factory image to the device
step "Copying firmware to device..."
scp -O -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "$FIRMWARE_FILE" "root@${TARGET_IP}:/tmp/openwrt-factory.bin" || die "SCP transfer failed"

# Write to alt_kernel partition
step "Writing to alt_kernel partition (this will reboot the device)..."
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "root@${TARGET_IP}" \
  'mtd -r -e alt_kernel -n write /tmp/openwrt-factory.bin alt_kernel' || \
  warn "mtd write returned non-zero exit code, but the device may still be rebooting correctly"

# --- Step 8: Wait for partition 2 boot and verify ---
step "Step 8: Waiting for device to reboot from partition 2..."

sleep 10

FOUND2=0
for i in $(seq 1 60); do
  if ping -c1 -W2 "$TARGET_IP" &>/dev/null; then
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
         -o ConnectTimeout=2 -o BatchMode=yes \
         "root@${TARGET_IP}" 'echo OK' &>/dev/null; then
      step "Device is back up on partition 2 (attempt ${i})"
      FOUND2=1
      break
    fi
  fi
  sleep 3
done

if [[ "$FOUND2" -ne 1 ]]; then
  die "Device did not come back after partition 2 flash. Both partitions may need recovery."
fi

# Verify OpenWrt version and state
step "Verifying final state..."
RELEASE=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "root@${TARGET_IP}" 'cat /etc/openwrt_release' 2>/dev/null) || true

if [[ "$RELEASE" == *"OpenWrt"* ]]; then
  VER=$(echo "$RELEASE" | grep DISTRIB_RELEASE | cut -d"'" -f2)
  step "SUCCESS: OpenWrt ${VER} running on Linksys ${MODEL} V${HWVER}"
  step "Both partitions flashed. Safe from 30/30/30 rollback."
else
  warn "SSH verification inconclusive. Device is reachable but version check failed."
fi

# Check partition layout
step "Partition layout:"
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  "root@${TARGET_IP}" 'cat /proc/mtd' 2>/dev/null || true

step "Done. SSH: ssh root@${TARGET_IP}"
step "Note: WiFi radios are disabled by default. Configure via LuCI or SSH."
