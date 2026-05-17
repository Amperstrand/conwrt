#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

TARGET_IP="${1:-192.168.1.1}"
OPENWRT_VERSION="${2:-24.10.6}"
FIRMWARE_FILE="${3:-}"
INTERFACE="${4:-}"

usage() {
  echo "Usage: $0 [TARGET_IP] [OPENWRT_VERSION] [FIRMWARE_FILE] [INTERFACE]"
  echo ""
  echo "  TARGET_IP       Router IP (default: 192.168.1.1)"
  echo "  OPENWRT_VERSION OpenWrt release (default: 24.10.6)"
  echo "  FIRMWARE_FILE   Local .bin file (omit to auto-download)"
  echo "  INTERFACE       Wired interface for tcpdump capture (omit to skip)"
  echo ""
  echo "Automatically detects WHW03 V1 (eMMC) vs V2 (NAND) and selects"
  echo "the correct firmware image."
  exit 1
}

[[ "${1:-}" == "--help" || "${1:-}" == "-h" ]] && usage

step() { echo "[$(date +%H:%M:%S)] $*"; }
die() { echo "[ERROR] $*" >&2; exit 1; }

step "Identifying device at ${TARGET_IP}..."
INFO=$(curl -sk --max-time 10 -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://linksys.com/jnap/core/GetDeviceInfo" \
  -d '{}' "http://${TARGET_IP}/JNAP/" 2>/dev/null) || die "Cannot reach device"

RESULT=$(echo "$INFO" | jq -r '.result')
[[ "$RESULT" == "OK" ]] || die "GetDeviceInfo failed: $INFO"

MANUFACTURER=$(echo "$INFO" | jq -r '.output.manufacturer')
MODEL=$(echo "$INFO" | jq -r '.output.modelNumber')
HWVER=$(echo "$INFO" | jq -r '.output.hardwareVersion')
step "Found: ${MANUFACTURER} ${MODEL} V${HWVER}"

[[ "$MODEL" == "WHW03" ]] || die "Expected WHW03, got ${MODEL}"

if [[ "$HWVER" == "1" ]]; then
  OWRT_DEVICE="linksys_whw03"
  FLASH_TYPE="eMMC"
elif [[ "$HWVER" == "2" ]]; then
  OWRT_DEVICE="linksys_whw03v2"
  FLASH_TYPE="NAND"
else
  die "Unknown hardware version ${HWVER}"
fi
step "Flash type: ${FLASH_TYPE}, OpenWrt device: ${OWRT_DEVICE}"

step "Verifying default admin password..."
HTTP_CODE=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
  -u "admin:admin" "http://${TARGET_IP}/fwupdate.html" 2>/dev/null || \
  curl -sk --max-time 5 -o /dev/null -w '%{http_code}' \
  -u "admin:admin" "https://${TARGET_IP}/fwupdate.html" 2>/dev/null)
[[ "$HTTP_CODE" == "200" ]] || die "Default password rejected (HTTP ${HTTP_CODE})"
step "Default credentials accepted"

if [[ -z "$FIRMWARE_FILE" || ! -f "$FIRMWARE_FILE" ]]; then
  FIRMWARE_FILE="/tmp/openwrt-${OPENWRT_VERSION}-${OWRT_DEVICE}-factory.bin"
  URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/ipq40xx/generic/openwrt-${OPENWRT_VERSION}-ipq40xx-generic-${OWRT_DEVICE}-squashfs-factory.bin"
  step "Downloading OpenWrt ${OPENWRT_VERSION} for ${OWRT_DEVICE}..."
  curl -fL --progress-bar -o "$FIRMWARE_FILE" "$URL" || die "Download failed"
fi
step "Firmware: $(ls -lh "$FIRMWARE_FILE" | awk '{print $5}')"

TCPDUMP_PID=""
if [[ -n "$INTERFACE" ]]; then
  CAPTURE_FILE="flash-capture-$(date +%Y%m%d-%H%M%S).pcap"
  step "Starting packet capture on ${INTERFACE}..."
  sudo tcpdump -i "$INTERFACE" -w "$CAPTURE_FILE" -s 0 host "$TARGET_IP" &>/dev/null &
  TCPDUMP_PID=$!
  disown
  sleep 1
fi

step "Uploading firmware..."
RESPONSE=$(curl -sk --max-time 300 \
  -u "admin:admin" \
  -F "X-JNAP-Action=updatefirmware" \
  -F "X-JNAP-Authorization=Basic YWRtaW46YWRtaW4=" \
  -F "upload=@${FIRMWARE_FILE};type=application/octet-stream" \
  "https://${TARGET_IP}/jcgi/" 2>/dev/null) || die "Upload failed"

UPLOAD_RESULT=$(echo "$RESPONSE" | jq -r '.result' 2>/dev/null || echo "$RESPONSE")
[[ "$UPLOAD_RESULT" == "OK" ]] || die "Upload rejected: $RESPONSE"
step "Upload accepted"

step "Waiting for reboot..."
sleep 10
FOUND=0
for i in $(seq 1 60); do
  if ping -c1 -W2 "$TARGET_IP" &>/dev/null; then
    TITLE=$(curl -sk --max-time 3 "http://${TARGET_IP}/" 2>/dev/null | grep -o 'LuCI' | head -1)
    if [[ -n "$TITLE" ]]; then
      step "OpenWrt is up! (attempt $i)"
      FOUND=1
      break
    fi
  fi
  sleep 5
done
[[ "$FOUND" -eq 1 ]] || die "Device did not come back after 5 minutes"

step "Verifying OpenWrt via SSH..."
RELEASE=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
  "root@${TARGET_IP}" 'cat /etc/openwrt_release' 2>/dev/null) || true
if [[ "$RELEASE" == *"OpenWrt"* ]]; then
  VER=$(echo "$RELEASE" | grep DISTRIB_RELEASE | cut -d"'" -f2)
  step "SUCCESS: OpenWrt ${VER} on ${MANUFACTURER} ${MODEL} V${HWVER} (${FLASH_TYPE})"
else
  step "WARNING: SSH verification inconclusive"
fi

if [[ -n "$TCPDUMP_PID" ]]; then
  sudo kill "$TCPDUMP_PID" 2>/dev/null || true
  step "Packet capture saved"
fi

step "Done. ssh root@${TARGET_IP}"
