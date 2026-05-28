#!/bin/bash
# ASUS Lyra MAP-AC2200 — Lab device auto-detect and test
# Plug in ethernet (any port), power on, run this script.
# It detects stock vs OpenWrt and runs the appropriate tests.
set -euo pipefail

INTERFACE="${1:-en6}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTSDIR="/tmp/conwrt-stock-lab"
mkdir -p "$RESULTSDIR"

echo "=== ASUS Lyra MAP-AC2200 Lab Device Detection ==="
echo "Interface: $INTERFACE  |  Timestamp: $TIMESTAMP"
echo ""

# ─── Wait for link ────────────────────────────────────────────────
echo "Waiting for link on $INTERFACE..."
for i in $(seq 1 30); do
    if ifconfig "$INTERFACE" 2>/dev/null | grep -q "status: active"; then
        echo "Link up!"
        break
    fi
    sleep 1
done

# ─── Wait for DHCP ────────────────────────────────────────────────
echo "Waiting for DHCP..."
for i in $(seq 1 60); do
    IP=$(ifconfig "$INTERFACE" 2>/dev/null | grep "inet " | awk '{print $2}')
    if [ -n "$IP" ] && [ "$IP" != "0.0.0.0" ]; then
        echo "Got IP: $IP"
        break
    fi
    sleep 2
done

# Determine subnet
SUBNET=$(echo "$IP" | cut -d. -f1-3)
echo "Subnet: $SUBNET.0/24"
GATEWAY="${SUBNET}.1"

echo ""

# ─── Detect firmware type ─────────────────────────────────────────
echo "--- Detecting firmware type ---"

IS_OPENWRT=false
IS_STOCK=false

# Check if gateway responds
if ping -c1 -t2 "$GATEWAY" >/dev/null 2>&1; then
    echo "Gateway $GATEWAY responds to ping"
    
    # Try SSH with OpenWrt credentials (root, no password)
    if echo "" | nc -w2 "$GATEWAY" 22 2>/dev/null | grep -qi "dropbear"; then
        echo "[!] Dropbear SSH detected — likely OpenWrt"
        IS_OPENWRT=true
    elif echo "" | nc -w2 "$GATEWAY" 22 2>/dev/null | grep -qi "openssh"; then
        echo "[!] OpenSSH detected — likely stock ASUS firmware"
        IS_STOCK=true
    else
        # Try HTTP fingerprint
        SERVER=$(curl -s -I "http://$GATEWAY/" 2>/dev/null | grep -i "^server:" || true)
        if echo "$SERVER" | grep -qi "openwrt"; then
            echo "[!] HTTP Server header says OpenWrt"
            IS_OPENWRT=true
        elif echo "$SERVER" | grep -qi "asus\|httpd"; then
            echo "[!] HTTP Server header says ASUS stock"
            IS_STOCK=true
        else
            # Default guess based on subnet
            if [ "$SUBNET" = "192.168.1" ]; then
                echo "[?] Subnet 192.168.1.x — could be either, checking further..."
                # Try OpenWrt LuCI
                if curl -s "http://$GATEWAY/cgi-bin/luci" 2>/dev/null | grep -qi "luci\|openwrt"; then
                    echo "[!] LuCI detected — OpenWrt"
                    IS_OPENWRT=true
                else
                    echo "[?] Cannot determine — assuming stock (try manual check)"
                    IS_STOCK=true
                fi
            elif [ "$SUBNET" = "192.168.72" ]; then
                echo "[!] Subnet 192.168.72.x — stock ASUS firmware"
                IS_STOCK=true
            fi
        fi
    fi
else
    echo "[-] Gateway $GATEWAY does not respond"
    echo "    Device may still be booting. Wait and re-run."
    exit 1
fi

echo ""

# ─── Collect basic device info ─────────────────────────────────────
echo "--- Basic device info ---"
MAC=$(ifconfig "$INTERFACE" 2>/dev/null | grep "ether" | awk '{print $2}')
echo "Our MAC: $MAC"
echo "Our IP: $IP"
echo "Gateway: $GATEWAY"

# ARP table
ARP_MAC=$(arp -n "$GATEWAY" 2>/dev/null | awk '{print $4}' | tail -1)
if [ -n "$ARP_MAC" ]; then
    echo "Device MAC (ARP): $ARP_MAC"
    
    # OUI lookup (first 3 octets)
    OUI=$(echo "$ARP_MAC" | tr ':' '-' | cut -d- -f1-3 | tr 'a-f' 'A-F')
    echo "OUI: $OUI"
fi

echo ""

# ─── Save results ──────────────────────────────────────────────────
RESULTSFILE="$RESULTSDIR/detect-${TIMESTAMP}.txt"

{
    echo "=== Lab Device Detection Results ==="
    echo "Timestamp: $TIMESTAMP"
    echo "Interface: $INTERFACE"
    echo "Our IP: $IP"
    echo "Gateway: $GATEWAY"
    echo "Device MAC: ${ARP_MAC:-unknown}"
    echo "Firmware: $(if $IS_OPENWRT; then echo 'OpenWrt'; elif $IS_STOCK; then echo 'ASUS Stock'; else echo 'Unknown'; fi)"
} | tee "$RESULTSFILE"

echo ""

# ─── Route to appropriate test suite ───────────────────────────────
if $IS_OPENWRT; then
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  OPENWRT DEVICE DETECTED                             ║"
    echo "║  This device is already flashed.                     ║"
    echo "║  Skip attack-vector tests.                           ║"
    echo "║  Use for: sysupgrade testing, inventory, or as host  ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    
    # Collect inventory from OpenWrt device
    echo "--- Collecting OpenWrt inventory ---"
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "root@$GATEWAY" "cat /etc/board.json; echo '---'; uname -a; echo '---'; cat /proc/cpuinfo | head -10; echo '---'; free -m; echo '---'; df -h /overlay" 2>/dev/null; then
        echo "[+] Inventory collected"
    else
        echo "[-] SSH failed (may need password)"
    fi
    
    echo ""
    echo "This is NOT a lab device. Please find an unflashed (stock) device."
    
elif $IS_STOCK; then
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  STOCK ASUS FIRMWARE DETECTED                        ║"
    echo "║  Running attack-vector tests...                      ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    
    # Run the attack vector tests
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    if [ -f "$SCRIPT_DIR/test-attack-vectors.sh" ]; then
        bash "$SCRIPT_DIR/test-attack-vectors.sh" "$INTERFACE" "$GATEWAY" 2>&1 | tee -a "$RESULTSFILE"
    else
        echo "[!] test-attack-vectors.sh not found, running inline tests..."
        
        # Inline Test: infosvr UDP 9999
        echo "--- Inline Test: infosvr UDP 9999 ---"
        python3 -c "
import socket
pkt = bytearray(512)
pkt[0] = 0x0C; pkt[1] = 0x15; pkt[2] = 0x33; pkt[3] = 0x00
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(bytes(pkt), ('$GATEWAY', 9999))
    data, addr = sock.recvfrom(512)
    print(f'[!] RESPONSE: {len(data)} bytes from {addr[0]}')
    print(f'    ServiceID=0x{data[0]:02x} PacketType=0x{data[1]:02x}')
except socket.timeout:
    print('[-] No response')
except Exception as e:
    print(f'[-] Error: {e}')
finally:
    sock.close()
" 2>&1
        
        # Inline Test: CVE-2021-32030
        echo "--- Inline Test: CVE-2021-32030 null auth ---"
        RESP=$(curl -s -o /dev/null -w "%{http_code}" \
          -b "asus_token=%00" \
          -H "User-Agent: asusrouter--" \
          "http://$GATEWAY/apply.cgi" 2>/dev/null || echo "failed")
        echo "HTTP response: $RESP"
        
        # Inline Test: WiFi AP scan
        echo "--- Inline Test: WiFi AP scan ---"
        /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null | grep -i "asus\|lyra\|MAP" || echo "[-] No ASUS APs found"
        
        # Port scan
        echo "--- Inline Test: Quick port scan ---"
        for port in 22 53 80 443 5222 7788 8443 9999; do
            if echo "" | nc -w1 "$GATEWAY" "$port" 2>/dev/null | head -1 | grep -q .; then
                echo "[!] Port $port: OPEN"
            fi
        done
        
        # Check AiMesh port 7788
        echo "--- Inline Test: AiMesh TCP 7788 ---"
        if nc -z -w2 "$GATEWAY" 7788 2>/dev/null; then
            echo "[!] TCP 7788 OPEN — AiMesh cfg_server listening!"
        else
            echo "[-] TCP 7788 closed — AiMesh not active (expected on factory default)"
        fi
    fi
    
    echo ""
    echo "Results saved to: $RESULTSFILE"
    echo ""
    echo ">>> This is our STOCK LAB DEVICE. Do NOT flash it yet. <<<"
    echo ">>> Run additional tests, then decide whether to keep or flash. <<<"
fi

echo ""
echo "=== Detection complete ==="
