# --- mptcp-bonding (BSBF) → 192.168.13.10:5000 ---
apk add curl 2>/dev/null || opkg update && opkg install curl 2>/dev/null || true

curl -fsSL owrt.bondingshouldbefree.org | sh -s -- --server-ipv4 192.168.13.10 --server-port 5000 --uuid b3accb70-3fdd-4c1e-a8b1-conftest0001

echo "BSBF installed. Verify: bsbf-bonding --status"
echo "Monitor: bsbf-netspeed"
echo "Uninstall: bsbf-bonding --uninstall"

# REQUIRES: MPTCP-enabled kernel (CONFIG_MPTCP=y)
# Firmware: https://firmware.bondingshouldbefree.org