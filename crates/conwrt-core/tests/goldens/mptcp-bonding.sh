# golden: conwrt 1.x output of scripts/use_cases/mptcp_bonding.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- mptcp-bonding (BSBF) → 203.0.113.7:16384 ---
apk add curl 2>/dev/null || opkg update && opkg install curl 2>/dev/null || true

curl -fsSL owrt.bondingshouldbefree.org | sh -s -- --server-ipv4 203.0.113.7 --server-port 16384 --uuid 0f0e0d0c-0b0a-4909-8807-060504030201

echo "BSBF installed. Verify: bsbf-bonding --status"
echo "Monitor: bsbf-netspeed"
echo "Uninstall: bsbf-bonding --uninstall"

# REQUIRES: MPTCP-enabled kernel (CONFIG_MPTCP=y)
# Firmware: https://firmware.bondingshouldbefree.org