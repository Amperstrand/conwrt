# golden: conwrt 1.x output of scripts/use_cases/vpn_node.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- VPN Node: Nostr listing publisher ---
cat > /etc/vpn-listing.sh << 'SCRIPT'
#!/bin/sh
# Publish Europa listing on first boot
NSEC_FILE="/etc/vpn-node/nsec"
WG_PUBKEY=$(wg show wg0 public-key 2>/dev/null)
if [ -z "$WG_PUBKEY" ] || [ ! -f "$NSEC_FILE" ]; then
    echo "vpn-listing: missing wg0 pubkey or nsec, skipping" >&2
    exit 0
fi
NSEC=$(cat "$NSEC_FILE")
/usr/bin/nak event \
    -k 30402 \
    --sec "$NSEC" \
    -d "vpn-node" \
    -t "t=vpn-service" \
    -t "t=wireguard" \
    -t "protocol=wireguard" \
    -t "region=US" \
    -t "price=50sat/hour" \
    -c '{"type":"vpn-service","name":"VPN Node","endpoint":"vpn.example.com:51820","protocols":["wireguard"],"prices":[{"amount":50,"currency":"sat","unit":"hour"}],"policies":["no-logs"],"content":"VPN node. WireGuard. No logs."}' \
    wss://relay.damus.io wss://relay.cashu.email 2>&1
echo "vpn-listing: published"
SCRIPT
chmod +x /etc/vpn-listing.sh

mkdir -p /etc/vpn-node
echo '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef' > /etc/vpn-node/nsec
chmod 600 /etc/vpn-node/nsec

( sleep 30 && /etc/vpn-listing.sh > /tmp/vpn-listing.log 2>&1 ) &
