# golden: conwrt 1.x output of scripts/use_cases/ap_nostr_id.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- AP Nostr identity ---
mkdir -p /etc/tollgate
[ -f /etc/tollgate/ap-nsec ] || printf '%s\n' 'nsec1qqv9p7wq3zq5x2swp3jv4tdd6syr8whs' > /etc/tollgate/ap-nsec
[ -f /etc/tollgate/ap-nsec ] || chmod 600 /etc/tollgate/ap-nsec
[ -f /etc/tollgate/ap-npub ] || printf '%s\n' 'npub1qqv9p7wq3zq5x2swp3jv4tdd6syr8whs' > /etc/tollgate/ap-npub
[ -f /etc/tollgate/ap-npub ] || chmod 644 /etc/tollgate/ap-npub

# --- Set nas_identifier on all wifi-iface sections ---
for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' | cut -d. -f2 | cut -d= -f1); do uci set wireless.$_s.nas_identifier='npub1qqv9p7wq3zq5x2swp3jv4tdd6syr8whs'; done
uci commit wireless
wifi reload 2>/dev/null || true
echo "AP Nostr identity configured: npub=npub1qqv9p7wq3zq5x2swp3j..."