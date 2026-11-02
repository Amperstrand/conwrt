# --- AP Nostr identity ---
mkdir -p /etc/tollgate
[ -f /etc/tollgate/ap-nsec ] || printf '%s\n' 'nsec1testsec0123456789abcdefghijklmnopqrstu' > /etc/tollgate/ap-nsec
[ -f /etc/tollgate/ap-nsec ] || chmod 600 /etc/tollgate/ap-nsec
[ -f /etc/tollgate/ap-npub ] || printf '%s\n' 'npub1testpub0123456789abcdefghijklmnopqrstuv' > /etc/tollgate/ap-npub
[ -f /etc/tollgate/ap-npub ] || chmod 644 /etc/tollgate/ap-npub

# --- Set nas_identifier on all wifi-iface sections ---
for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' | cut -d. -f2 | cut -d= -f1); do uci set wireless.$_s.nas_identifier='npub1testpub0123456789abcdefghijklmnopqrstuv'; done
uci commit wireless
wifi reload 2>/dev/null || true
echo "AP Nostr identity configured: npub=npub1testpub0123456789ab..."