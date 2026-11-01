# --- TollGate: nodogsplash captive portal ---
uci set nodogsplash.@nodogsplash[0].enabled='1'
uci set nodogsplash.@nodogsplash[0].gatewayname='bench-gw'
uci set nodogsplash.@nodogsplash[0].gatewaydomainname='gw.bench.test'
uci set nodogsplash.@nodogsplash[0].clientid='mac'
uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2121' 2>/dev/null || true
uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2121'
uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2050' 2>/dev/null || true
uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 2050'
uci commit nodogsplash
/etc/init.d/nodogsplash enable
/etc/init.d/nodogsplash restart

# --- TollGate: hotplug (wwan ifup \u2192 tollgate restart) ---
mkdir -p /etc/hotplug.d/iface && printf '%s' '#!/bin/sh
[ "$ACTION" = "ifup" ] || exit 0
[ "$INTERFACE" = "wwan" ] || exit 0
logger -t tollgate-hotplug "wwan up \u2014 restarting tollgate"
/etc/init.d/tollgate-wrt restart &
' > /etc/hotplug.d/iface/95-tollgate-restart && chmod +x /etc/hotplug.d/iface/95-tollgate-restart

# --- TollGate: payment configuration ---
touch /etc/config/tollgate
uci set tollgate.payment=tollgate
uci set tollgate.payment.mint_url='https://testnut.cashu.space'
uci set tollgate.payment.lightning_address='bench@ln.test'
uci set tollgate.payment.price_per_minute='2'
uci commit tollgate

# --- TollGate: byte pricing (explicit price_sats_per_mib = 21 sat/MiB) ---
if [ -f /etc/tollgate/config.json ]; then SS=$(sed -n 's/.*"step_size":[ ]*\([0-9][0-9]*\).*/\1/p' /etc/tollgate/config.json | head -1); [ -n "$SS" ] || SS=1048576; P=$(( ( 21 * SS + 1048575 ) / 1048576 )); sed -i 's/"price_per_step":[ ]*[0-9]*/"price_per_step": '"$P"'/g' /etc/tollgate/config.json && /etc/init.d/tollgate-wrt restart 2>/dev/null && echo "tollgate: price_per_step=$P applied (step_size=$SS bytes; 21 sat/MiB)" || echo "tollgate: price patch FAILED on existing config.json"; else echo "tollgate: /etc/tollgate/config.json absent (ipk not installed yet) — re-run configure after deploy_tollgate_post_flash"; fi

# --- TollGate: ipk installed separately via deploy_tollgate_post_flash() ---