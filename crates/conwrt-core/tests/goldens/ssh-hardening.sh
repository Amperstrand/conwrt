# --- SSH hardening ---
uci set dropbear.@dropbear[0].PasswordAuth='off'
uci set dropbear.@dropbear[0].RootPasswordAuth='off'
uci set dropbear.@dropbear[0].Port='22'
uci set dropbear.@dropbear[0].IdleTimeout='300'
uci set dropbear.@dropbear[0].MaxAuthTries='3'
uci set dropbear.@dropbear[0].GatewayPorts='no'
uci commit dropbear
/etc/init.d/dropbear restart
echo "SSH hardened: password_auth=off idle=300s max_tries=3 port=22"
