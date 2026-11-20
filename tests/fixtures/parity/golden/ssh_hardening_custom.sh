# --- SSH hardening ---
uci set dropbear.@dropbear[0].PasswordAuth='on'
uci set dropbear.@dropbear[0].RootPasswordAuth='on'
uci set dropbear.@dropbear[0].Port='2222'
uci set dropbear.@dropbear[0].IdleTimeout='600'
uci set dropbear.@dropbear[0].MaxAuthTries='2'
uci set dropbear.@dropbear[0].GatewayPorts='yes'
uci commit dropbear
/etc/init.d/dropbear restart
echo "SSH hardened: password_auth=on idle=600s max_tries=2 port=2222"