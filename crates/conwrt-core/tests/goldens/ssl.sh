# golden: conwrt 1.x output of scripts/use_cases/ssl.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- SSL: trusted HTTPS via lancert ---
# -- uhttpd HTTPS (admin interface) --
if [ -f /etc/tollgate/ssl/server.crt ] && [ -f /etc/tollgate/ssl/server.key ]; then
uci -q revert uhttpd 2>/dev/null || true
uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt'
uci set uhttpd.main.key='/etc/tollgate/ssl/server.key'
uci -q delete uhttpd.main.listen_https || true
uci add_list uhttpd.main.listen_https='0.0.0.0:443'
uci add_list uhttpd.main.listen_https='[::]:443'
uci commit uhttpd
/etc/init.d/uhttpd restart
echo 'ssl: uhttpd HTTPS wired on :443'
else
echo 'ssl: /etc/tollgate/ssl certs not present yet — skipping uhttpd HTTPS wiring (deploy certs, then re-run)' >&2
fi
# -- Allow port 443 through nodogsplash --
if uci -q show nodogsplash >/dev/null 2>&1; then
uci -q revert nodogsplash 2>/dev/null || true
uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' || true
uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443'
uci commit nodogsplash
/etc/init.d/nodogsplash restart
echo 'ssl: nodogsplash allows tcp/443 to the router'
fi

