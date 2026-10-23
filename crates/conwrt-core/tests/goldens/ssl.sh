# golden: conwrt 1.x output of scripts/use_cases/ssl.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- SSL: trusted HTTPS via lancert ---
# -- uhttpd HTTPS (admin interface) --
uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt'
uci set uhttpd.main.key='/etc/tollgate/ssl/server.key'
uci -q delete uhttpd.main.listen_https && uci add_list uhttpd.main.listen_https='0.0.0.0:443' && uci add_list uhttpd.main.listen_https='[::]:443'
uci commit uhttpd
/etc/init.d/uhttpd restart
# -- Allow port 443 through nodogsplash --
uci -q show nodogsplash >/dev/null 2>&1 && uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' && uci commit nodogsplash && /etc/init.d/nodogsplash restart || true

