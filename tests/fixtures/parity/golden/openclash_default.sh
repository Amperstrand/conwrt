# --- OpenClash transparent proxy ---
mkdir -p /etc/openclash/config
uci -q revert openclash 2>/dev/null || true
uci set openclash.config.enable='1'
uci set openclash.config.config_path='/etc/openclash/config/config.yaml'
uci set openclash.config.proxy_type='ss'
uci set openclash.config.core_type='Meta'
uci set openclash.config.dashboard_type='Official'
uci set openclash.config.dns_mode='redir-host'
uci set openclash.config.operation_mode='redir-host'
uci commit openclash
/etc/init.d/openclash enable
echo "OpenClash configured: Meta core, ss proxy"
echo "Post-flash: import your subscription config via the LuCI web UI"