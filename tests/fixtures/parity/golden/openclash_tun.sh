# --- OpenClash transparent proxy ---
if [ -n "$(opkg list-installed luci-app-openclash 2>/dev/null)" ]; then echo 'openclash: luci-app-openclash already installed'; elif [ -n "$(opkg list luci-app-openclash 2>/dev/null)" ]; then opkg update >/dev/null 2>&1; opkg install luci-app-openclash; else echo 'PRECONDITION-FAIL (#59): luci-app-openclash ships from the third-party vernesong feed (github.com/vernesong/OpenClash), not the official OpenWrt package feeds - bake it into the image (packages_via=image) or configure the feed first; refusing before any configuration is touched'; exit 1; fi
mkdir -p /etc/openclash/config
uci -q revert openclash 2>/dev/null || true
uci set openclash.config.enable='1'
uci set openclash.config.config_path='/etc/openclash/config/config.yaml'
uci set openclash.config.proxy_type='vmess'
uci set openclash.config.core_type='Meta'
uci set openclash.config.dashboard_type='Official'
uci set openclash.config.dns_mode='fake-ip'
uci set openclash.config.operation_mode='fake-ip'
uci commit openclash
/etc/init.d/openclash enable
echo "OpenClash configured: Meta core, vmess proxy"
echo "Post-flash: import your subscription config via the LuCI web UI"