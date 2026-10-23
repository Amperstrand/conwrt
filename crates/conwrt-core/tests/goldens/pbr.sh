# golden: conwrt 1.x output of scripts/use_cases/pbr.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- pbr (nftables-native policy routing) ---
uci set pbr.config=pbr
uci set pbr.config.enabled='1'
uci set pbr.config.verbosity='2'
uci set pbr.config.strict_enforcement='1'
uci set pbr.config.resolver_set='none'
uci set pbr.config.nft_file_helper='1'
uci set pbr.config.netifd_interface_default=wan
uci add_list pbr.config.netifd_interface_local=lan
# Example: default policy routes all traffic via WAN

uci commit pbr
/etc/init.d/pbr enable
/etc/init.d/pbr restart
echo "pbr configured. Verify with: nft list table inet pbr 2>/dev/null"
echo "Check status: /etc/init.d/pbr status"