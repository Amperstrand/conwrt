# golden: conwrt 1.x output of scripts/use_cases/travelmate.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- Travelmate travel router ---
uci set travelmate.global.trm_enabled='1'
uci set travelmate.global.trm_automatic='1'
uci set travelmate.global.trm_captive='1'
uci set travelmate.global.trm_timeout='60'
uci set travelmate.global.trm_retry='5'
uci set travelmate.global.trm_radio='radio0'
uci commit travelmate
/etc/init.d/travelmate enable
/etc/init.d/travelmate restart
echo "Travelmate configured: auto-connect on radio0"
