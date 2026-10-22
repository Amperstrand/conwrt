# golden: conwrt 1.x output of scripts/use_cases/mesh11sd.py build_configure (mesh_id=testmesh) — regenerate with the command in tests/use_case_goldens.rs
# --- Mesh11sd 802.11s mesh ---
opkg remove wpad-basic-mbedtls wpad-basic-wolfssl wpad-basic-openssl wpad-basic 2>/dev/null || true
opkg install wpad-mbedtls 2>/dev/null || true
service wpad restart 2>/dev/null || true

uci set mesh11sd.setup.auto_mesh_id='testmesh'
uci set mesh11sd.setup.mesh_gate_base_ssid='MeshNet'
uci set mesh11sd.setup.mesh_gate_encryption='1'
uci set mesh11sd.setup.auto_config='0'
uci commit mesh11sd
service mesh11sd restart 2>/dev/null || true
echo "Mesh11sd configured: mesh_id=testmesh ssid=MeshNet"
