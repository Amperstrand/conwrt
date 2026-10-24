# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/nordvpn.py _build_nordvpn_openvpn_ops — regenerate with the command in tests/use_case_goldens.rs
# --- NordVPN OpenVPN (openvpn-udp, udp, endpoint 193.29.107.10, cipher AES-256-CBC) ---
cat > /tmp/nordvpn_openvpn_setup.sh << 'VPN_SETUP_EOF'
# Clean up old WireGuard interface + peers
uci -q delete network.wg0
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done


# Tear down any previous OpenVPN instance
uci -q delete openvpn.nordvpn

mkdir -p /etc/openvpn
cat > /etc/openvpn/nordvpn.ca << 'NORD_CA_EOF'
-----BEGIN CERTIFICATE-----
MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ
MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2
MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV
BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI
hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF
kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr
XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU
eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV
skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu
MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA
37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR
hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s
Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy
WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6
MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST
LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG
SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g
nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/
k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S
DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/
pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo
k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp
+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd
NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa
wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC
VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S
PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==
-----END CERTIFICATE-----

NORD_CA_EOF
cat > /etc/openvpn/nordvpn.ta << 'NORD_TA_EOF'
#
# 2048 bit OpenVPN static key
#
-----BEGIN OpenVPN Static key V1-----
e685bdaf659a25a200e2b9e39e51ff03
0fc72cf1ce07232bd8b2be5e6c670143
f51e937e670eee09d4f2ea5a6e4e6996
5db852c275351b86fc4ca892d78ae002
d6f70d029bd79c4d1c26cf14e9588033
cf639f8a74809f29f72b9d58f9b8f5fe
fc7938eade40e9fed6cb92184abb2cc1
0eb1a296df243b251df0643d53724cdb
5a92a1d6cb817804c4a9319b57d53be5
80815bcfcb2df55018cc83fc43bc7ff8
2d51f9b88364776ee9d12fc85cc7ea5b
9741c4f598c485316db066d52db4540e
212e1518a9bd4828219e24b20d88f598
a196c9de96012090e333519ae18d3509
9427e7b372d348d352dc4c85e18cd4b9
3f8a56ddb2e64eb67adfc9b337157ff4
-----END OpenVPN Static key V1-----

NORD_TA_EOF
cat > /etc/openvpn/nordvpn.auth << 'NORD_AUTH_EOF'
svcuser1234
svcpass5678abcd
NORD_AUTH_EOF
chmod 600 /etc/openvpn/nordvpn.auth

uci -q delete openvpn.nordvpn
uci set openvpn.nordvpn=openvpn
uci set openvpn.nordvpn.enabled='1'
uci set openvpn.nordvpn.client='1'
uci set openvpn.nordvpn.dev='tun'
uci set openvpn.nordvpn.proto='udp'
uci add_list openvpn.nordvpn.remote='193.29.107.10 1231'
uci add_list openvpn.nordvpn.remote='193.29.107.10 1232'
uci add_list openvpn.nordvpn.remote='193.29.107.10 1233'
uci add_list openvpn.nordvpn.remote='193.29.107.10 1234'
uci set openvpn.nordvpn.resolv_retry='infinite'
uci set openvpn.nordvpn.nobind='1'
uci set openvpn.nordvpn.persist_key='1'
uci set openvpn.nordvpn.persist_tun='1'
uci set openvpn.nordvpn.ca='/etc/openvpn/nordvpn.ca'
uci set openvpn.nordvpn.auth_user_pass='/etc/openvpn/nordvpn.auth'
uci set openvpn.nordvpn.tls_auth='/etc/openvpn/nordvpn.ta'
uci set openvpn.nordvpn.key_direction='1'
uci set openvpn.nordvpn.verify_x509_name='de500.nordvpn.com name'
uci set openvpn.nordvpn.remote_cert_tls='server'
uci set openvpn.nordvpn.cipher='AES-256-CBC'
uci set openvpn.nordvpn.data_ciphers='AES-256-GCM:AES-256-CBC'
uci set openvpn.nordvpn.auth='SHA512'
uci set openvpn.nordvpn.comp_lzo='no'
uci set openvpn.nordvpn.mssfix='1450'
uci set openvpn.nordvpn.ping='15'
uci set openvpn.nordvpn.ping_restart='0'
uci set openvpn.nordvpn.verb='3'
uci set openvpn.nordvpn.pull='1'
uci commit openvpn

# Bring tun0 up and attach the vpn zone to it
uci -q del_list firewall.vpn_zone.network='wg0'
uci -q add_list firewall.vpn_zone.network='tun0'
/etc/init.d/openvpn restart || /etc/init.d/openvpn start
VPN_SETUP_EOF
sh /tmp/nordvpn_openvpn_setup.sh

# --- VPN firewall zone + forwarding ---
while uci show firewall 2>/dev/null | grep -q "name='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "name='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "dest='vpn'"; do _s=$(uci show firewall 2>/dev/null | grep "dest='vpn'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='KillSwitch-Reject-NonVPN'"; do _s=$(uci show firewall 2>/dev/null | grep "name='KillSwitch-Reject-NonVPN'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
while uci show firewall 2>/dev/null | grep -q "name='Allow-VPN-Management'"; do _s=$(uci show firewall 2>/dev/null | grep "name='Allow-VPN-Management'" | head -1 | cut -d. -f2 | cut -d= -f1); uci delete "firewall.$_s" 2>/dev/null; done; true
uci set firewall.vpn_zone=zone
uci set firewall.vpn_zone.name='vpn'
uci set firewall.vpn_zone.input='REJECT'
uci set firewall.vpn_zone.output='ACCEPT'
uci set firewall.vpn_zone.forward='REJECT'
uci set firewall.vpn_zone.masq='1'
uci set firewall.vpn_zone.mtu_fix='1'
uci set firewall.vpn_zone.network='tun0'
uci set firewall.vpn_fwd=forwarding
uci set firewall.vpn_fwd.src='lan'
uci set firewall.vpn_fwd.dest='vpn'

# --- Management (SSH/LuCI) from the VPN zone ---
uci set firewall.vpn_mgmt=rule
uci set firewall.vpn_mgmt.name='Allow-VPN-Management'
uci set firewall.vpn_mgmt.src='vpn'
uci set firewall.vpn_mgmt.proto='tcp'
uci set firewall.vpn_mgmt.dest_port='22 80 443'
uci set firewall.vpn_mgmt.target='ACCEPT'

uci set firewall.vpn_killswitch=rule
uci set firewall.vpn_killswitch.name='KillSwitch-Reject-NonVPN'
uci set firewall.vpn_killswitch.src='lan'
uci set firewall.vpn_killswitch.dest='wan'
uci set firewall.vpn_killswitch.proto='all'
uci set firewall.vpn_killswitch.target='REJECT'

# --- VPN DNS through tunnel ---
uci del_list dhcp.@dnsmasq[0].server='103.86.96.100' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='103.86.96.100'
uci del_list dhcp.@dnsmasq[0].server='103.86.99.100' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='103.86.99.100'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit network
uci commit firewall
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart
