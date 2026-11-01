# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/nordvpn.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- NordVPN IKEv2/IPsec (server de500.nordvpn.com, hw_accel=True) ---
cat > /tmp/nordvpn_ikev2_setup.sh << 'VPN_SETUP_EOF'
# --- NordVPN IKEv2 (strongSwan, EAP-MSCHAPv2) ---
modprobe crypto_hw_eip93 2>/dev/null || true

mkdir -p /var/ipsec /etc/swanctl/conf.d /etc/swanctl/x509ca

printf 'charon {\n  install_routes = yes\n}\n' > /var/ipsec/strongswan.conf

cat > /etc/swanctl/x509ca/nordvpn.pem << 'NORD_CA_EOF'
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

cat > /etc/swanctl/conf.d/nordvpn-ikev2.conf << 'NORD_SWAN_EOF'
connections {
  nordvpn {
    version = 2
    send_cert = never
    local_addrs = %defaultroute
    remote_addrs = 193.29.107.10
    proposals = aes256-sha256-modp2048, aes256-sha1-modp2048, aes128-sha256-modp2048
    reauth_time = 0s
    fragmentation = yes
    mobike = yes
    local {
      auth = eap
      eap_id = "svcuser"
    }
    remote {
      auth = pubkey
      id = %any
    }
    vips = 0.0.0.0
    dpd_delay = 60s
    children {
      nord {
        remote_ts = 0.0.0.0/0
        local_ts = dynamic
        start_action = start
        close_action = restart
        esp_proposals = aes256-sha256, aes256-sha1, aes128-sha256
        rekey_time = 3600s
      }
    }
  }
}
secrets {
  eap-nord {
    secret = "svcpass"
  }
}
NORD_SWAN_EOF

chmod 600 /etc/swanctl/conf.d/nordvpn-ikev2.conf

# charon is not under procd here: start it from rc.local after the network
grep -q 'nordvpn-ikev2-charon' /etc/rc.local 2>/dev/null || cat >> /etc/rc.local << 'NORD_RC_EOF'
# nordvpn-ikev2-charon
( sleep 8; /usr/lib/ipsec/charon >/dev/null 2>&1; ) &
( sleep 20; swanctl --load-all >/dev/null 2>&1; swanctl --initiate --child nord >/dev/null 2>&1; ) &
NORD_RC_EOF

# also bring it up right now (first boot)
( sleep 8; /usr/lib/ipsec/charon >/dev/null 2>&1; ) &
( sleep 20; swanctl --load-all >/dev/null 2>&1; swanctl --initiate --child nord >/dev/null 2>&1; ) &
echo "NordVPN IKEv2 staged: server de500.nordvpn.com (193.29.107.10), hw_accel=on"
VPN_SETUP_EOF
sh /tmp/nordvpn_ikev2_setup.sh

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
uci set firewall.vpn_zone.network='ipsec0'
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
nft add rule inet fw4 input_wan udp dport { 500, 4500 } accept comment 'IKE/NAT-T' 2>/dev/null; nft add rule inet fw4 input_wan meta l4proto esp accept comment 'ESP' 2>/dev/null; true

# --- VPN DNS through tunnel ---
uci del_list dhcp.@dnsmasq[0].server='103.86.96.100' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='103.86.96.100'
uci del_list dhcp.@dnsmasq[0].server='103.86.99.100' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='103.86.99.100'
uci set dhcp.@dnsmasq[0].noresolv='1'