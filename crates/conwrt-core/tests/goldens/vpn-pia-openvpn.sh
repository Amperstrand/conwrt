# golden: conwrt 1.x output of scripts/use_cases/vpn_providers/pia.py build_configure — regenerate with the command in tests/use_case_goldens.rs
# --- PIA OpenVPN (udp/8080, 10-endpoint pool, remote-random) ---
cat > /tmp/pia_openvpn_setup.sh << 'VPN_SETUP_EOF'
# Clean up old WireGuard interface + peers
uci -q delete network.wg0
while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do
    uci delete network.@wireguard_wg0[0]
done


# Tear down any previous OpenVPN instance
uci -q delete openvpn.pia

mkdir -p /etc/openvpn
cat > /etc/openvpn/pia-ca.rsa.4096.crt << 'PIA_CA_EOF'
-----BEGIN CERTIFICATE-----
MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV
BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu
dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx
IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB
FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw
MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex
EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg
QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE
AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50
ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy
bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk
hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN
De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K
V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ
25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND
fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl
p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p
Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj
tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi
jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz
meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz
1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV
HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt
yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl
cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw
HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0
ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl
aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq
hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt
pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv
Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G
tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu
LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs
6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3
5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX
JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ
iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l
8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW
+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=
-----END CERTIFICATE-----
PIA_CA_EOF
cat > /etc/openvpn/pia.auth << 'PIA_AUTH_EOF'
p1234567
testpass
PIA_AUTH_EOF
chmod 600 /etc/openvpn/pia.auth

uci set openvpn.pia=openvpn
uci set openvpn.pia.enabled='1'
uci set openvpn.pia.client='1'
uci set openvpn.pia.dev='tun'
uci set openvpn.pia.proto='udp'
uci add_list openvpn.pia.remote='151.241.122.99 8080'
uci add_list openvpn.pia.remote='37.19.197.168 8080'
uci add_list openvpn.pia.remote='151.241.119.192 8080'
uci add_list openvpn.pia.remote='37.19.220.37 8080'
uci add_list openvpn.pia.remote='181.41.206.48 8080'
uci add_list openvpn.pia.remote='102.129.153.205 8080'
uci add_list openvpn.pia.remote='145.79.182.176 8080'
uci add_list openvpn.pia.remote='193.56.117.160 8080'
uci add_list openvpn.pia.remote='191.96.106.197 8080'
uci add_list openvpn.pia.remote='173.239.198.91 8080'
uci set openvpn.pia.remote_random='1'
uci set openvpn.pia.resolv_retry='infinite'
uci set openvpn.pia.nobind='1'
uci set openvpn.pia.persist_key='1'
# NO persist_tun (validated lesson): a dead tunnel must tear its routes
# down, not blackhole the LAN behind stale routes.
uci set openvpn.pia.ca='/etc/openvpn/pia-ca.rsa.4096.crt'
uci set openvpn.pia.auth_user_pass='/etc/openvpn/pia.auth'
uci set openvpn.pia.auth_nocache='1'
uci set openvpn.pia.remote_cert_tls='server'
uci set openvpn.pia.data_ciphers='AES-256-GCM:AES-128-GCM:AES-256-CBC'
uci set openvpn.pia.data_ciphers_fallback='AES-256-CBC'
uci set openvpn.pia.auth='sha256'
uci set openvpn.pia.reneg_sec='0'
uci set openvpn.pia.disable_occ='1'
uci set openvpn.pia.mssfix='1420'
uci set openvpn.pia.verb='3'
uci set openvpn.pia.pull='1'
# PIA has no IPv6: it pushes route-ipv6/ifconfig-ipv6 anyway, which
# blackholes v6 on the v4-only tun0 (broke Signal on the validated box).
uci add_list openvpn.pia.pull_filter='ignore "route-ipv6"'
uci add_list openvpn.pia.pull_filter='ignore "ifconfig-ipv6"'
uci commit openvpn

# pin the endpoint pool's route to the upstream (no v4 route via tun)
for _pia_ep in 151.241.122.99 37.19.197.168 151.241.119.192 37.19.220.37 181.41.206.48 102.129.153.205 145.79.182.176 193.56.117.160 191.96.106.197 173.239.198.91; do
    ip route replace $_pia_ep/32 via 192.168.8.1 dev wan 2>/dev/null || true
done
# tun0 joins the vpn zone (wg0 was removed by the cleanup above)
uci -q del_list firewall.vpn_zone.network='wg0'
uci -q add_list firewall.vpn_zone.network='tun0'
/etc/init.d/openvpn restart || /etc/init.d/openvpn start
VPN_SETUP_EOF
sh /tmp/pia_openvpn_setup.sh

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
uci del_list dhcp.@dnsmasq[0].server='10.0.0.241' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='10.0.0.241'
uci del_list dhcp.@dnsmasq[0].server='10.0.0.242' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='10.0.0.242'
uci del_list dhcp.@dnsmasq[0].server='10.0.0.243' 2>/dev/null; true
uci add_list dhcp.@dnsmasq[0].server='10.0.0.243'
uci set dhcp.@dnsmasq[0].noresolv='1'
uci commit network
uci commit firewall
uci commit dhcp
/etc/init.d/network restart
/etc/init.d/dnsmasq restart
i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart
