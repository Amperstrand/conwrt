# golden: conwrt 1.x output of scripts/use_cases/fips_bluetooth_rfcomm.py build_configure — regenerate with the command in tests/use_case_goldens.rs
mkdir -p /etc/fips
echo 'node:' > /etc/fips/fips.yaml
echo '  identity:' >> /etc/fips/fips.yaml
echo '    persistent: true' >> /etc/fips/fips.yaml
echo '' >> /etc/fips/fips.yaml
echo 'tun:' >> /etc/fips/fips.yaml
echo '  enabled: true' >> /etc/fips/fips.yaml
echo '' >> /etc/fips/fips.yaml
echo 'dns:' >> /etc/fips/fips.yaml
echo '  enabled: true' >> /etc/fips/fips.yaml
echo '' >> /etc/fips/fips.yaml
echo 'transports:' >> /etc/fips/fips.yaml
echo '  rfcomm:' >> /etc/fips/fips.yaml
echo '    mode: "client"' >> /etc/fips/fips.yaml
echo '    channel: 1' >> /etc/fips/fips.yaml
echo '    mtu: 1000' >> /etc/fips/fips.yaml
echo '    auto_connect: true' >> /etc/fips/fips.yaml
echo '' >> /etc/fips/fips.yaml
echo 'peers: []' >> /etc/fips/fips.yaml
echo '' >> /etc/fips/fips.yaml
echo 'gateway:' >> /etc/fips/fips.yaml
echo '  enabled: true' >> /etc/fips/fips.yaml
echo '  pool: "fd01::/112"' >> /etc/fips/fips.yaml
echo '  lan_interface: "br-lan"' >> /etc/fips/fips.yaml
echo '  dns:' >> /etc/fips/fips.yaml
echo '    listen: "[::1]:5353"' >> /etc/fips/fips.yaml
echo '    upstream: "[::1]:5354"' >> /etc/fips/fips.yaml
echo '    ttl: 60' >> /etc/fips/fips.yaml
echo '0000' > /etc/fips/bt-pin
echo '#!/bin/sh /etc/rc.common' > /etc/init.d/bt-agent
echo 'START=98' >> /etc/init.d/bt-agent
echo 'STOP=10' >> /etc/init.d/bt-agent
echo 'start() {' >> /etc/init.d/bt-agent
echo '    hciconfig hci0 up' >> /etc/init.d/bt-agent
echo '    command -v bt-agent >/dev/null 2>&1 && bt-agent -c NoInputNoOutput -p /etc/fips/bt-pin &' >> /etc/init.d/bt-agent
echo '}' >> /etc/init.d/bt-agent
echo 'stop() {' >> /etc/init.d/bt-agent
echo '    killall bt-agent 2>/dev/null' >> /etc/init.d/bt-agent
echo '}' >> /etc/init.d/bt-agent
chmod +x /etc/init.d/bt-agent
/etc/init.d/bt-agent enable
echo '#!/bin/sh /etc/rc.common' > /etc/init.d/fips
echo 'START=99' >> /etc/init.d/fips
echo 'STOP=10' >> /etc/init.d/fips
echo 'start() {' >> /etc/init.d/fips
echo '    fips -c /etc/fips/fips.yaml &' >> /etc/init.d/fips
echo '}' >> /etc/init.d/fips
echo 'stop() {' >> /etc/init.d/fips
echo '    killall fips 2>/dev/null' >> /etc/init.d/fips
echo '}' >> /etc/init.d/fips
chmod +x /etc/init.d/fips
/etc/init.d/fips enable
echo 'FIPS Bluetooth RFCOMM configured (client, channel 1, 0 peer(s))'