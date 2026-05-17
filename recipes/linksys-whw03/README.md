# Linksys Velop WHW03 — OpenWrt Migration (V1 and V2)

## V1 vs V2 Differences

| Field | WHW03 V1 | WHW03 V2 |
|-------|----------|----------|
| **Flash storage** | **4GB eMMC** | **512MB NAND** (Macronix MX30LF4G18AC) |
| **OpenWrt device name** | `linksys_whw03` | `linksys_whw03v2` |
| **Factory image filename** | `*-linksys_whw03-squashfs-factory.bin` | `*-linksys_whw03v2-squashfs-factory.bin` |
| **Support PR** | #15384 (Lanchon) | #11602 (vtremblay) |
| **Default password (firmware 1.x)** | `admin` (HTTP only, HTTPS may differ) | `admin` |
| **Default password (firmware 2.x)** | `admin` | `admin` |
| **SoC** | Qualcomm IPQ4019 | Qualcomm IPQ4019 |
| **RAM** | 512MB DDR3 | 512MB DDR3 |
| **WiFi** | Tri-band (IPQ4019 + QCA9888) | Tri-band (IPQ4019 + QCA9888) |
| **Ethernet** | 2x GbE (QCA8072) | 2x GbE (QCA8072) |
| **Dual partition** | Yes (3-boot rollback) | Yes (3-boot rollback) |
| **OpenWrt target** | ipq40xx/generic | ipq40xx/generic |

### How to tell them apart

Use the JNAP `GetDeviceInfo` endpoint (works unauthenticated on factory-reset devices):

```bash
curl -sk -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://linksys.com/jnap/core/GetDeviceInfo" \
  -d '{}' http://192.168.1.1/JNAP/ | jq '.output.hardwareVersion'
```

- Returns `"1"` → V1 (eMMC)
- Returns `"2"` → V2 (NAND)

### Passive identification (from packet capture)

LLDP frames broadcast by the Velop contain:
- System name: `"Velop"`
- Chassis name: `"nodes"`
- OS: `"Linux 3.14.77 #1 SMP PREEMPT"`
- Management IP: `192.168.1.1` (factory default)
- Port: `"eth1"`

MAC OUI prefixes seen:
- `E8:9F:80` (Belkin) — V2 devices
- `14:91:82` (Belkin/Linksys) — V1 devices

## Flashing Procedure

### Prerequisites
1. Factory-reset the device (hold reset 10+ seconds until LED flashes red)
2. Connect via wired ethernet to the device
3. Device should be at 192.168.1.1

### Default Credentials (after factory reset)
- Username: `admin`
- Password: `admin`
- Note: V1 with firmware 1.x may accept `admin:admin` only via HTTP, not HTTPS
- Important: immediately after a reset, link and DHCP may come up before JNAP or `/fwupdate.html` respond. Wait for service readiness, not just carrier.

### Method: curl (no browser needed)

```bash
# 1. Identify device and get hardware version
HWVER=$(curl -sk -X POST \
  -H "Content-Type: application/json; charset=UTF-8" \
  -H "X-JNAP-Action: http://linksys.com/jnap/core/GetDeviceInfo" \
  -d '{}' http://192.168.1.1/JNAP/ | jq -r '.output.hardwareVersion')

# 2. Select the correct firmware
if [ "$HWVER" = "1" ]; then
  FIRMWARE="openwrt-24.10.6-ipq40xx-generic-linksys_whw03-squashfs-factory.bin"
else
  FIRMWARE="openwrt-24.10.6-ipq40xx-generic-linksys_whw03v2-squashfs-factory.bin"
fi

# 3. Verify default password works
curl -sk -o /dev/null -w '%{http_code}' -u "admin:admin" http://192.168.1.1/fwupdate.html
# Should return 200

# 4. Upload firmware
curl -sk --max-time 300 \
  -u "admin:admin" \
  -F "X-JNAP-Action=updatefirmware" \
  -F "X-JNAP-Authorization=Basic YWRtaW46YWRtaW4=" \
  -F "upload=@$FIRMWARE;type=application/octet-stream" \
  https://192.168.1.1/jcgi/
# Should return {"result":"OK"}

# 5. Wait several minutes for reboot on V1 eMMC devices, then verify
ssh -o StrictHostKeyChecking=no root@192.168.1.1
```

### Rollback
If OpenWrt fails to boot, power-cycle the device 3 times in a row (off/on within 2 seconds each). The bootloader will revert to the stock firmware partition.

## Firmware Download

```
# V1 (eMMC)
https://downloads.openwrt.org/releases/24.10.6/targets/ipq40xx/generic/openwrt-24.10.6-ipq40xx-generic-linksys_whw03-squashfs-factory.bin

# V2 (NAND)
https://downloads.openwrt.org/releases/24.10.6/targets/ipq40xx/generic/openwrt-24.10.6-ipq40xx-generic-linksys_whw03v2-squashfs-factory.bin
```

## Post-Flash Configuration

```bash
SSH_PUBKEY=$(cat /path/to/ssh-key.pub)
WIFI_SSID="your-network"
WIFI_PASS="your-password"
HOSTNAME=$(echo -n "AA:BB:CC:DD:EE:FF" | sha256sum | cut -c1-12)

ssh root@192.168.1.1 "
  uci set system.@system[0].hostname='$HOSTNAME'
  uci commit system
  echo '$HOSTNAME' > /proc/sys/kernel/hostname

  mkdir -p /etc/dropbear
  echo '$SSH_PUBKEY' > /etc/dropbear/authorized_keys
  chmod 600 /etc/dropbear/authorized_keys

  uci set wireless.radio1.disabled='0'
  uci set wireless.radio1.channel='auto'
  uci set wireless.default_radio1.mode='sta'
  uci set wireless.default_radio1.ssid='$WIFI_SSID'
  uci set wireless.default_radio1.encryption='psk2'
  uci set wireless.default_radio1.key='$WIFI_PASS'
  uci set wireless.default_radio1.network='wan'

  uci set network.wan.device='phy1-sta0'
  uci set network.wan.proto='dhcp'
  uci commit network
  uci commit wireless

  uci set firewall.@zone[1].input='ACCEPT'
  uci commit firewall

  uci set dropbear.main.PasswordAuth='off'
  uci set dropbear.main.RootPasswordAuth='off'
  uci commit dropbear

  wifi reload
"
sleep 15
ssh root@192.168.1.1 '/etc/init.d/dropbear restart'
```

## Known Issues

- **Warm reboot bug**: Some 24.10.x builds may hang on reboot. Fixed by running `opkg upgrade` after first boot.
- **Channel restrictions**: Stock builds limit 5GHz channels. Extra-channel builds available in GitHub issue #15048.
- **Reset timing**: After factory reset, `192.168.1.1` may answer ping or DHCP before JNAP and `/fwupdate.html` are ready. Wait until management endpoints respond before concluding that `admin:admin` is wrong.
- **V1 first boot duration**: WHW03 V1 eMMC first boot after stock-to-OpenWrt flash can exceed 2 minutes. If packet capture shows `OpenWrt.lan`, DHCP offers, ARP replies, or IPv6 router advertisements, the flash likely succeeded even if earlier polling timed out.
- **Missing MAC in GetDeviceInfo**: Some V1 stock responses omit `macAddresses`. Use ARP or packet capture to recover the router MAC.

## Session Notes

See [`NOTES.md`](./NOTES.md) for the detailed operator playbook from the April 2026 flash session, including port selection guidance, capture interpretation, service-readiness timing, and recovery behavior.

## References

- V1 Wiki: https://openwrt.org/toh/linksys/whw03_v1
- V2 Wiki: https://openwrt.org/toh/linksys/whw03_v2
- V1 Support PR: https://github.com/openwrt/openwrt/pull/15384
- V2 Support PR: https://github.com/openwrt/openwrt/pull/11602
- DeviWiki V2: https://deviwiki.com/wiki/Linksys_Velop_(WHW03_V2)
