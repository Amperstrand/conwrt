# Flash Runbook: Asus Lyra MAP-AC2200 + TollGate

Date: 2026-06-04
Operator: [connected later today]

## Assets (pre-downloaded)

| Asset | Location | Size |
|-------|----------|------|
| conwrt ipk | `/tmp/conwrt_0.0.0-alpha.127+3c8db7b_all.ipk` | 214KB |
| TollGate ipk | `/tmp/tollgate-wrt_main.104.8ec5342_arm_cortex-a7.ipk` | 7.3MB |

Both are on the laptop. TollGate is tip-of-main (commit `8ec5342`, CI run #1176, 2026-06-03).

## Device info

- Model: Asus Lyra MAP-AC2200
- SoC: IPQ4019 (arm_cortex-a7)
- Target: ipq40xx/generic
- OpenWrt: 24.10.4
- State: **unknown** (stock, OpenWrt, or off — detect when connected)

## Step 0: Physical setup

1. Connect ethernet between laptop and Lyra
2. Try **both ports** — port assignments vary by hardware batch:
   - Batch `10:7b:44` → LAN = port next to power
   - Batch `2c:fd:a1` → LAN = port far from power
3. Power on the Lyra
4. Watch LED:
   - Solid white → stock firmware, ready for setup
   - Breathing colors → booting
   - Steady blue → OpenWrt running
   - No LED → dead/no power

## Step 1: Detect device state

```bash
# Check if OpenWrt is running (root, no password)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@192.168.1.1 "cat /etc/openwrt_release" 2>/dev/null

# Check if stock firmware is running (admin:admin after reset, or CVE chain)
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@192.168.1.1 "echo hello" 2>/dev/null

# Check MAC to determine port batch
arp -a | grep 192.168.1.1
```

## Step 2: Flash OpenWrt (depends on state)

### If running OpenWrt already → sysupgrade

Request a custom ASU image with nodogsplash baked in:

```bash
cd ~/src/conwrt
source .venv/bin/activate
python3 scripts/firmware-manager.py request \
  --profile asus_map-ac2200 \
  --packages nodogsplash libustream-wolfssl ca-bundle ca-certificates \
  --ssh-key ~/.ssh/id_ed25519.pub
```

Then sysupgrade:
```bash
python3 scripts/conwrt.py flash \
  --model-id asus-lyra-map-ac2200 \
  --request-image --no-voice
```

### If running stock firmware → stock-ssh-mtd (two-stage)

**Stage 1: Enable SSH on stock**

If factory default (white LED), use CVE chain:
```bash
# CVE-2021-32030 null-byte auth bypass + CVE-2018-5999 apply.cgi
# conwrt handles this automatically
```

If already configured, use web UI credentials.

**Stage 2: Write initramfs**
```bash
# Download initramfs
curl -O https://downloads.openwrt.org/releases/24.10.4/targets/ipq40xx/generic/openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-initramfs-uImage.itb

# SCP to device (use -O for dropbear compat)
scp -O openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-initramfs-uImage.itb admin@192.168.1.1:/tmp/

# Write to linux partition
ssh admin@192.168.1.1 "mtd-unlock -d linux && mtd-write -d linux -i /tmp/openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-initramfs-uImage.itb && reboot -f"
```

Wait 5 min. LED: breathing → blink blue → steady blue.

**Stage 3: Sysupgrade from initramfs**
```bash
# Request custom ASU image with tollgate deps
python3 scripts/firmware-manager.py request \
  --profile asus_map-ac2200 \
  --packages nodogsplash libustream-wolfssl ca-bundle ca-certificates \
  --ssh-key ~/.ssh/id_ed25519.pub

# Or use stock sysupgrade image
curl -O https://downloads.openwrt.org/releases/24.10.4/targets/ipq40xx/generic/openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-squashfs-sysupgrade.bin

scp -O openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-squashfs-sysupgrade.bin root@192.168.1.1:/tmp/
ssh root@192.168.1.1 "sysupgrade -n /tmp/openwrt-24.10.4-ipq40xx-generic-asus_map-ac2200-squashfs-sysupgrade.bin"
```

Wait 10 min (NAND first boot).

## Step 3: Deploy TollGate

After OpenWrt boots and SSH is verified:

```bash
# Install TollGate ipk (pre-downloaded)
scp -O /tmp/tollgate-wrt_main.104.8ec5342_arm_cortex-a7.ipk root@192.168.1.1:/tmp/tollgate-wrt.ipk
ssh root@192.168.1.1 "opkg install /tmp/tollgate-wrt.ipk && /etc/init.d/tollgate-wrt enable"

# Install conwrt on the router (for router-to-router flashing)
scp -O /tmp/conwrt_0.0.0-alpha.127+3c8db7b_all.ipk root@192.168.1.1:/tmp/
ssh root@192.168.1.1 "opkg install /tmp/conwrt_0.0.0-alpha.127+3c8db7b_all.ipk"
```

## Step 4: Configure TollGate

```bash
ssh root@192.168.1.1
# Set mint URL, lightning address, price
uci set tollgate.@tollgate[0].mint_url='https://mint.example.com'
uci set tollgate.@tollgate[0].lightning_address='user@domain.com'
uci set tollgate.@tollgate[0].price_per_minute='1'
uci commit tollgate
/etc/init.d/tollgate-wrt restart
```

## Step 5: Verify

```bash
# Check tollgate is running
ssh root@192.168.1.1 "/etc/init.d/tollgate-wrt status"

# Check conwrt works
ssh root@192.168.1.1 "conwrt --version"

# Check nodogsplash
ssh root@192.168.1.1 "/etc/init.d/nodogsplash status"

# Check WiFi radios
ssh root@192.168.1.1 "iwinfo | grep -E 'ESSID|Mode'"
```

## Rollback

If anything goes wrong:
- **OpenWrt bricked**: Serial TFTP at header J35, or ASUS Firmware Restore tool
- **TollGate broken**: `opkg remove tollgate-wrt` and re-install
- **Network unreachable**: Factory reset via reset button (5 seconds, NOT 10+ which enters rescue mode)

## Safety reminders

- **NEVER** use `sysupgrade -F` (bypasses hardware validation = brick risk)
- **Always** verify board name matches: `cat /tmp/sysinfo/board_name` should say `asus,map-ac2200`
- **Always** use `scp -O` (dropbear has no sftp-server)
- After initramfs flash, cable MUST be on middle port (LAN in OpenWrt)
