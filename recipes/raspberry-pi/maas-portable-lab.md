# MAAS Portable Lab: Raspberry Pi 4B + D-Link COVR-X1860

A self-contained, portable Metal-as-a-Service deployment using two devices
and one USB disk. Boots, provisions, and manages physical or virtual servers
over a dedicated bench network with wireless internet uplink.

## Architecture

```
                    ┌─────────────────────┐
     "5" SSID ──────┤ x1860 (OpenWrt)     │
     5GHz WiFi      │ "maas-bench"        │
     (uplink+mgmt)  │ wwan: <uplink-ip>   │
                    │ br-bench: 10.50.0.1 │
                    │ DHCP: OFF (MAAS     │
                    │  owns it)           │
                    └────┬─────────┬──────┘
                         │         │
                    LAN1 │    WAN  │ (both ports bridged)
                         │         │
              ┌──────────┴──┐  ┌──┴──────────┐
              │ Raspberry   │  │ MAAS-managed│
              │ Pi 4B       │  │ server (or  │
              │ 10.50.0.5   │  │ QEMU test   │
              │ MAAS        │  │ VM)         │
              │ region+rack │  │ DHCP from   │
              │ on USB disk │  │ MAAS pool   │
              └─────────────┘  └─────────────┘
```

## Hardware Requirements

| Component | Model | Notes |
|-----------|-------|-------|
| Router | D-Link COVR-X1860 A1 | Flashed with OpenWrt 25.12.x via conwrt recovery-http |
| SBC | Raspberry Pi 4B (4GB) | EEPROM BOOT_ORDER=0xf241 (SD→USB→NET) |
| Storage | USB 3.0 SSD, ≥32GB | Via ASM1153E or similar reliable bridge |
| Power | USB-C PD for Pi, DC for x1860 | Standard chargers |

## Network Plan (parameterized)

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BENCH_SUBNET` | 10.50.0.0/24 | MAAS management network |
| `BENCH_GATEWAY` | 10.50.0.1 | x1860 bridge IP |
| `MAAS_IP` | 10.50.0.5 | Static IP for the Pi |
| `DHCP_RANGE_START` | 10.50.0.100 | MAAS dynamic pool start |
| `DHCP_RANGE_END` | 10.50.0.200 | MAAS dynamic pool end |
| `UPLINK_SSID` | (required) | WiFi network for internet |
| `UPLINK_PASSWORD` | (required) | WiFi password |
| `MANAGEMENT_IP` | (from DHCP) | x1860's address on the uplink network |
| `MAAS_ADMIN_PASSWORD` | (generated) | MAAS admin credentials |

## Deployment Time

| Phase | Time | Notes |
|-------|------|-------|
| x1860 flash (recovery-http) | ~5 min | conwrt proven method |
| x1860 bench config | ~2 min | Scripted uci commands |
| USB disk flash | ~8 min | dd + verify + partition + inject |
| Pi first boot (cloud-init) | ~15 min | MAAS snap install + init + config |
| Image sync | ~10 min | Ubuntu noble amd64 |
| QEMU enlistment test | ~5 min | With KVM on x86 host |
| **Total** | **~45 min** | From boxes to working MAAS |

## Performance Characteristics (measured)

| Metric | Value | Context |
|--------|-------|---------|
| MAAS API response | <1s | Region API on Pi 4B |
| DHCP offer latency | <100ms | Bench network |
| PXE → iPXE → kernel | ~30s | Wired, boot resources from SSD |
| Ephemeral download | ~600MB @ ~10MB/s | Pi SSD → VM (wired gigabit) |
| Ephemeral boot (KVM) | ~3 min | Including cloud-init |
| Image sync (WiFi) | ~10 min for ~1.5GB | Rate-limited by upstream |
| Pi temperature (idle) | 52-56°C | Passive cooling sufficient |
| Pi temperature (load) | 62-67°C | Below 80°C throttle |
| Memory usage | 1.7-2.2 GiB / 3.7 GiB | With zram 75% + 2GB swap |

## Known Limitations

1. **Single point of failure**: One Pi, one x1860, one disk
2. **WiFi uplink**: Image sync and ephemeral boot downloads are WiFi-bound
3. **VL711 bridge**: The specific USB-SATA bridge used has warm-reboot issues
4. **Temporal workflows**: MAAS 3.6.6/3.7.3 have intermittent workflow deadlocks
5. **No HA**: Single rack controller, no failover

## Prerequisites

### On the flashing host (any Linux box):
- conwrt repository cloned
- Python 3.10+
- SSH key for the Pi (`~/.ssh/id_ed25519.pub`)
- The Ubuntu Server 26.04 arm64+raspi image downloaded and verified

### EEPROM on the Pi:
- `BOOT_ORDER=0xf241` (SD→USB→NET, netboot-last)
- `ENABLE_SELF_UPDATE=1` (for EEPROM updates over network)

## Deployment Steps

### Phase 1: Flash the x1860

```bash
# Using conwrt's proven recovery-http method
python3 scripts/conwrt.py --model-id dlink-covr-x1860-a1 \
    --image <openwrt-image.bin> --flash-method recovery-http
```

### Phase 2: Configure the x1860 as bench router

Apply the bench-mode configuration:
- Bridge both ports into `br-bench`
- Set LAN IP to `10.50.0.1/24`
- Disable DHCP on the bridge (MAAS will own it)
- Configure 5GHz WiFi STA for uplink
- Enable SSH from the uplink network
- Add firewall pinholes for MAAS API access

### Phase 3: Flash the USB disk

On any Linux host:
1. Verify image checksum
2. dd to the USB disk (with serial-whitelist safety checks)
3. Resize partition to 50GB (fast fsck)
4. Inject cloud-init user-data + network-config + meta-data

### Phase 4: Boot the Pi

1. Insert USB disk into Pi's blue USB 3.0 port
2. Connect Pi's ethernet to x1860 (either port)
3. Power on
4. Wait ~15 minutes for cloud-init to complete
5. Watch beacons on `udp/6667` for progress

### Phase 5: Verify

```bash
# From any machine on the bench:
ssh ubuntu@10.50.0.5
sudo maas status  # Should show regiond, rackd, dhcpd active
```

### Phase 6: Test enlistment (QEMU)

On any x86 Linux host on the bench network:
```bash
qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 1024 \
    -netdev bridge,br=br-bench,id=net0 \
    -device e1000,netdev=net0 \
    -boot n -nographic
```

The VM PXE boots from MAAS, downloads the ephemeral image,
runs cloud-init enlistment, and appears as a New machine.

## Self-Flashing Architecture (future)

The x1860's TFTP capability can eliminate the third-party flashing host:

```
1. x1860 serves a minimal netboot kernel via TFTP
2. Pi's EEPROM falls through to network boot (BOOT_ORDER includes NET)
3. Netboot kernel runs a minimal Linux with:
   - USB disk detection + serial verification
   - Image download (HTTP from x1860 or direct from internet)
   - dd to USB disk with safety checks
   - cloud-init injection
   - Reboot from USB
4. Pi boots into MAAS, zero external computers involved
```

This requires:
- A minimal initramfs with USB + network + dd capability
- HTTP file serving on the x1860 (uhttpd already present)
- The Ubuntu image cached on the x1860's flash or fetched on-demand

## Rust Alignment

conwrt's target is Rust. This use case prepares for that transition:

1. **Use case definition** mirrors what would become a Rust struct with
   serde deserialization from TOML/JSON
2. **Parameterization** uses the same pattern as conwrt's existing
   use_cases system (declarative config)
3. **The bench-mode uci script** translates directly to a Rust function
   that generates uci commands via SSH
4. **The flash script** patterns (verify → write → verify → inject)
   map to a Rust pipeline with type-safe checksums
5. **Beacon/monitoring** aligns with a Rust systemd service generating
   structured events

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Pi won't boot from USB | VL711 warm-reboot issue | Power cycle (never warm reboot) |
| dhcpd not listening | MAAS temporal deadlock | Check dhcpd.conf has subnet block |
| Image sync stalled | Rate limiting or workflow deadlock | Wipe image-storage, re-import |
| QEMU DHCP timeout | STP on bridge port | `ip link set br-bench type bridge stp_state 0` |
| No beacons received | Listener IP wrong | Check laptop has 10.50.0.127 |
| SSH to Pi fails via WiFi | Firewall pinhole missing | Check x1860 firewall rules |
