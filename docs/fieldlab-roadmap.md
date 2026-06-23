# Field Lab Roadmap

## Milestone 1: Observation + Discovery (COMPLETE)

All commands implemented, tested on live hardware (x1860 field router +
GL-AR300M target), 57 unit tests, lint/typecheck clean.

| Command | What it does | Status |
|---------|-------------|--------|
| `inspect` | Collect field router state, detect probe interface | ✅ live tested |
| `capture` | Remote tcpdump → local pcap via SSH streaming | ✅ live tested |
| `discover` | ARP/ping/port-scan from field router | ✅ live tested |
| `fingerprint` | Full SSH identity via ProxyJump | ✅ live tested |
| `forward` | SSH -L port-forward to target services | ✅ live tested |
| `serve dhcp` | Temporary DHCP scope via UCI/dnsmasq | ✅ live tested |
| `serve tftp` | Temporary TFTP server via dnsmasq | ✅ scaffolded |
| `prepare-probe` | Probe-port state report + optional cleanup | ✅ live tested |

### Proven on hardware
- Captured AR300 boot sequence (U-Boot → OpenWrt transition, dual-MAC)
- Fingerprinted AR300 as GL-AR300M NAND via ProxyJump
- Forwarded AR300's LuCI to Mac at http://127.0.0.1:18080
- Served DHCP on non-colliding subnet, cleanup verified

## Milestone 2: Agent-Mode Flash (NEXT)

Use the field router to flash the unknown device through the probe port.

### 2a: SSH sysupgrade (target running OpenWrt)
```
fieldlab fingerprint → model match → download image → scp + sysupgrade
```
- AR300 is already SSH-accessible via ProxyJump
- conwrt's `sysupgrade` flash method works through SSH
- Need: `fieldlab flash --host root@10.89.4.1 --target 192.168.1.1`
  that wraps the sysupgrade flow through ProxyJump

### 2b: TFTP netboot (target in U-Boot mode)
```
fieldlab capture → detect U-Boot ARP pattern → serve tftp with firmware → reboot
```
- AR300 in U-Boot looks for TFTP at 192.168.1.2
- `serve tftp` is scaffolded, needs testing with real firmware
- Need: firmware resolution via `profile/target.py` (pending from Session 1)

### 2c: Recovery HTTP (target in recovery mode)
```
fieldlab discover → detect recovery HTTP → forward port 80 → upload firmware
```
- conwrt already has recovery-http handler
- Need: wire it through the field-lab forward tunnel

## Milestone 3: Opencode Backchannel

When the target is an unknown model (not in `models/`), feed field-lab
artifacts to opencode for Stage 1 AI-assisted discovery.

```
fieldlab capture → pcap artifacts
fieldlab discover → findings.json
fieldlab fingerprint → identity
                    ↓
opencode (on Mac) ← artifacts → models/*.json (new entry)
                    ↓
fieldlab flash → now a known model → milestone 2 flow
```

## Future Direction

- **Wireshark extcap** — wrap `capture` as an extcap interface for live
  Wireshark streaming from the remote probe port
- **True L2 TAP** — WireGuard/UDP tunnel + TAP interfaces so the Mac gets
  a virtual Ethernet interface on the probe subnet
- **FIPS transport** — allowlisted node identities, gated root SSH over
  a FIPS mesh network
- **Platform abstraction** — extract shared `network_ops.py` (see
  `docs/architecture-analysis.md` for the recommendation)
- **Power/serial integrations** — USB-serial relay, camera for LEDs

## Known Limitations

1. **IP collision** — if field router br-lan and target share a subnet,
   L3 access is blocked (L2 capture still works). Fix: `conwrt lan-migrate`.
2. **python3 missing on field router** — port scanner falls back to nc,
   which is less reliable. Fix: install python3-light via opkg.
3. **DHCP port-67 conflict** — can't run standalone dnsmasq alongside the
   primary. Fix: UCI scope approach (already implemented).
4. **Single-platform serve** — `serve dhcp/tftp` only works on OpenWrt
   (uses UCI). macOS/Linux fallbacks not yet implemented.
5. **No full test suite run** — some existing tests from other sessions
   hang (test_lan_migrate, test_build_ipk, test_handlers_oem). Fieldlab's
   57 tests all pass independently.
