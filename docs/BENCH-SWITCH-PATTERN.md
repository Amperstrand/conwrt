# The Bench-Switch Pattern — labgrid-ready OpenWrt PoE switches

The authoritative recipe for deploying and managing bench/PoE switches
(GS1900-8HP and siblings) the conwrt way. **Proven end-to-end 2026-09-22**:
the 8HP was backed up, factory-reset, and redeployed from scratch over
serial by `scripts/bench_switch.py` — config, keys, DHCP, firewall, and the
Amperstrand realtek-poe fork — then reboot-verified unattended.

## Architecture

```
ERX (house router) ──eth2──→ switch lan1      uplink: VLAN 1 untagged
                              lan1 also tags VLANs 100N (trunk flexibility)
switch management: 192.168.13.2 on switch.1 (static, gw 192.168.13.1)
DUT bay: lan2..lan8, each port isolated in bridge-vlan 100N
  switch L3:  192.168.10N.1/24 (mnemonic: VLAN 1003 → 192.168.103.1)
  DUT DHCP:   192.168.10N.50-150 (dnsmasq per VLAN; rogue-DHCP-safe:
              isolated VLANs, and dhcp.lan.ignore=1 keeps mgmt VLAN quiet)
PoE: realtek-poe fork (github.com/Amperstrand/realtek-poe, ai-experiments),
     ubus interface: poe.info / poe.manage {"port":"lanN","action":"..."}
     uplink port PoE off, DUT ports on
Firewall: all dut100N interfaces in the lan zone (input ACCEPT — otherwise
     fw4 silently drops management SSH on unzoned interfaces; see lessons)
```

## Why each piece

- **Uplink on VLAN 1 via the router** — the switch is always reachable from
  the house network (Mac, ai-legion, ERX) at one stable IP. No dependency on
  any bench host.
- **Per-port VLAN isolation** — DUTs cannot see each other or the house LAN;
  parallel tests are safe; a misbehaving DUT poisons only its port.
- **Mnemonic DUT subnets** — VLAN 100N ↔ 192.168.10N.0/24. No overlapping
  subnets anywhere (the trap that cost hours on 2026-09-22).
- **Serial as bootstrap-only** — post-firstboot there are no keys and no
  password; the serial console (115200, askfirst, root) is the entry point.
  Once deployed, the box is network-managed and the serial adapter moves on.

## The from-scratch procedure (proven)

Prereqs: serial adapter on the deploy host (`pyserial`), the switch's PoE
backup artifacts (`bench_switch.py backup` output), the deploy host's pubkey.

```bash
# 0. backup the CURRENT state (never skip; the artifacts also carry the fork)
python3 scripts/bench_switch.py backup --host <ip> --out data/backups/<switch>

# 1. factory reset (firstboot) — via SSH if reachable, else serial
python3 scripts/bench_switch.py reset --host <ip> --i-know
python3 scripts/bench_switch.py reset --serial /dev/serial/by-id/<dev> --i-know

# 2. after the factory reboot, deploy over serial (console = askfirst root)
python3 scripts/bench_switch.py deploy --host x --serial /dev/serial/by-id/<dev> \
    --pubkey ~/.ssh/id_ed25519.pub

# 3. apply + verify (reload was not run by deploy; reload then check)
#    over serial: ubus call network reload
python3 scripts/bench_switch.py verify --host <dut-vlan-ip or mgmt-ip>

# 4. restore the PoE fork from the backup artifacts (md5-gated)
python3 scripts/bench_switch.py install-poe --host <ip> --artifacts <backup-dir>

# 5. reboot-verify — the box MUST come back fully autonomous
#    reboot, wait ~150s, then:
python3 scripts/bench_switch.py verify --host <ip>
```

Post-deploy contact IPs: management 192.168.13.2 (via router uplink), or
any dut VLAN L3 (e.g. 192.168.102.1) reached via a tagged VLAN 1002
interface on the deploy host (`ip link add <if>.1002 link <if> type vlan
id 1002; ip addr add 192.168.102.10/24 dev <if>.1002`).

## labgrid integration

- Power: labgrid `ExternalPowerDriver` with cmd_on/cmd_off =
  `ssh root@192.168.13.2 "ubus call poe manage '{\"port\":\"lanN\",\"action\":\"enable|disable\"}'"`
  (our fork speaks `action:` strings; labgrid's native `ubus` backend sends
  `enable:` booleans — patch the fork to accept both, or keep the driver).
- Console: serial adapters on the exporter host (NetworkSerialPort / raw).
- DUT network: SSHDriver / NetworkService against DUT addresses, or
  jump via the switch (`-J root@192.168.13.2`).
- Follow-up hardening: uhttpd-mod-ubus + ACL for unauthenticated
  poe.info/poe.manage → native labgrid `model: ubus` backend, no SSH in the
  power path.

## Failure modes and recovery (all proven 2026-09-22)

- **Config bricked the management plane** (bad uci commit): every network
  path dies incl. tagged VLANs — only config-independent channels remain:
  serial console, or failsafe (hold reset through power-on, LED rapid-flash;
  telnet 192.168.1.1, `mount_root`, fix `/overlay/upper/etc/config/network`).
  NEVER firstboot for recovery — it wipes the fork (reinstallable from
  backup artifacts, but why pay it).
- **fw4 drops SSH on unzoned VLAN interfaces** — ARP alive, TCP refused/
  timeout. Fix: put interfaces in a zone. Symptom trio to remember:
  ARP REACHABLE + ping filtered + port refused.
- **FT232R serial adapter wedges on device power-cycle** (UART break):
  close the port, wait 3s, reopen (built into scripts/serial_transport.py).
- **Serial line discipline**: max ~200 chars/line; deliver scripts
  line-by-line; never carry `$VARS` through single-quoted serial lines —
  `serial_transport.lint_script` refuses them by design.
- **uci pending changes merge into your commit** — always `uci changes`
  before `commit` (a stale September change corrupted a VLAN once).
- **firstboot over SSH can silently not run** — verify with uptime; when in
  doubt, firstboot over serial where you can watch it.

## Tooling map

| Tool | Role |
|---|---|
| `scripts/bench_switch.py` | backup / deploy / install-poe / verify / reset |
| `scripts/serial_transport.py` | serial console driver (lint, chunking, break-recovery) |
| `data/backups/<switch>/` | sysupgrade bundle, overlay tar (fork!), uci exports, manifest |
| Amperstrand/realtek-poe @ ai-experiments | fork source of truth |
