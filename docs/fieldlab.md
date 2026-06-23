# conwrt Field Lab

Use a deployed OpenWrt router (the "field router") as a remote probe and flash
appliance for diagnosing unknown routers.

## Concept

```
Mac / development machine
    |
    | SSH (today) / FIPS mesh (future)
    v
field router (OpenWrt, deployed by conwrt)
    |
    | Wi-Fi STA uplink for internet / management
    |
    | Ethernet WAN port repurposed as isolated probe port
    v
unknown router under investigation
```

The field router keeps Wi-Fi as its real uplink. Its Ethernet WAN port is free
and becomes a dedicated probe/flash port — isolated from the LAN — for observing
and interacting with whatever device is connected to it.

## Two modes

### Passthrough (Mac-driven)

The Mac does the thinking; the field router is a transparent conduit. Use this
for troubleshooting and discovering new routers with opencode in the loop.

- `capture` — stream remote tcpdump to a local pcap
- `forward` — open a local SSH port-forward to a TCP service on the unknown device

### Agent (field-router-driven)

conwrt runs on the field router, detects and flashes the unknown device through
the probe port. The Mac supervises via artifacts and an opencode backchannel.

- `discover` — probe the unknown device from the field router (ARP, ping, ports)
- `flash` (future) — router-to-router flashing through the probe port

## Topology assumptions

- The field router is online via Wi-Fi STA uplink (NOT the Ethernet WAN port).
- The Ethernet WAN port is free for field-lab use.
- The probe interface name is **not** always `wan` — on MT7621/DSA devices it's
  typically `internet`. The CLI auto-detects via `uci get network.wan.device`.
- Management access (SSH to the field router) survives probe-port changes because
  it goes through br-lan or Wi-Fi, not the Ethernet WAN port.

## Commands

### inspect — collect field router state (read-only)

```bash
python3 scripts/fieldlab.py inspect --host root@192.168.1.1
```

Collects: board identity, OpenWrt release, UCI network/wireless/firewall, IP
state, bridge topology, tool availability, probe-interface detection. Writes to
`runs/<session>/inspect/router-state.json`.

### capture — stream remote tcpdump to local pcap

```bash
# 30-second capture, auto-detect probe interface
python3 scripts/fieldlab.py capture --host root@192.168.1.1 --duration 30

# Stream to stdout for piping into local tcpdump/wireshark
python3 scripts/fieldlab.py capture --host root@192.168.1.1 --out - \
  | tcpdump -r - -nn -e

# With a capture filter
python3 scripts/fieldlab.py capture --host root@192.168.1.1 \
  --filter "not port 22" --duration 60
```

Output goes to `runs/<session>/captures/probe-<iface>.pcap` by default. Use
`--out <path>` for a custom location, or `--out -` for stdout.

The capture uses `tcpdump -i <iface> -s 0 -U -w -` over SSH. Killing the local
SSH process (Ctrl-C or duration timeout) cleanly kills the remote tcpdump via
broken pipe.

**tcpdump must be installed on the field router.** If missing, the command
prints install instructions.

### discover — probe the unknown device from the field router

```bash
python3 scripts/fieldlab.py discover --host root@192.168.1.1

# Target a specific IP
python3 scripts/fieldlab.py discover --host root@192.168.1.1 --target 192.168.1.1
```

Reads the ARP table on the probe interface, pings common router IPs, scans
common ports with busybox `nc`, and optionally probes HTTP with `curl` if
available. Writes findings to `runs/<session>/discover/findings.json`.

### forward — local SSH port-forward to the unknown device

```bash
# Print the command
python3 scripts/fieldlab.py forward --host root@192.168.1.1 --target 192.168.1.1:80

# Execute directly
python3 scripts/fieldlab.py forward --host root@192.168.1.1 \
  --target 192.168.1.1:80 --exec
```

Opens `ssh -L 127.0.0.1:18080:192.168.1.1:80 root@<field-router> -N`, giving the
Mac direct TCP access to the unknown device's web UI through the field router.

### prepare-probe — inspect probe-port state (optional cleanup)

```bash
# Dry-run (default): show state, print cleanup plan
python3 scripts/fieldlab.py prepare-probe --host root@192.168.1.1

# Apply: remove stale WAN UCI binding from the probe interface
python3 scripts/fieldlab.py prepare-probe --host root@192.168.1.1 --apply
```

Shows the current state of the probe interface and whether a stale `wan` UCI
binding exists. With `--apply`, clears the binding at runtime (no `uci commit`)
so the field router stops treating the unknown device as an ISP. Changes revert
on reboot.

## Manual lab setup

### 1. Install tcpdump on the field router (if missing)

If the field router has no internet (the unknown router may not provide upstream):

```bash
# On the Mac (has internet):
REPO="https://downloads.openwrt.org/releases/24.10.7/packages/mipsel_24kc/base"
curl -O "${REPO}/tcpdump_4.99.5-r1_mipsel_24kc.ipk"
curl -O "${REPO}/libpcap1_1.10.5-r2_mipsel_24kc.ipk"

# Transfer (note: -O required for Dropbear)
scp -O tcpdump_*.ipk libpcap1_*.ipk root@192.168.1.1:/tmp/

# Install on the router
ssh root@192.168.1.1 'opkg install /tmp/libpcap1_*.ipk && opkg install /tmp/tcpdump_*.ipk'
```

Replace the URL with the correct OpenWrt version, target, and architecture for
your field router. Check with `ssh root@<ip> 'cat /etc/openwrt_release'`.

### 2. Verify the field router is online via Wi-Fi

```bash
ssh root@192.168.1.1 'ip route show default; uci show wireless | grep mode'
```

The default route should go through a Wi-Fi STA interface (phy\*-sta\*), not the
Ethernet WAN port.

### 3. Connect the unknown device to the WAN/probe port

Plug an Ethernet cable from the unknown router into the field router's WAN port.

### 4. Run field-lab commands

```bash
python3 scripts/fieldlab.py inspect   --host root@192.168.1.1
python3 scripts/fieldlab.py capture   --host root@192.168.1.1 --duration 30
python3 scripts/fieldlab.py discover  --host root@192.168.1.1
```

## Rollback

All field-lab commands except `prepare-probe --apply` are read-only — no
rollback needed.

For `prepare-probe --apply`:
- Changes are runtime-only (no `uci commit`). **Reboot restores the original
  config.**
- To revert without reboot: `ssh root@<ip> 'uci revert network; ifup wan'`

## Run artifacts

Each command creates or updates a run directory:

```
runs/20260623-153045-fieldlab/
├── manifest.json              # session metadata + command log
├── notes.md                   # human-readable notes (if written)
├── inspect/
│   └── router-state.json      # field router state from inspect
├── captures/
│   └── probe-internet.pcap    # pcap from capture
└── discover/
    └── findings.json          # discovery results
```

Run directories are gitignored (see `.gitignore`). The `manifest.json` tracks
which commands were run and when.

## Transport

Today: SSH over LAN/Wi-Fi using `ssh_utils` (BatchMode, key-only, Dropbear
compatibility options).

The transport layer (`fieldlab/transport.py`) is designed to be swappable:
- Future: FIPS mesh (allowlisted peers, WireGuard)
- Future: direct RPC over a management VPN
- Future: field-lab agent daemon on the router

## Future direction

- **Wireshark extcap plugin** — wrap `capture` as an extcap interface so
  Wireshark can stream directly from the remote probe port in the GUI.
- **True L2 TAP** — WireGuard/UDP tunnel + TAP interfaces so the Mac gets a
  virtual Ethernet interface on the probe subnet (DHCP, ARP, full L2 access).
- **Agent mode** — conwrt running on the field router detects and flashes known
  models through the probe port. Unknown models write `findings.json` for an
  opencode backchannel to do Stage 1 discovery.
- **FIPS transport** — allowlisted node identities, gated root SSH over FIPS mesh.
- **Power/serial integrations** — USB-serial relay control, camera for LED
  observation, PDU for power cycling.
