# Recovery Flash via Bench Rig — token-lean runbook

**Use when**: a DUT on the bench is dark, wedged, or in recovery mode and needs
OpenWrt (re)installed through a rig router (ER6P bay, GS1900 bench port).
Goal: ~1 command + 1 operator action instead of a discovery session.

## Rules that save the most tokens

1. **Never re-derive recovery parameters.** They live in
   `models/<model-id>.json` → `flash_methods["recovery-http"]`
   (recovery_ip, upload endpoint/field, reset instructions, timings).
2. **Never conclude "device dead" from ping.** Recovery-mode firmware does
   NOT answer ICMP. Probe TCP: `curl -m 3 -s -o /dev/null -w '%{http_code}'
   http://<recovery_ip>/`. Also: a device can be totally silent at L2
   (0 frames in tcpdump) yet alive — steady red LED = wedged stack.
3. **Do not poll. Arm the watcher.** Push the image + a detached watcher
   (`setsid`, BusyBox rule) to the rig, then do other work or end the turn.
   The flash fires the moment the operator's reset dance brings recovery up.
4. **Use the tool**: `python3 scripts/dut_recover.py --model-id <id>
   --rig root@192.168.12.4 --bay br-lan.401 --image <recovery.bin>
   --pubkey ~/.ssh/id_ed25519.pub` does stage → watcher → wait → verify →
   adopt (rogue-disarm + key + inventory line). `--stage-only` and
   `--status` for async flows.
5. **Image variant matters**: recovery flashing uses `recovery.bin`
   (NOT factory.bin, NOT sysupgrade). Check `data/` for a cached one
   before downloading.

## LED state → action (D-Link class)

| LED | Meaning | Action |
|---|---|---|
| Steady red | firmware fault / bootloop — stack dead, zero frames | Operator: re-enter recovery (reset pin held while powering on, ~10-12 s until blinking) |
| Blinking red | recovery mode LIVE — HTTP server at recovery_ip | Flash now (tool or curl POST) |
| No LED / no carrier | no power or cable | Operator: check power/cable |

## The rig pattern (ER6P, 192.168.12.4)

Upstream: ERX eth4, tagged VLAN 12 (lab island), static 192.168.12.4, its own DHCP
server disabled (rogue-safe). Each LAN port is an isolated DUT bay:

| Rig port | VLAN | Rig L3 | Staged client aliases |
|---|---|---|---|
| lan1 | 400 | 192.168.40.1 | — |
| lan2 | 401 | 192.168.41.1 | 192.168.0.10, 192.168.1.254 (recovery + fresh-OpenWrt) |
| lan3 | 402 | 192.168.42.1 | — |
| lan4 | 403 | 192.168.43.1 | — |
| lan5 | 404 | 192.168.44.1 | — |

Reach a DUT from the bench host via `ssh -J root@192.168.12.4 root@<dut-ip>`
(the jump's traffic sources from the staged same-subnet alias — DUTs have no
gateway, so cross-subnet sources get no reply).

## After the flash (already automated by the tool — know why)

1. `ssh-keygen -R <dut-ip>` — every reflash regenerates dropbear host keys.
2. Disarm the rogue: `dhcp.lan.ignore=1`, `dhcp.lan.ra=disabled`,
   `dhcp.lan.dhcpv6=disabled` + readbacks (fresh OpenWrt serves DHCP+RA).
3. Install key, append inventory record (AGENTS.md post-first-access).

## Finding an unknown device on the bench (cheap census)

```
ssh root@192.168.13.1 'bridge fdb show br br-lan | grep "dev eth[1-4]" | grep master | sort -u'
```
Attribute MACs by OUI (macvendors.com); DHCP clients appear in the ERX or
switch lease tables. A carrier-up-but-silent port means wedged or
statically-configured-elsewhere — probe per rule 2 before concluding.
