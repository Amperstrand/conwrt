# lan7/lan8 Recovery — 2026-09-22 (zero-serial)

The September 21 verdict for lan7/lan8 was "OpenWrt-alive kernel, network-dead,
serial-gated". On September 22 both units were fully recovered over the
network in ~90 minutes. This file records the story, the retro-analysis
(could we have done it WITHOUT the session archaeology?), and the durable
lessons. Methodology generalized in `docs/DARK-DEVICE-PLAYBOOK.md`; tooling
in `scripts/bench_discover.py`.

## What actually happened (timeline)

1. **Archaeology**: May-era Claude transcripts (~/.claude/transcripts,
   ses_1b6fa3311 / ses_1a743f02 / ses_1b9559d23 — the OpenCode index had
   almost none of it) showed the May bench was a FLAT VLAN 1 home LAN on
   192.168.13.0/24, with the APs statically addressed: lan7=.253, lan8=.254
   (earlier DHCP-era sightings .197/.161/.3).
2. **Probe**: `ip addr add 192.168.13.250/24 dev switch.1007` → lan7
   answered ping at .253 instantly. lan8 ignored v4 entirely.
3. **v6 discovery**: lan8's link-local `fe80::b62d:56ff:fe25:86bd` was in
   the switch's NDP cache (probes had touched it) and answered ping6. Its
   MAC also appeared in VLAN 1's neigh table (stale dual-untagged port config).
4. **Access**: `ProxyJump`+zone-scoped v6 FAILS (jump sshd can't dial it);
   the switch's `/usr/bin/ssh` (openssh) is silently broken. The door:
   `DROPBEAR_PASSWORD=<pw> dbclient -y -y root@fe80::...%switch.1008`.
5. **Credentials**: lan7=`<bench-password-2026>` (no-serial flow), lan8=`conwrt`
   (May AP#2 lineage — matched HARDWARE-DISCOVERY.md exactly).
6. **lan8 pubkey bonus bug**: password worked, keys never did → syslog said
   it: `/etc/dropbear must be owned by user or root...` — directory was
   1000:1000 group-writable since the May flash. `chown root:root; chmod 755`
   fixed key auth.
7. **Standardization**: both units → 192.168.1.1/24 on their VLAN (uci set →
   commit → `uci get` readback → reboot → verify), authorized_keys deduped
   + Mac `id_rsa` + switch key added. Mac aliases `lan7-ap`/`lan8-ap`
   (pin `ip route replace 192.168.1.1/32 dev switch.100X` first).

## Retro-analysis: paths that existed WITHOUT the May history

The September session had already observed, on the wire: both units' source
MACs (DAD/MLD frames), lan8 briefly claiming 192.168.1.1, and "silence"
after ~10s. From that data alone:

| Path | Would it have worked? | Why |
|---|---|---|
| **EUI-64 link-local derivation** | **YES — the killer move** | `fe80::<MAC with FFFE + XOR 0x02>` — b4:2d:56:25:47:a2 → fe80::b62d:56ff:fe25:47a2. Linux/OpenWrt default link-locals are EUI-64. ping6 on the access VLAN → alive → banner → dbclient. Zero history needed. |
| **Long passive listen** | YES | Both units RA every ~16s forever (odhcpd ULA). September's ~90s races treated boot-window as the only signal period. |
| **Sweep the probe host's own subnets** | YES | The switch LIVED in 192.168.13.0/24. A .13 sweep on the access VLANs would have found lan7 in minutes. |
| **Credential brute force** | YES | Dropbear has no lockout. A ~10-entry ladder (empty/conwrt/<bench-password-2026>/new2day/admin/admin...) cracks both units. |
| **Fleet key reuse** | YES (lan8) | ai-legion's key was already authorized on lan8; ssh from ai-legion via the switch would have landed a shell. |
| **LFP stack probes** | identifies, doesn't access | iTTL/IPID from RSTs would have confirmed "Linux 4.x/OpenWrt" → informs cred ladder. |
| DHCP bait server | NO | Units are static (zero DISCOVERs — itself a useful negative: "operator-configured"). |
| Reset button / failsafe | NO | No GPIO buttons in DTS. |
| TFTP bait | NO | Bootloaders flash-boot. |
| Serial | YES but external | The known fallback; not needed in the end. |

**The honest conclusion: we had enough data in September to recover both
units same-day. The gap was methodology, not information** — no v6 layer, no
positive-control discipline, too-short passive windows, and a sweep list
that omitted the subnet our own infrastructure lived in.

## Durable lessons encoded into conwrt

- `docs/DARK-DEVICE-PLAYBOOK.md` — the generalized ladder.
- `scripts/bench_discover.py` — ladder generator/executor with the control
  gate, EUI-64 derivation, inventory archaeology, subnet prioritization,
  credential-ladder generation (never auto-executed).
- `prompts/bench-forensics-01-dark-device.md` — session template for the
  next dark device.
- Model JSON warning: the wrong-subnet verdict + v6 recovery path.
- AGENTS.md-adjacent rule (rule 11) vindicated twice: ping6 methodology and
  probe negatives both needed positive controls.

## Current state (end of session)

- lan7: 192.168.1.1 @ VLAN 1007, pw <bench-password-2026>, keys (switch + Mac id_rsa),
  alias `lan7-ap`. IPv4 ICMP echo intermittently filtered (ARP/SSH fine) —
  cosmetic, unfixed by choice.
- lan8: 192.168.1.1 @ VLAN 1008, pw conwrt, keys (ai-legion + switch + Mac),
  alias `lan8-ap`.
- Both send RAs (ip6assign ULA) on their isolated VLANs — harmless.
- Inventory entries [22]/[23]. lan6 remains serial-gated (#62).
