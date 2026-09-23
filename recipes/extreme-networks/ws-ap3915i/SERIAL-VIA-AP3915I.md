# Serial Console via a Second AP3915i (Router-to-Router Serial Bridge)

**Proven 2026-09-23** on the home bench (GS1900-8HP). A healthy WS-AP3915i can act
as the serial listener for a *second* AP3915i over a 3-wire UART splice — no
USB-TTL adapter, no laptop in the loop. This closes the serial-gated diagnostic
class (AGENTS.md "Serial-First Recovery", the #62 dark-unit problem) with hardware
already racked on the PoE bay.

## What this is for

- Reading the boot of a dark / wedge-suspect AP3915i (U-Boot banner, kernel,
  procd, failsafe prompt) when the network path is untrusted or absent.
- A labgrid-able serial console for AP3915i DUTs (see "labgrid integration").
- Hypothesis testing that needs ground truth from the console: e.g. the
  `sf read`+`bootm` flash-boot mystery (AGENTS.md AP3915i rule 10), the
  BootBAK-vs-BootPRI slot-selection question, overlay-replay races.

## Wiring (validated)

Both ends speak **RS-232 over the RJ45 console jack**, 115200 8N1 (AP3915i
console = `ttyMSM0` behind an RS-232 transceiver, `console=ttyMSM0,115200n81`).
CORRECTED 2026-09-23: this jack previously documented as "3.3V TTL" — wrong.
A **standard Cisco console cable works on it** (per the OpenWrt forum thread
that added AP3915i support and Extreme's published Cisco-style pinout:
pin3=TXD, pin6=RXD, pins4/5=GND). The 3.3V TTL header is a separate 4-pin
header INSIDE the case (T8 Torx). There is no VCC pin on the RJ45 jack.

Cross TX/RX, common the ground (this is an RS-232 null-modem):

| Listener (host AP) |        | Target (DUT AP) |
|---|---|---|
| RX  | ←—— | TX  |
| TX  | ——→ | RX  |
| GND | ——— | GND |

The user's splice ("blue to blue crossed green") maps to exactly this: one pair
straight-through (GND↔GND), one pair crossed (TX↔RX). Verify with a known-good
boot before trusting a reading — AGENTS.md positive-control rule.

**Why it stays clean while you cycle the target:** the listener only sees its
*own* boot spew during its own first ~30s. If you keep the listener powered and
only PoE-cycle the *target*, the wire is silent until the target boots — the
capture is 100% target output. (The pre-boot `root@OpenWrt#` / `unexpected
newline` chatter you may see is the target's own console echoing back into its
RX through the splice — harmless feedback, not a fault.)

## Listener setup (on the healthy AP, over SSH)

The reference image has **no `stty`/microcom/screen** — but the kernel console is
already 115200 8N1, so no termios setup is needed. You only have to free the tty
from the console getty, then `cat` it. From the Mac (jump via the bench switch):

```bash
SWITCH=root@192.168.13.2          # bench GS1900-8HP
LISTENER=root@192.168.104.51      # lan4 reference AP (adjust per bench)

ssh -J $SWITCH $LISTENER '
  cp /etc/inittab /etc/inittab.bak-conwrt
  sed -i "s|^ttyMSM0|#ttyMSM0|" /etc/inittab     # comment out askfirst line
  kill -HUP 1; sleep 1
  # kill the getty by PID (a pkill pattern can self-match the invoking shell)
  for p in $(ps | grep -E "askfirst|login.sh" | grep -v grep | awk "{print \$1}"); do kill $p; done
  sleep 1
  rm -f /tmp/target-console.log
  setsid sh -c "cat /dev/ttyMSM0 > /tmp/target-console.log 2>/dev/null" < /dev/null > /dev/null 2>&1 &
'
```

Confirm the capture is armed before touching power:

```bash
ssh -J $SWITCH $LISTENER 'ps | grep "cat /dev/ttyMSM0" | grep -v grep; wc -c /tmp/target-console.log'
```

## Power-cycle the target and read the boot

PoE port indices on the GS1900-8HP fork: `lan2`→index 1 … `lan8`→index 7 (verify
with `for i in 0 1 2 3 4 5 6 7; do echo $i $(uci get poe.@port[$i].name); done`).
Cycle only the target port — **never the listener's port, and never lan5**
(TFTP-fallback-dependent, one-way trip until the lifeline is re-armed).

```bash
# zero the log for a clean boot, then cycle the TARGET (example: lan2)
ssh -J $SWITCH $LISTENER ': > /tmp/target-console.log'
ssh $SWITCH 'ubus call poe manage "{\"port\":\"lan2\",\"action\":\"disable\"}"; sleep 8; \
             ubus call poe manage "{\"port\":\"lan2\",\"action\":\"enable\"}"'

# AP3915i takes ~90s to a shell; then pull the capture (dropbear has no
# sftp-server — stream it, do not scp):
sleep 95
ssh -J $SWITCH $LISTENER 'cat /tmp/target-console.log' > ./target-boot.log
```

## Restore the listener (leave the reference unit pristine)

```bash
ssh -J $SWITCH $LISTENER '
  for p in $(ps | grep "cat /dev/ttyMSM0" | grep -v grep | awk "{print \$1}"); do kill $p; done
  cp /etc/inittab.bak-conwrt /etc/inittab
  kill -HUP 1
'
```

The console getty re-announces on the listener's next reboot (cosmetic). Its SSH
and network are untouched throughout — you never lose the listener mid-capture
because you only cycle the target.

## Reading the AP3915i boot (what "good" looks like)

From the validated 2026-09-23 capture of ap-lan2
(`data/bench/ap-lan2/20260923-serial-via-lan4/lan2-boot.log`):

- PBL → SBL1 → **BootBAK** (`U-Boot 2012.07.19 ... (back-up)`) → "found primary
  bootROM, load and run" → **BootPRI** (`U-Boot 2012.07.22 (Jul 19 2022)`) →
  FIT image → `Starting kernel ...` → squashfs root mounts **read-only** →
  `mount_root: switching to jffs2 overlay` → procd → `Console is alive` →
  `Press Enter to activate this console` → `root@OpenWrt:~#`.
- Kernel cmdline on this unit carries `ubi.mtd=0` → `UBI error: cannot attach
  mtd0` — **harmless** (root is on the mtd9 squashfs, not UBI), but it is the
  known-bad arg AGENTS.md says to strip during env review.
- A healthy boot ends with `qca8k ... lan: Link is Up` + `br-lan: port 1(lan)
  entered forwarding state`. Absence of those = network never came up.
- Watch the jffs2 line: `jffs2_build_xattr_subsystem ... N unchecked, M orphan`
  = dirty overlay (the ap-lan2 auth-dead signature). On a bad boot the replay
  hangs and dropbear never gets a writable /etc — that is the unit going dark
  *with a live console*, and it is only visible on serial.

## labgrid integration

**Live on ap-lan2 since 2026-09-23.** The bridge (`scripts/conwrt_serial_bridge.py`)
runs as `conwrt-serial-bridge@ap-lan2.service` on the exporter host (ai-legion),
SSH-jumping via the bench switch to the lan4 listener AP and serving its
`/dev/ttyMSM0` on `127.0.0.1:4002`. The exporter (`conwrt-exporter.service`,
systemd user, coordinator `192.168.13.221:20408`) exports it as
`NetworkSerialPort { host: 127.0.0.1, port: 4002, speed: 115200 }`; the place
matches `*/ap-lan2/{NetworkPowerPort,NetworkSerialPort,NetworkService}`. A
`SerialDriver` on an acquired ap-lan2 place now gets the console — enabling
`UBootTFTPStrategy`-class flows and boot-log assertions with no USB adapter.

To add another serial pair (e.g. the lan6 dark unit):

1. Splice the target's UART to a listener AP's console (3-wire, above).
2. Add an instance: copy `labgrid/conwrt-serial-bridge@.service` to the exporter
   host, set its `Environment` (target = listener IP, jump = switch, tty, and a
   fresh `CONWRT_SERIAL_PORT`), `systemctl --user enable --now
   conwrt-serial-bridge@<place>`.
3. Export `NetworkSerialPort { host: 127.0.0.1, port: <port>, speed: 115200 }` on
   that place in `exporter.yaml`, `systemctl --user restart conwrt-exporter`, then
   `labgrid-client -x 192.168.13.221:20408 -p <place> add-match '*/<place>/NetworkSerialPort'`.

Gotchas proven during bring-up: kill any *stale* `cat $TTY` on the listener (two
readers race for the bytes — `free_tty` in the bridge handles it); a chatty
console (echo loop) makes the stream flap — send Ctrl-C to quiet it; the exporter
must run under its systemd unit, not `nohup`/`setsid` over SSH, or it dies with
the session.

## Safety

- 3.3V only, never VCC. Confirm from the OpenWrt patch / DTS before first
  contact (AGENTS.md "Verify Serial Baud Rate From Source").
- Positive-control the wiring against a known-good boot before believing any
  "target is silent" result.
- PoE-cycle by port *name* after confirming the index map; keep lan5 and the
  listener's own port off-limits.
- This is a *read/heal* door. It does not by itself make `firstboot` or env
  writes safe — those still follow AGENTS.md escape-hatch and U-Boot-env rules.

## Repointing the bridge (lan6 recovery plan)

One bridge host (lan4) has ONE UART — it serves whichever target its 3-wire
splice is physically connected to. To bring console to a new target (e.g.
the dark lan6 unit, the last serial-gated device on the bench):

1. **At the bench** (operator hands): move the splice from the current
   target's console pads to the new target's TX/RX/GND. Photo the old
   wiring first. The bridge host's own port must stay powered throughout.
2. Update the per-place coordinates in `conwrt-serial-bridge@.service` (or
   the instance env) to the new target, then
   `systemctl --user restart conwrt-serial-bridge@<place>`.
3. Export/refresh the `NetworkSerialPort` on the TARGET's place (not the
   old one) and `add-match` it.
4. **Positive control first** (AGENTS rule 11): power-cycle a KNOWN-good
   boot on the new target and watch for PBL/U-Boot bytes before trusting
   any silence. lan6 has never emitted frames — its splice is exactly where
   a miswire would masquerade as "still dead".
5. With console proven, lan6 diagnosis follows the standard serial ladder
   (SERIAL-RESCUE doc): capture boot, decide U-Boot vs kernel vs power.

Until someone is physically at the bench, the bridge stays on its current
target — repointing is a 5-minute physical job, not a remote one.
