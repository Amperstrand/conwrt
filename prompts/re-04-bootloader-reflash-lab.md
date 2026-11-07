# RE prompt 04 — bootloader reflash labs (TFTP recovery flows)

How to run a vendor bootloader's network recovery/reflash flow safely on a
bench. Built around ZTE-style `lr`/TFTP flows but the discipline is generic.

Read [CONTEXT-footguns.md](CONTEXT-footguns.md) first (rules 1–9: firewall masking, IP-alias traps, runts, cold-boot timing, derived identities) and [CONTEXT-re-methods.md](CONTEXT-re-methods.md).

## Before the first window

1. **Full verified backups** of every flash partition, two independent
   reads for the small ones, per-chunk checksums for the big ones; a second
   copy outside tmpfs. Unit-unique partitions (calibration/MAC/certs) are
   irreplaceable — no public image contains them.
2. **Re-baseline the bootloader RE on *your* unit's dump** — firmware
   generations differ (a 2020 and 2021 build of the same bootloader shared
   only two thirds of their bytes; every hardcoded address from the older
   analysis was invalid). Strings survive; addresses do not.
3. **Rehearse the server against a simulator** (a fake client exercising
   negotiation, block ACKs, loss, abort) before the device ever asks.
4. **Trigger design**: prefer the smallest possible on-device write (a
   minimal valid image that routes the boot into recovery) over wholesale
   erases; know which failure modes leave the flash untouched (a `&&`
   chained flash script aborts safely on download failure) and which can
   strand the bootloader at a prompt with no serial attached.

## During the window

- The recovery client's identity may be **derived per boot** (random-ish
  IP/MAC from sprintf builders). Do not hardcode `192.0.0.2`; match the
  whole subnet or the MAC pattern.
- **Cold-boot windows can open minutes after power-on** (timeout ladders in
  the update path). Warm-reset windows open in seconds. Watch for at least
  ten minutes before calling a device dead.
- Watch the server log and a live packet capture together; keep the pcap as
  the transfer evidence.
- Serve exactly what is asked; a liveness probe answered with a
  multi-megabyte image aborts the session.

## Success and failure signals

- Progress = per-block ACKs. Completion = the vendor's fin/marker packet
  (log its exact bytes — it is the proof the bootloader accepted the write).
- After the fin: expect a reset, then a first boot that can take minutes;
  a silent first boot on a fresh filesystem is a power-cycle problem before
  it is a brick.
- If the device loops back into recovery after a successful flash, the image
  does not boot: stop serving it, swap in the rollback image, and let the
  same flow restore.

## Bench infrastructure that will betray you (checklist)

- Host firewall default-deny eating device requests while bench-local tests
  pass via loopback — test the server path from an external source.
- A local address alias inside the client subnet capturing replies to
  loopback.
- Duplicate IPs on a bridge and its port.
- Short (runt) ARP replies from the bridge that embedded MACs drop — if a
  client's requests arrive but it never completes resolution, inject padded
  frames yourself.
- Single-threaded servers dropping requests during another transfer's
  timeout window.

## Never

Never `sysupgrade -F`-equivalents on a bootloader flow, never write the
boot chain partitions from a recovery experiment, never run a flash window
without the rollback image staged and its hash verified in the server.
