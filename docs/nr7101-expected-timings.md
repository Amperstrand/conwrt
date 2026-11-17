# NR7101 zycast + recovery: expected timings (measured, 2026-11-08..10 bench sessions)

Derived from instrumented bench sessions (PoE draw curves, switch counters,
packet captures). Use these in progress messages and timeout defaults —
not guesses: each number cites its source session.

## Zycast send

| Step | Expected | Notes |
|---|---|---|
| One full loop, recovery image 7.6 MB @ 98 pkt/s (10 ms) | ~76 s | 7420 chunks (donor v2, Nov-8 rescue logs) |
| One full loop, official image 5.3 MB @ 98 pkt/s | ~53 s | 5166 chunks |
| Inter-packet delay | keep 10 ms (default) | 2 ms (477 pkt/s) never accepted in N attempts; the bootloader's poll-loop drops chunks at 5x pace — DO NOT speed up |
| Window coverage | loop start must fall in the ~7 s listen window | ~50 %/boot at 10 ms; expect 1–3 verified power cycles per successful flash |
| Power cycle (off→on, verified states) | ~20–25 s incl. readbacks | state-verified via `poe info` |

## Boot after flash / clean reboot (measured, clean air)

| Milestone | Donor (4ec5) | Borrower (…:91:9c) | a6e4 |
|---|---|---|---|
| PoE on → carrier (PHY) | +6.2 s | +1.9 s | +8.5 s (kernel-time) |
| First frame emitted | +36 s | — | — |
| fe80 answers ping | +62 s | +72 s | ~+4–5 min (image-variant) |
| SSH/HTTP reachable | ~+70 s | ~+75 s | with stock-default image ~+5 min |

## sysupgrade (7.3 MB, initramfs → persistent)

- fire → unit back on SSH: **3–4 min** (both measured units)
- after reboot: `rootfs=overlay`; first-boot uci-defaults may flap LAN once
  (~30–60 s) before the final address (fleet ASU image: hashed LAN) settles.

## PoE draw signatures (GS1900-8HP realtek-poe, coarse mW quantization)

- Crash-loop / flash-loop: rapid small oscillation, no long plateau
- Healthy boot: brief dip then climb to a stable plateau (donor: 3.4→4.8 W)
- Idle initramfs ≈ 4.5–4.6 W steady (all three units)

## The two big timing traps (both paid for on the bench)

1. **A looping sender + a listening bootloader = infinite flash-loop**: the
   unit accepts, boots, re-enters the window, re-accepts. Symptom: LED
   color-cycle that never resolves. Cure: sender OFF, ONE clean reboot.
   Rule: senders are bounded and killed the moment a result appears.
2. **Slow first boot ≠ dead**: stock-default units answer 192.168.1.1 within
   ~20 s, but fleet ASU first-boot adds uci-defaults (up to ~5 min total on
   one unit). Wait the measured window before declaring failure.
