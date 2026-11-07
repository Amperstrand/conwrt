# Prompts index

Numbered series = reusable mission briefs. `CONTEXT-*` files are shared
reference material the prompts assume. Serial/step series predate the RE
series; RE entries distill the ZTE MF286D campaign (2026-11).

## Context files (read first)

- [CONTEXT-footguns.md](CONTEXT-footguns.md) — 20 bench/RE footguns, each
  paid for: firewall masking, IP-alias traps, runt frames, cold-boot
  delays, derived client identities, single-threaded web servers,
  checksum-first downloads, tmpfs purges, two-repo discipline.
- [CONTEXT-re-methods.md](CONTEXT-re-methods.md) — technique notes:
  handler-table walking, sink-string triage, PIC literal-pool xrefs,
  qemu-user execution, known-plaintext delta RE, observable ladders.

## Serial console missions (device-peripheral lane)

| Prompt | Use when |
|---|---|
| serial-01-connect-and-identify | first serial contact with a device |
| serial-02-bootloader-explore | enumerating bootloader prompts/commands |
| serial-03-backup | read-only flash backup over serial |
| serial-04-flash / serial-06-flash | flashing over serial |
| serial-05-configure | post-flash configuration over serial |

## Device discovery missions

step-01..04 (identify → fingerprint → plan capture → analyze) for the
generic bring-up flow.

## Reverse-engineering missions (re-01..re-06)

| Prompt | Use when | Origin |
|---|---|---|
| [re-01-firmware-inventory](re-01-firmware-inventory.md) | new router lands; fast structured understanding before live probing | MF286D |
| [re-02-injection-sink-hunting](re-02-injection-sink-hunting.md) | finding exec sinks in embedded web servers (budgets, gates, handler tables) | MF286D |
| [re-03-live-lab-discipline](re-03-live-lab-discipline.md) | probing a live device without bricking your session | MF286D (incl. the single-threaded-server wedge) |
| [re-04-bootloader-reflash-lab](re-04-bootloader-reflash-lab.md) | running vendor TFTP/recovery reflash flows safely | MF286D no-serial install |
| [re-05-firmware-delta-analysis](re-05-firmware-delta-analysis.md) | vendor OTA delta acquisition + format cracking (known-plaintext method) | MF286D B07→B14 ladder |
| [re-06-variant-and-modem-research](re-06-variant-and-modem-research.md) | two-SoC products, carrier variants, feature enablement (voice/remote-SIM) | MF286D phone lines |

Conventions: every prompt is species-agnostic (no payloads, no unit
identifiers — those stay in the private research repos); each ends with
deliverables. When a prompt succeeds or fails on new hardware, append the
lesson to the matching CONTEXT file rather than forking the prompt.
