# RE prompt 05 — firmware delta analysis (vendor OTA update archaeology)

Use when the vendor's OTA deltas are obtainable (their DM/OTA server, forum
mirrors, or captured from a live update) and you want to know *exactly*
what each version changed — file by file — without owning every
intermediate image.

Read [CONTEXT-re-methods.md](CONTEXT-re-methods.md) first (known-plaintext section) and [CONTEXT-footguns.md](CONTEXT-footguns.md) rules 5–6 (WAF egress, DNS leftovers).

## Acquire the chain

1. Find the community delta-finder for the platform (vendors often share
   one DM protocol across a product line; ZTE MF28x uses an OMA-DM SyncML
   exchange with fixed credentials, community-documented).
2. Walk the ladder: query the update server once per known base version;
   each answer gives the next delta's CDN URL. Record which bases return
   nothing (the server floor and the current tip).
3. Vendor DM endpoints often sit behind a WAF that fingerprints TLS
   stacks (python-requests blocked, curl passes) and may require a
   mobile-network source IP — routing through the router's own LTE uplink
   (SSH SOCKS proxy) satisfies both and is the authentic path.
4. sha256 everything on arrival; keep the store on non-tmpfs.

## Decode structure top-down

Container → region descriptors → per-region units → unit header → block
map → per-block ops. Concrete example of what this looked like on ZTE
ZDF01.05 (verify everything against *known* images before trusting):

- unit payload = one LZMA raw stream (props in unit header);
- block map = fixed-size records with source/target CRC32 per flash
  block-size unit — **CRC pairs are a gift**: they let you verify your
  parse against images you DO have, and chain-verify consecutive deltas
  without any image at all (delta N's target CRCs must equal delta N+1's
  source CRCs);
- changed blocks carry copy-ops (source-relative) + a literal stream for
  everything else. The literal codec is usually the vendor's own —
  budget real RE time for it, and look for the applier code in the
  firmware itself (bootloader update engine or userspace update daemon
  carry the decoder).

## Verify with known plaintext

Before decoding anything exotic, line up one (source, target, delta)
triple you fully possess — for a partitions that is wear-stable (raw
cramfs/ROM areas, not live UBI). Validate: sizes match the container's
declared source/target lengths; every map CRC matches the actual blocks;
decoded copy-ranges appear verbatim in both sides. Only then trust the
decoder on unknown deltas.

## Deliverables

Per-version change log (which blocks/files changed), the chain-verified
CRC matrix, the decoder tool, and — if the platform interests you — the
extracted intermediate images themselves (reconstructable by applying
decoded deltas forward from an owned base image).
