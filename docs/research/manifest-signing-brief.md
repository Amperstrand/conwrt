# BRIEF — manifest signing & key ceremony for conwrt/tollgate (#767)

## Product context
conwrt builds and flashes OpenWrt-family router images (ASU/
imagebuilder/SDK) for the Amperstrand fleet; tollgate is the POS/esh
family carried on them. Today release artifacts are hash-pinned but
UNSIGNED (scripts/use_cases/tollgate.py:357 --allow-untrusted). #767
wants: signed release manifests + M-of-N verification on the install
path + a documented key ceremony. The AGENTS irreversible-write rules
already demand hash-pinned artifacts; signing adds WHO pinned them.

## Topics, priority order (mechanisms not vibes; cite what you
actually fetched; skip what 404s)
1. Gluon autoupdater signing (the direct precedent, implemented and
   deployed): manifest format (fields, --- separator, append-only
   signatures), ecdsautils (curve, key format), contrib/sign.sh flow,
   good_signatures M-of-N semantics, community key-ceremony practice
   (Bremen Freifunk), rotation/compromise story.
2. OpenWrt in-ecosystem equivalents: usign (Ed25519, /etc/opkg/keys,
   opkg verify), owut/attended sysupgrade verification path, `sysupgrade
   -c` / firmware signature checks; image-level vs package-level.
3. Industry heavyweight: TUF (and Uptane) — survivable key compromise,
   offline root, rotation, threshold signatures. What's stealable for a
   small fleet vs overkill.
4. Lighter comparators: SWUpdate CMS/PKCS#7 signed images; sigstore/
   cosign keyless (applicability for an OFFLINE fleet — verdict).
5. Rust/python implementation surface for our lane: ecdsa crates vs
   ed25519-dalek vs usign-compatible verification ON-DEVICE (what does
   the DUT itself run to verify — usign? openssl? busybox?).

## Required shape
what exists → what they do well → what to steal → what to avoid, with
URLs; end with a steal-these-five section naming the conwrt/tollgate
component each steal changes, plus the key-ceremony policy OPTIONS
(2-3, with a recommendation) for the owner.
