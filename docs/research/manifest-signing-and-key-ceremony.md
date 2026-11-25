# Manifest signing and key ceremony — comparative digest 3

Digest 3 of the 2026-11 campaign series (#765 digest 1: router fleet
tooling; #775 digest 2: flasher verification + boardfarm). Feeds #767
(tollgate/signed release manifests) and the AGENTS irreversible-write
rule that already demands hash-pinned artifacts: a hash says the
bytes are intact; a signature says WHO pinned them.

Research brief: /root/.hermes/cache/scratch/signing-brief.md. All
claims below were fetched from the cited primary source in-session
(2026-11-25); anything that 404'd or stayed secondary was dropped.

## 1. Gluon autoupdater — the deployed M-of-N precedent

https://gluon.readthedocs.io/en/latest/features/autoupdater.html

The manifest is a text file: a header (BRANCH / DATE / PRIORITY),
then one `hash filename` line per firmware image, then a `---`
separator, then signatures. Only the content ABOVE the separator is
signed — signatures are APPEND-ONLY, so any maintainer can add their
signature to an already-signed manifest without coordinating
(re-signing is idempotent; the signing helper is `contrib/sign.sh`).

- Signing: ECDSA (secp256k1) via ecdsautils; keypair generation and
  `sign.sh` are one-liners in the docs.
- Verification: the node bakes the `pubkeys` list and
  `good_signatures = M` in site.conf (per branch); the autoupdater
  refuses an image with fewer than M valid signatures
  (https://gluon.readthedocs.io/en/latest/user/site.html). The docs
  explicitly advise MORE pubkeys than M to survive lost keys.
- The community practice (Bremen Freifunk, cited in #767): different
  humans sign the SAME manifest; nobody trusts a single builder.

**What to avoid — the CVE that matters here**: ecdsautils had a
signature-FORGERY vulnerability (CVE-2022-24884 / GHSA-qhcg-9ffp-78pw,
fixed in Gluon v2021.1.2). Gluon's own release notes state the
critical part for us: *requiring multiple signatures did NOT mitigate
it* — the forgery bypassed the key knowledge entirely
(https://gluon.readthedocs.io/en/main/releases/v2021.1.2.html). A
decade-old ECDSA codepath in a C utility is a weaker foundation than
OpenWrt's actively-maintained usign (Ed25519, below). Gluon is the
right PRECEDENT for manifest shape and M-of-N; the wrong precedent
for the signature algorithm.

## 2. OpenWrt in-ecosystem — usign/ucert, and the path the DUT already has

Two trust layers, both already deployed on every OpenWrt device:

**Host-side chain of trust** (release distribution): the release
server publishes `sha256sums` + `sha256sums.asc` (GPG, human) +
`sha256sums.sig` (usign, build system). The checksum verifies the
image; the signature verifies the checksum file
(https://openwrt.org/docs/guide-user/security/release_signatures).
The 25.12 release key is even kept on a hardware token
("OpenWrt Build System (NitroKey3)",
https://safeguard.sh/resources/blog/openwrt-release-history-versions-targets-package-managers-and-security-support).

**On-device verification** (sysupgrade): images built with a
`key-build` key carry a ucert certificate; `sysupgrade` runs
fwtool → ucert → verifies against the keys in `/etc/opkg/keys`,
gated by `REQUIRE_IMAGE_SIGNATURE`
(https://github.com/openwrt/openwrt/blob/main/package/base-files/files/lib/upgrade/fwtool.sh
— the check is a runtime shell function we can read, not a black
box). usign itself is Ed25519 + SHA-512, OpenBSD signify lineage,
and lives on every device already (usage documented at the same
fwtool.sh reference and the ArnoldLu walkthrough,
https://www.cnblogs.com/arnoldlu/p/18819308).

**The era trap** (directly relevant to our 24.x→25.x fleet): on
apk-based builds (25.x) the usign build key is NOT installed into
`/etc/opkg/keys` — only the opkg-side key is — so a self-built,
signed apk image cannot verify its own sysupgrade; ucert finds no
key (https://github.com/openwrt/openwrt/issues/24838). Any conwrt
signing design must bake the key explicitly (like we bake
uci-defaults) rather than relying on the image default.

owut (the ASU CLI client, "generally considered the best CLI option
now") verifies the image SHA-256 before installing
(safeguard.sh reference above) — i.e. the ASU path trusts the
server + checksum, NOT a signature. That is the same gap
tollgate has today.

## 3. TUF / Uptane — the heavyweight design vocabulary

https://theupdateframework.github.io/specification/latest

TUF's core separation: the ROOT role (offline keys, threshold
quorum, survives compromise by rotation) delegates to online roles;
clients walk root → timestamp → snapshot → targets, every step
threshold-verified, every signature counted once per KEYID. Root
rotation is versioned and verifiable across multiple generations
(spec §5.3; TAP 8 https://github.com/theupdateframework/taps/blob/master/tap8.md
generalizes rotation for targets roles).

The most concretely stealable operational numbers come from
Foundries.io's deployment of TUF
(https://docs.foundries.io/93/reference-manual/security/offline-keys.html):
root = 3-5 OFFLINE keys with threshold 2; targets = one offline key
per human authorized to release; rotate root at least yearly;
production threshold 2, CI threshold 1. That is a complete,
field-run key ceremony for a small embedded fleet — the same shape
as ours.

What TUF is for us: a policy vocabulary (offline root, threshold,
rotation, one-signature-per-key counting), not an implementation —
running the full four-role metadata dance for a fleet we flash
ourselves is overkill. Uptane (TUF for automotive) adds
director/image-repo split for adversary models we don't have.

## 4. SWUpdate — sign the description, hash the artifacts

https://sbabic.github.io/swupdate/signed_images.html

SWUpdate's designers explicitly rejected signing the whole compound
image (verification would come only after the full download, and a
power-cut mid-install of an unverified image is unrecoverable) and
signing each sub-image (signed pieces could be REMIXED into a new
compound image). Their answer: sign ONLY `sw-description` — the
manifest that carries each artifact's SHA-256 — and refuse any
artifact whose hash is not listed. Signature check first, then
hashes, then install; `CONFIG_SIGNED_IMAGES` cannot be disabled at
runtime.

This is the exact conwrt/tollgate shape: one small signed object
(the release manifest with image hashes), artifacts verified by
hash from within it. It also matches our irreversible-write rule
("verify before touching the device", never install-then-discover).

Algorithms are pluggable (RSA / RSA-PSS / CMS PKCS#7 / GPG; OpenSSL,
mbedTLS, wolfSSL providers — https://swupdate.org/features/),
keys generated with plain `openssl` — no bespoke crypto utilities.

## 5. sigstore/cosign keyless — verdict: inapplicable offline

Keyless signing binds an OIDC identity (not a key) via Fulcio's
short-lived certificates and witnesses the event in the Rekor
transparency log
(https://github.com/sigstore/docs/blob/main/content/en/cosign/signing/overview.md).
Both the identity issuance and the transparency-log verification are
ONLINE steps; verification must additionally pin the expected
identity and issuer (`--certificate-identity/--certificate-oidc-issuer`
are mandatory in keyless mode —
https://blog.sigstore.dev/cosign-2-0-released). A DUT on a bench VLAN
(or an operator flashing over serial) cannot reach either service;
using cosign in bring-your-own-key mode reduces it to "a signature"
with none of the ceremony benefits. NOT ADOPTED; revisit only if
fleet manifests ever become a public, CI-signed distribution.

## 6. Comparison

| | signs what | algo | M-of-N | on-device verify | key rotation | fit |
|---|---|---|---|---|---|---|
| Gluon | manifest (hashes inside) | ECDSA secp256k1 (CVE'd) | yes (good_signatures) | yes (autoupdater) | re-build images | shape: YES, algo: NO |
| OpenWrt usign/ucert | sha256sums / image ucert | Ed25519 (usign) | no (1 key per sig path) | yes (fwtool→ucert→/etc/opkg/keys) | key-build swap | algo + on-device path: YES |
| TUF | metadata (all roles) | any | yes (per role) | client lib | versioned root chain | policy vocabulary only |
| SWUpdate | sw-description (hashes inside) | RSA/CMS/GPG | no | yes (CONFIG_SIGNED_IMAGES) | re-issued cert/key | manifest pattern: YES |
| sigstore keyless | artifact digest | ECDSA (Fulcio) | no | needs online Rekor/OIDC | ephemeral keys | NO (offline fleet) |

## 7. Steal these five (each names the conwrt component it changes)

1. **Manifest shape = Gluon's, bytes = ours**: header
   (BRANCH/DATE/MODEL lines) + `sha256 <filename>` per artifact +
   `---` separator + APPEND-ONLY signature lines. Changes
   `scripts/use_cases/tollgate.py` (the #767 TODO) and the release
   step of `scripts/firmware-manager.py` — signing happens where the
   sha256 pin already exists.
2. **Algorithm = Ed25519 via usign semantics, NOT Gluon's ecdsautils**
   (CVE-2022-24884 forgery class; usign is maintained, on every
   device, and OpenBSD-signify lineage). Host-side signing in Rust
   (ed25519-dalek — already a dep-line we audit) or by shelling to
   `usign -S` where available; the ON-DEVICE verify path is the
   stock fwtool→ucert chain reading `/etc/opkg/keys`.
3. **Key installation is OUR job, not the image's** (the #24838 apk
   trap): bake the pubkey exactly like `conwrt initramfs-bake` bakes
   uci-defaults (#784/#813) — the same overlay path, files/etc/opkg/
   keys/<keyid>. Also documents the 24.x vs 25.x split for the fleet.
4. **M-of-N counting: TUF's rule, Gluon's simplicity** — each
   signature counts once per KEYID (threshold by distinct key, not
   signature count — the go-tuf threshold bug is the cautionary tale,
   https://github.com/theupdateframework/go-tuf/commit/64ded1864de9e948e174d7270c66364d368eefe5).
   Verify M distinct valid signatures; refuse duplicates of one key.
5. **SWUpdate's install-order discipline**: signature first, then
   artifact hashes, then transfer to DUT; unsigned refusal with an
   EXPLICIT override flag (mirrors sysupgrade's -F gate, which
   AGENTS.md already restricts). The override stays loud and
   logged — it is an incident record, not a convenience.

## 8. Key ceremony — options for the owner

**A. Single offline key now (M=1).** One Ed25519 key on the
operator's hardware token (Nitrokey, per OpenWrt's own release-key
practice); everything else as designed. Fastest to land, no
coordination cost. Weakness: one lost/stolen key = full reflash of
trust (re-bake pubkeys fleet-wide — cheap for OUR fleet size, but a
real event).

**B. 2-of-3 Ed25519, three holders (Gluon/Foundries shape).**
Owner + two other humans/machines (e.g. the ops host's hardware
token, a second operator, an offline paper/steel backup key that
only signs rotations). Manifest needs any 2 signatures; pubkeys
(3) baked via the initramfs-bake overlay. A single compromise is
survivable WITHOUT touching the fleet; rotation = sign the new key
set with 2-of-3 old keys, re-bake on next flash. Foundries'
field-run numbers (root 3-5 keys, threshold 2) say this is the
small-fleet sweet spot.

**C. TUF-lite roles.** Root (offline, threshold) + targets (online,
per-releaser). Full rotation machinery. Overkill for a fleet where
every flash is operator-driven and the manifest server is ours; only
worth it if release authority ever separates from flash authority.

**Recommendation: B.** It matches the fleet's actual threat model
(one operator, bench network, occasional WAN mirror), costs two
extra signing commands per release, and makes the single-key
failure mode survivable. The manifest format supports it from day
one (append-only signatures above `---`), so A can be the
transitional state while keys are minted — the code is identical,
only M changes.

## 9. Implementation lane (the code this unlocks, ~1 session)

1. `scripts/conwrt/release_sign.py` — build the manifest (hash the
   artifacts we already hash), sign/append with Ed25519, verify
   (M-distinct-keycount rule). Pure host-side, offline-testable.
2. `tollgate.py` install op: verify manifest before the scp; refuse
   unsigned with an explicit `--allow-untrusted` (kept, but now
   LOUD + logged + carrying the M-of-N failure reason).
3. `initramfs-bake`/profile overlay: `files/etc/opkg/keys/<keyid>`
   for the on-device ucert path (24.x opkg-era; 25.x apk-era trap
   documented).
4. Keygen + ceremony runbook doc (options above; owner picks M).
