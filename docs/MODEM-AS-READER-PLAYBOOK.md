# Modem-as-Reader Playbook — eSIM provisioning through a router's own modem

**The generalized process.** `NR7101-ESIM-PLAYBOOK.md` was the first full walk
(one model, one modem, proven end-to-end). This document is the species-agnostic
version: the gates, the two transport paths, the reference wire fingerprints,
and a per-model appendix. A new model needs only an appendix — everything above
the appendices is model-independent.

Per-model status:

| Model | Modem | Appendix | Status |
|---|---|---|---|
| Zyxel NR7101 | Quectel RG502Q-EA | A (filled) | production-proven (download, enable, rollback, silent.link) |
| GL.iNet GL-E750 | Quectel EM060K-GL | B (stub → #619) | in progress |
| ZTE MF286D | ZTE cat.12 mPCIe | C (stub → #621) | not started |

The deep evidence lives in Amperstrand/ifd-modemifd `docs/` (known-good
toolchain, wire fingerprints, refresh policy, findings history). This playbook
links; it does not duplicate — when the two disagree, the ifd-modemifd doc wins.

## The chain (either path)

    profile purchase (host: silentlink-lib / nadanada web)
        → activation code (SMDP host + matching ID)
        → lpac (SGP.22) ──────────────────────────────► 9eSIM (ECP3 eUICC)
            path A: host pcscd → ifd-modemifd → ssh://  seated in the modem's
                    dropbear exec relay → AT+CSIM        SIM slot
            path B: lpac ON the router, LPAC_APDU=at_csim,
                    own modem tty directly

## Two paths, when to use which

**Path A — host-side reader** (`ifd-modemifd` README + NR7101-ESIM-PLAYBOOK).
Zero router-side software (dropbear + busybox relay only). Formally reasoned
no-resend transport semantics (typed `AtOutcome`, retry only for provably
undelivered lines) — the conservative choice for a **one-shot paid activation**.
Enables PC/SC tooling (pySim, OpenSC) against the seated card.

**Path B — on-device lpac** (`KNOWN-GOOD-ONDEVICE-PROVISIONING.md`). lpac
cross-compiled for the router's arch, `LPAC_APDU=at_csim`, the modem's own AT
tty. No network in the card path at all; fastest proven download (~24 s).
Costs: a per-arch artifact + a router-side deploy footprint (see the
non-invasive bundle in `lpac-openwrt`). Hardware-proven for the full download
(T-A) and free rehearsals; the paid one-shot has also been executed and
verified on this stack (silent.link — silentlink-lib #43, closed 2026-10-27).

Practical rule: rehearse on B (free profiles), spend the one-shot through
whichever path has two clean rehearsals — A if in doubt.

## Universal gates — run in this order, never reordered

1. **Dry gate (no hardware):** `tests/hardware/validate.sh` in ifd-modemifd —
   defaults to a local mock-modem dry run. Encodes every failure class that has
   actually burned a one-shot activation code.
2. **Card doctrine:** ccid-firmware-rs `AGENTS.md` §"Card-Handling Doctrine"
   before ANY card session. Never loop secure-channel-class commands; GP/eUICC
   one-shot auth budgets are small and non-renewable.
3. **AT port discovery (read-only):** probe candidates with `AT+CPIN?` —
   **never bare `AT`** (several ports echo `OK` to it). Quectel-class layouts
   put AT on ttyUSB2/3, but verify per model; ports shuffle across resets, so
   re-detect every session and never hardcode.
4. **Wire-fingerprint comparison (read-only):** run the §fingerprints probes
   below against the model's modem and diff against the reference table.
   **Drift is a finding, not noise** — record it in the model's appendix.
5. **eSIM gate (read-only):** `validate-esimgate.sh` (ISD-R readiness, EID,
   chipInfo) before any write-class operation.
6. **Free rehearsal:** the osmocom known-test-profiles Speedtest profile
   (`LPA:1$rsp.truphone.com$QRF-SPEEDTEST`) — free-failure, additive,
   deletable. SINGLE-QUOTE the LPA string (`$` expands under double quotes).
   Download → list → enable → delete is the full rehearsal cycle.
7. **Paid provisioning (owner-gated):** silentlink-lib `checkout.sh` →
   `parse_order.sh` → lpac download. Real money, one-shot discipline, explicit
   owner sign-off first. Sequence the post-enable refresh per the ladder below.

## The refresh ladder (after any profile operation)

Executable policy: ifd-modemifd `tools/modem/refresh.sh` (doctrine:
`docs/MODEM-REFRESH-POLICY.md`). Rungs gentle-first; **`AT+CFUN=1,1` is
FORBIDDEN after profile operations** (it wedged the RG502Q off the USB bus on
2026-10-25; recovery was a 20-second physical power cut). Refresh order:
refreshFlag-driven enable → data-protocol UIM slot power-cycle (needs QMI/MBIM
composition, `/dev/cdc-wdm0`) → `CFUN 0→1` with settle-wait and functional
port re-detection. Pull artifacts off the box BEFORE any reset — tmpfs dies
with the power. Transient `euicc_init` failures right after profile
operations are settle-dependent: wait, never reset into a tired modem.

## Reference wire fingerprints (Quectel RG502Q-EA — the comparison baseline)

Full table: `KNOWN-GOOD-ONDEVICE-PROVISIONING.md` §6. The load-bearing ones:

- Lowercase hex `AT+CSIM` payload → bare `ERROR` (Qualcomm-class parser; one
  REAL modem defect — set `LPAC_APDU_AT_HEX=UPPER` on the pin stack, don't
  patch hexutil like the route1-gate2 era did)
- `AT+CSIM=10,"0070000001"` → `+CSIM: 6,"0x9000"` (logical channel opens)
- ISD-R SELECT by AID → `61 21`, chained `INS C0` fetch works unmodified
- Channel close MUST be the 5-byte form (`007080xx00`); 4-byte → AT `ERROR`
- `AT+CSIM=?` → bare `OK` (no range line — probes must not require `+X:`)
- Basic-channel SELECT-by-AID (A4/04) silently dropped — use logical channels
- No command-size ceiling; malformed APDUs (bad Lc) silently dropped
- Thrash signature (`+CPIN` URC flood, lagging responses): stop, idle 15 s,
  re-detect port

## Rules that apply to every model

- Species-level only: no EIDs, ICCIDs, unit MACs, bench IPs in conwrt or
  ifd-modemifd — those live in the operator's private project.
- Model JSONs record official-image assumptions; community-build provenance
  (MF286D class) must be explicit in the model + recipe notes.
- External etiquette: findings about lpac/pySim/upstream get recorded for a
  HUMAN to upstream (see ifd-modemifd `docs/upstream-reports/`); agents never
  file/comment outside Amperstrand.
- New-model deliverables: appendix below, `models/<model>.json` updates
  (`hardware.lte`/`hardware.modem`: AT port map, CSIM capability), recipe
  notes, and wire fingerprints into the appendix.

## Appendix A — Zyxel NR7101 (filled)

- Modem: Quectel RG502Q-EA (USB `2c7c:0800`), AT historically ttyUSB2 but
  shuffles (ttyUSB0-3); QMI composition available, stock ECM.
- OpenWrt: ramips/mt7621, `mipsel_24kc` — lpac artifact `route1-gate2` era is
  superseded: build from Amperstrand/lpac `pin/nr7101-known-good`
  (`lpac-openwrt` repo builds it; fingerprints recorded per artifact).
- Known-good on-router env: `LPAC_APDU=at_csim`, `LPAC_APDU_AT_HEX=UPPER`,
  `LPAC_APDU_AT_DEVICE=<re-detected>`, `LPAC_HTTP_SSL_VERIFY` ON,
  GSMA-augmented trust store (RSP2 Root CI1).
- Full evidence: `NR7101-ESIM-PLAYBOOK.md` (host-side chain), ifd-modemifd
  `docs/KNOWN-GOOD-ONDEVICE-PROVISIONING.md` (path B, fingerprints, T-A/T-B),
  `docs/INDEPENDENT-REVIEW-9ESIM-20261025.md` (ledger + corrections).
- Recovery instrument: `tools/gpiopoke` + 20-second physical cut (proven);
  PoE-powered outdoor unit — recovery is genuinely expensive, respect the
  refresh ladder.

## Appendix B — GL.iNet GL-E750 (stub → #619)

Task issue #619 carries the full context drop (EM060K-GL port map research,
fingerprint checklist, lessons). Expected AT ttyUSB2/3 (USB `2c7c:030b`,
externally verified), arch `mips_24kc` (shares the ath79 artifact class with
Appendix C). Battery-powered handheld: the physical-power-cut recovery rung is
trivial (hold power), and rung 2 (UIM power-cycle) should be available if the
unit runs a QMI/MBIM composition on `/dev/cdc-wdm0`. Fill this appendix from
the #619 results: port map, fingerprint diff vs §reference, rehearsal
transcript pointers, model JSON updates.

## Appendix C — ZTE MF286D (stub → #621)

Task issue #621. Community-build OpenWrt only (eko.one.pl framework / 24.10.4
community build) — record build provenance per the rules above. ZTE cat.12
mPCIe modem: a genuinely new firmware family for the fingerprint library; no
CSIM behavior assumed either way. Arch `mips_24kc` (ath79) — same lpac
artifact class as Appendix B.
