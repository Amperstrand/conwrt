# PR #85 (ddimension/wwand) reply — session input bullets
For the overseer's draft. Species-level facts only. Human approval required
before posting anywhere.

## What obsy/user asked
- MF286D internal modem + wwand/QMI on firmware B14: QMI WDS start-network
  fails ("Unknown error"), stop-network --autoconnect "No effect", voice broken,
  3G disabled; AT/UIM/NAS/DMS/WDA all fine.

## What we can now state with evidence (2026-11-09 spike)
- We unpacked the official Nordic B14 update package (TELIA_MF286DV1.0.0B12 →
  TELIA_MF286DV1.0.1B02 .up, router V1.0.1B02 + modem BD_…B14). Public ZTE DMS
  URL still serves it.
- B14 is not just a router security bundle: the update **rewrites the modem's
  own software** — full baseband (AMSS) segments AND the modem-side Linux
  data-path stack, including the Qualcomm DSI data-call config
  (dsi_config.xml), QMI libraries (libqmi_cci/csi/sap), MCM RIL service, and
  ZTE data adapters, plus 119 carrier-policy (MCFG) files — the Telia Sweden
  profile among them — and direct writes to the modem EFS config.
- The update also sets 30 NV parameters (full list extracted; community
  previously had 5). Notable: LTE-only RAT lock with Nordic band set
  (B1/B3/B7/B20/B28/B38), a datastall watchdog enabled, and **version identity
  stored in NV** — which is why flashing B12 modem partitions over B14 still
  shows B14 until factory defaults are restored (matches eko.one.pl reports).
- None of the NV items is a QMI/autoconnect switch — the "NV script breaks QMI"
  shorthand from the forums is incomplete; the evidence points at the modem
  data-path stack + carrier/EFS policy changes (analysis ongoing).

## Practical guidance we can already give
- Known-good: modem B12. If on B14 and QMI data matters: downgrade path exists
  (community-documented mtd flash + factory defaults to clear NV identity),
  or keep stock-locked profile; wiki note (2026-03-03) already advises against
  the B14 modem upgrade.
- Why "CGPADDR shows 3 live PDP contexts while QMI WDS says out-of-call" is the
  key symptom: the B14 modem manages data sessions internally; external QMI WDS
  control conflicts — consistent with our unpack findings.

## Our tooling status (relevant offer)
- Verified 22-partition router-side backup tooling + firehose/ADB paths;
  package parsers (delta container + per-file manifests) published in our
  evidence; B14 payload decode + controlled A/B tests are next on our bench.

## Tone/pointers
- Link, don't argue: openwrt forum thread 175362, eko.one.pl thread id=21790
  (posts ~791, 803–823), ZTE firmware matrix work.
- Do NOT promise timelines; do invite reproduction (package is publicly
  downloadable; our manifests list exactly which modem files B14 changes).
