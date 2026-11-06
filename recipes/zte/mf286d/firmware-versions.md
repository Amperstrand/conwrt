# MF286D firmware versions — matrix, community consensus, sources

Species-level research (2026-11-06). Unit identifiers redacted; delta hashes
live in the private repo. The install/rollback runbook is
[openwrt-install-no-serial.md](openwrt-install-no-serial.md).

## Version matrix (Telia/Nordic line — the "MF286D" most units run)

| Version | Era | Modem-side | Router-side | Notes |
|---|---|---|---|---|
| B02 | 2019–2020 | base | base | Kit-era; U-Boot 2020-03 builds; the "Play→Nordic" factory baseline |
| B06 | pre-2021 | — | — | dead end on the update server (no delta from B06) |
| B07→B08 | 2021 | — | — | lowest delta still hosted (server floor: devices on ≤B06 cannot FOTA) |
| B09 | Apr 2021 | — | full refresh | Last widely-dumped stock; kernel 2021-04-08; community zip provenance |
| B10 | Jul 2021 | — | full refresh + new U-Boot 2021-07-22 | Factory state of later units |
| B11 | ~2022 | **VoLTE enabled** | small patch (mld ≈ 140 KB) | modem-focused bump |
| B12 | ~2022 | **UL carrier aggregation** (3xCA DL / 2xCA UL total) | small patch (mld ≈ 226 KB) | **community's stability favorite** |
| "B14" = V1.0.1B02 | Oct 2024 | — | full refresh (mld ≈ 10.8 MB, delta ≈ 13.2 MB) | first update in ~18 mo; no public changelog; still current (Nov 2026) |

Version-scheme wrinkle: after B12 the internal line jumps to V1.0.1Bxx —
"V1.0.1B02" is what the UI calls **B14**. Keep modem and router versions in
lockstep (mixed states confuse the updater; community-confirmed).

## Community consensus (ISPreview + eko.one.pl, 2022–2025)

- **Best all-rounder on stock: B12** — VoLTE + UL-CA complete, long soak
  time, the version most modders standardize on before flashing OpenWrt.
- **B14 (2024):** ships with **B32 disabled by default** (needs the JS
  "Auto" band-selection hack to enable); one OpenWrt user reported
  **no-4G after B14+OpenWrt** and downgraded back to B12; DMZ/bridge bug
  hoped fixed, never confirmed. No changelog published anywhere.
- **Update path that works (community-proven):** flash B12 mtd8+mtd9 from
  OpenWrt console, insert a "3"/Telia-family SIM → device auto-pulls the
  next delta from the DM server on boot. Direct mtd flash of B14 dumps also
  works (mtd8/mtd9 available on the community mirror) but keep sides
  version-matched.
- Failed auto-update side effects seen: WiFi disabled with no UI/hardware
  re-enable — recover by re-flashing web+rootfs to a clean version first.

## Official delta server (still live, Nov 2026)

- DM endpoint `https://dmeu.ztems.com/zxmdmp/dm` (OMA-DM SyncML; community
  query script: gist `dream-svg/f0ff6b8…`). CDN:
  `https://dleu.ztems.com/zxmdmp/download.do?doWhat=getUp&filename=…`.
- Queries must come from a **mobile-network IP** (bench LTE uplink works)
  and a **WAF-friendly TLS stack** (python-requests is JA3-blocked → 405;
  curl passes). The known full Telia ladder: B07→08→09→10→11→12→14.
- Each `.up` is a zip: `delta.package` (magic 8855AA55), `root_uImage.mld`
  (ZDF01.05 web+rootfs delta), cpe post-script, and a full RSA signature
  chain (key.signature → public_ver.pem → delta+image signatures) — the
  chain we verified statically in the FOTA-writer RE.
- B10→B11 and B11→B12 mld sizes (≈0.14/0.23 MB) confirm they are
  modem-focused bumps; the others are full component refreshes.

## What we hold locally (species archive)

- All six official Telia deltas + the PLAY (NTT PL B02→V1.0.1B02) delta,
  sha256-catalogued (hashes in the private repo).
- Full mtd8/mtd9 images: Nordic B10/B12/B14, T-MOBILE V1.0.1B02 (eko
  mirror, cross-verified), the B02 kit, and our specimen's verified
  pre-flash captures (private).
- Community sources: dl.eko.one.pl `/orig/zte_mf286d/` (NORDIC B14,
  T-MOBILE; older dirs currently empty), eko.one.pl forum threads 21790
  (modem lane) and the MF286D-OpenWrt thread, ISPreview thread 42622.

## Open RE follow-ups

1. ZDFU op-stream decoding (the per-block diff format inside ZDF01.05) —
   would let us diff *exactly* what each version changed file-by-file
   (the ATLAS has the header format; the unit opcode encoding is the
   remaining work).
2. Diff the web partitions (B09 vs B12 vs B14 cramfs) to track the web-UI
   attack surface per version (private lane).
3. The modem-side delta contents (VoLTE/CA config) — read-only strings
   comparison across delta.packages.
