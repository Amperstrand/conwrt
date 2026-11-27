# PINNED-STACK — the NR7101 eSIM flow, reproducibly

The answer to "this works for me but I don't remember exactly how":
every component below is pinned to an exact, fetchable artifact. If a
component is not pinned here, a working run with it is NOT a
reproducible result — pin it before claiming it.

## The pinned stack (2026-11-27, the bench-proven set)

| Component | Pin | Proven by |
|---|---|---|
| OpenWrt (eSIM bench unit) | **25.12.6, r33311-981c978eff**, ramips/mt7621, mipsel_24kc | `/etc/openwrt_release` on the live unit (4c:c5:3e:b6:1d:90, the eSIM test bed) |
| OpenWrt image (flash target) | 25.12.6 sysupgrade sha256 `4a5cc305…` (the campaign's E2/E4 image) | #841 E2; verified sha at transfer |
| lpac | **Amperstrand/lpac @ `43559a2`** (branch `fix/help-no-card-init`, build r483) — release `v2.3.0-amperstrand-r483` on Amperstrand/lpac-openwrt, artifact sha256 `91de12161370cb16819ef4426109c14f…`, non-invasive bundle layout | #856's e2e endgame + #857's on-target proof + the esim-dryrun 7/7 |
| lpac build toolchain | OpenWrt SDK 25.12.4 ramips/mt7621 (sha-verified per the #859 recipe); musl ABI compatible with 25.12.6 runtime | build-lpac-openwrt-25.12.sh, two clean builds |
| Cross-build driver | `build-lpac-openwrt-25.12.sh` @ lpac-openwrt main (5b03415+) | the r482/r483 builds |
| AT-tty resolver | `lpac-at-tty` (conwrt-bench a321bd0+, deployed /usr/bin/lpac-at-tty on the bench shape) | the dry-run's shuffle gate |
| eSIM flow harness | `esim-dryrun.sh` + `esim-http-relay/relay.py` + `lpac-at-tty` (conwrt-bench a151869) | 7/7 gates + the expected-outcome debrief |
| SM-DP+ TLS trust | the GSMA RSP2 CI bundle (`/root/vpcd-nr7101/ci-bundle.pem` — the relay's `CTX`) | the TLS gate; the default CA store CANNOT verify the SM-DP+ chain (8.1.1's sibling lesson) |
| 9eSIM card | EID `89086030202200000025000080784062`, production GSMA CI (euiccCiPKId `81370f51…`) — no free/public code is obtainable for it (EID-locked family + empty pools + SGP.26 PKI mismatch: see FREE-PROFILE-AVAILABILITY.md) | felixfelix-bot #868 |

## The wwand question (why a fork, and what the fork is for)

The OpenWrt **feed** ships upstream ddimension/wwand — that base is fine
for a stock single-card user (felix's flow needs no fork feature: lpac
at_csim + the modem's own tty; he even drove the slot with raw AT).

The **Amperstrand fork** (ddimension main + our ~54 commits, always kept
containing upstream's HEAD) exists for the BENCH flow, and the eSIM
test bed depends on its doors: `wwandctl sims` (the authoritative
card↔seat map), `slot <n>` (the daemon-managed seat switch — the only
clean way we found off the post-profile-flip seat), `reset` (the GPIO
modem reset door — the cure for the sim_transport wedge class), the
recovery watchdogs, the MF286D port entries, and the rsim/remote-SIM
system. Upstream has none of those yet; they are the forward-PR
candidates when the owner gates them.

**Known pinning debt (do not trust, re-pin):** the wwand daemon +
wwandctl binaries on the bench unit are an **October 17 2026 build of
the fork at an untracked commit** (raw scp'd binaries, no package, no
build record). The next wwand-touching session must rebuild from the
current fork HEAD, deploy as a package, and record the commit here.
`wwand-lpac-2.3.0-r4` on the unit is the feed's package (tracked).

## Rule for every future run

Pins drift. The preflight (`esim-dryrun` gate set) checks the pins it
can (lpac build id, resolver presence, reachability) — extend it when
you add a component. A green preflight with an unpinned component is
only evidence for THIS machine, TODAY.
