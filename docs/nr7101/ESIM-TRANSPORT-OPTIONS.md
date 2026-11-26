# eSIM transport options — the decision matrix (2026-11-26)

> **Context**: you have an NR7101 and a 9eSIM, and want to provision a
> profile (free test first, then paid). The chicken-and-egg: the router
> has no internet until the eSIM is provisioned, but provisioning needs
> internet for the SM-DP+ HTTPS leg. Every option below solves this
> differently.

## The one-line decision

**Who has internet?** That's the entire question.

| Internet is on… | Use | Why |
|---|---|---|
| The NR7101 itself (WiFi-STA, or ethernet on a routed port) | **Option 1: full on-router** | simplest — one process, no relay |
| A host (Linux/Mac/Windows) or the bench switch | **Option 2: split transport** | APDU on-router, HTTP relayed — the production-proven shape |
| Nobody | you're stuck — get internet to something first (WiFi-STA is the fastest hack) | — |

## The options in detail

### Option 1: Full on-router (at_csim + on-router HTTPS)

```
SM-DP+ ← HTTPS ← lpac (on router, at_csim + curl)
                       → AT+CSIM → active-slot eUICC
```

- **When**: the router already has internet (WiFi-STA leg, ethernet on a
  routed port, or a previously-installed profile that still has data)
- **Router needs**: lpac (full build with curl+TLS), internet
- **Host needs**: nothing (you ssh in and run it)
- **Pros**: simplest (one process, one system), fastest (native HTTPS),
  no coordination
- **Cons**: chicken-and-egg — needs internet to get internet; the full
  lpac build is larger (~2.4 MB vs 77 KB for the AT-only build)
- **Tested**: ✅ on hardware (2026-11-21 — the BetterRoaming download
  ran with on-router HTTPS when the router had WiFi internet)
- **Bundle**: `lpac-openwrt` full build (the non-invasive bundle with
  private curl+TLS libs)

### Option 2: Split transport (at_csim local + HTTP relay to host)

```
SM-DP+ ← HTTPS ← relay.py (any interneted host)
                       │ stdin/stdout JSON lines
                       │ (LPAC_HTTP=stdio)
                    ssh → router: lpac (at_csim only)
                             → AT+CSIM → active-slot eUICC
```

- **When**: the router has NO internet; any host on the same network
  has internet (your laptop, the bench switch, another router)
- **Router needs**: lpac (AT-only build — 77 KB static ELF), ssh access
- **Host needs**: python + internet (the relay script is ~50 lines)
- **Pros**: solves the chicken-and-egg without WiFi-STA; works on a
  truly offline router; the relay is simple (~6 HTTP round-trips); the
  AT-only build is tiny (no curl, no TLS, no dynamic libs — single
  static ELF, `libc.so` only)
- **Cons**: two-system coordination; needs a host with python; the
  relay script is bench-grade (hardcoded SSH target, needs editing
  for your setup)
- **Tested**: ✅ on hardware (2026-11-21 — the production proof: full
  SGP.22 download via this path, ~30 s); Felix's 2026-11-26 session
  re-proved it with the AT-only build
- **Bundle**: `lpac-openwrt` AT-only build (#859's recipe) +
  `tools/esim-http-relay/relay.py`

### Option 3: WiFi-STA bridge (not a transport — an internet source)

```
Any interneted AP ← WiFi STA ← NR7101
                                     (then use option 1)
```

- **When**: you have any WiFi AP with internet reachable from the router
- **Pros**: gets you to option 1 quickly
- **Cons**: unpinned connectivity checks lie (they ride WiFi — only
  wwan-pinned checks are truth); needs the AP's credentials; the
  router's WiFi radio is 2.4/5 GHz only (no 60 GHz); it's a hack, not
  a production path
- **Status**: documented as the fallback, not the recommended default

### Option 4: ssh:// host-side reader (24.10-era — REMOVED)

```
Host pcscd ← ifd-modemifd ← ssh:// ← router busybox relay ← AT tty
```

- **Status**: **DEAD on 25.12.x** (#856 — stty/timeout/socat all absent;
  the relay produces AT ERROR storms on a canonical+echo tty). Was
  removed from bench docs 2026-11-20 (structural byte-theft class).
  Kept in the playbook as a historical section for 24.10.x units.

## Host-OS matrix (for option 2 — the split transport)

| Host OS | Relay works? | Notes |
|---|---|---|
| Linux (any) | ✅ | python3 + openssh — the production-proven path |
| macOS | ✅ | python3 (system) + ssh — same shape; the relay has no Linux-only deps |
| Windows | ⚠️ | python3 + openssh (WSL or native OpenSSH); the relay script is POSIX-oriented but the HTTP+JSON core is portable; untested |
| OpenWrt router (the bench switch) | ✅ | the relay needs python3 (not on stock images — but the bench switch has it); the GS1900-8HP is proven as a relay host |
| Another phone/hotspot | ✅ for option 3 (internet source) | not a relay host (no python/ssh) |

## The current bench state (honest, 2026-11-26)

- The transport is proven (option 2, production, 2026-11-21)
- The AT-only build is proven (Felix's #859, 2026-11-26)
- **The actual e2e (download through the split transport with the
  AT-only build) has NOT been run yet** — Felix's handover names it
  as the next action; the bench card is currently on the wrong slot
  (the ice+ card is active, the 9eSIM is slot 1 — the ISD-R isn't
  reachable without a deliberate slot switch)
- The $1 nadanada step is owner-gated (real money)

## Recommended path for a newcomer

1. Flash the router (ZERO-TO-DATA Stages 1-2)
2. Side-load the toolchain: `conwrt esim-bundle --artifact <tarball>`
   (--push does it for you)
3. Verify card state (Gate 0): `lpac chip info` + `profile list`
4. Free rehearsal: the Speedtest test profile through the split transport
   (`relay.py 'profile download -a LPA:1$rsp.truphone.com$QRF-SPEEDTEST'`)
5. Paid profile (owner-gated): $0.99 nadanada or silent.link
