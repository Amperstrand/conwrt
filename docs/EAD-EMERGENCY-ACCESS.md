# EAD — the raw-ethernet emergency shell (bench/troubleshooting only)

EAD (Emergency Access Daemon) is OpenWrt's 2008-era out-of-band door: a
daemon that answers on **raw Ethernet layer 2** (UDP 56026, broadcast),
authenticates with SRP against a root password hash, and then runs
shell commands over an encrypted session — reachable when the IP stack,
firewall, or network config is so broken that even the v6 door fails.

**Status in conwrt: documented, deploy-on-demand, and NOT recommended
for anything but the bench.** This page exists because the lane that
needs it (flashing/troubleshooting experiments on DUTs) will keep
needing it — but treat it as a diagnostic instrument, not a feature.

## Security stance — read first

Do not ship EAD on production or field units, and do not bake it into
images. The tradeoffs:

- It is a **root shell reachable by anyone on the L2 segment**. SRP
  auth means the password never crosses the wire in the clear, but
  there is no rate limiting, no lockout, no audit trail — anyone on
  the VLAN can hammer it.
- Auth depends on **legacy MD5-crypt (`$1$`) shadow entries** — the
  parser silently ignores everything else (a `$6$` root hash means
  "Authentication failed" with no diagnostic).
- The daemon **reads the password file you point it at** and the
  protocol/crypto are 2008-vintage; treat the session as
  "better than nothing", not "hardened".
- The sanctioned pattern: an **isolated DUT VLAN** (the bench
  100N-bay discipline — one DHCP/RA authority per segment), daemon
  started only for the troubleshooting window, killed after.

Where it shines: a bench unit whose every network door is dead (the
wrong-subnet / firewall-looped / half-configured states), where serial
is not attached and a reflash would cost more than the answer.

## The upstream code is broken — use the fork

The stock package does not work as shipped; six bugs were found and
fixed during the 2026-11 live bring-up (full evidence:
conwrt-bench `sessions/2026-11-26-ead-emergency-access.md`):

1. **Deaf daemon (every little-endian target)**: `ead.c` passed
   `htons(ETH_P_IP)` to `pcap_set_protocol_linux`, which wants host
   byte order — the socket bound protocol 0x0008 and never saw a
   packet (`/proc/net/packet` shows it).
2. **`static const char password[...]`** written by `strncpy` — UB
   with two build-dependent modes: SIGSEGV on every auth, or the store
   silently elided (wrong hash, clean-looking auth failure).
3. **RX needs pcap immediate mode** (frames landing during a dispatch
   callback are lost — the follow-up request 176 µs after a reply
   never dispatches). Immediate mode on the **TX** handle breaks
   `sendpacket` — scope it RX-only.
4. **Manual cross-builds must pass `-DHAVE_CONFIG_H`** to the tinysrp
   compiles, or bn.h's word-size inference mismatches and the BN layer
   writes out of bounds (the SRP modulus corrupted, silently).
5. **`-f` foreground mode is deaf on DSA devices** — the RX re-open
   onto the bridge port only happens in the monitor loop that `-B`
   runs. Always `setsid ead -d <user-port> -B`.
6. **tinysrp's THIRTY_TWO_BIT BN path is broken** on 32-bit targets:
   `BigIntegerAdd` returns wrong bytes and `BN_mod_exp` returns
   zero/hangs, surfacing as `B` length 0, `u = SHA1("")`, and a
   clean "Authentication failed" while the daemon looks healthy.
   bn.h now routes 32-bit platforms to the 64-bit-word path.

Fixed source: **`Amperstrand/openwrt` branch `ead-bench-fixes`** (all
six; the bn.h fix also repairs the official package build on 32-bit
targets). Ready-made mipsel musl build recipe, per-arch configs, and
the built binary live in conwrt-bench
`data/bench/ead-emergency/` (gitignored artifact cache).

## Building the daemon for a DUT (mipsel example)

Toolchain: musl 1.2.5 from source with `-msoft-float -march=mips32r2`
(zig/Debian crosses default to hard-float → SIGILL on FPU-less 24Kc).
Build recipe: `data/bench/ead-emergency/scripts/build-ead-musl.sh`.
Verify the binary under `qemu-mipsel -cpu 24Kc` for basic execution,
but run the fixed-input BN-ops test **on the target** before trusting
the math (qemu-user has its own quirks).

## Using it

```
# on the unit (any working door; deploy-on-demand):
setsid /tmp/ead-fixed -d lan -B -p /etc/shadow    # DSA user port, NOT eth0

# on the host (the patched client — stock flags are unusable on
# multi-VLAN hosts):
conwrt-side ead-client -l <local-ip> -b <subnet-bcast> -D <iface> \
    -s <unit-ip> -w 3000                          # discovery: read the nid
ead-client -l <local-ip> -b <subnet-bcast> -D <iface> -s <unit-ip> \
    -w 8000 <nid> root:<password> "id"            # auth + command
```

Gotchas that will cost an hour each if skipped:

- **Discovery is mandatory** — the node id is randomized per daemon
  start; never assume the MAC-derived value.
- **`-w` ≥ 1500** — the stock 400 ms round-trip window races the
  daemon's ~200 ms pcap block retirement.
- **Host firewall**: open interface-scoped rules for **both** dport
  and sport 56026 (replies target the client's ephemeral port); the
  rules vanish on firewall reloads — re-check when "No devices found"
  appears with no code change.
- `rp_filter=2` on the staging VLAN when the host holds several routes
  to the DUT subnet.
- The hash must be MD5-crypt: `openssl passwd -1 -salt NR71 <pw>`, and
  **never interpolate it through SSH double quotes** — `$1$…` expands
  and a truncated hash locks dropbear for every auth method including
  keys (total lockout, no error names it). Push a file and sed from it.

## Where the full procedure lives

The step-by-step bring-up, the diagnostic ladder (where a drop dies),
and every pitfall above with its evidence: the `dut-emergency-access`
skill (Hermes). Session evidence and the E2E live proof:
conwrt-bench sessions/2026-11-26-ead-emergency-access.md, the issue-835
campaign comments, and the live `uid=0` round-trip on nr7101-78c5.
