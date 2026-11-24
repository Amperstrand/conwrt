# Flasher verification & board-farm architecture — comparative digest 2 (2026-11-24)

Second overnight-audit digest (companion:
docs/research/router-fleet-tooling-comparison.md). Two domains the
first digest did not touch: host-side serial flashers and board-farm
infrastructure. Primary sources cited inline; unverified claims
dropped.

## 1. esptool — the serial-flash verification discipline

**What exists.** Espressif's UART bootloader protocol: SLIP framing;
a ROM-resident loader that esptool upgrades by uploading a flasher
STUB to IRAM (the stub announces itself with an unsolicited OHAI
packet — the only one it ever sends); BEGIN/DATA/END command triples
where BEGIN declares erase size, address, block count and block size;
deflate-compressed transfer mode; and — the part worth stealing — a
verification ladder on top of the write path.
Sources: docs.espressif.com esptool release-v4 serial-protocol pages;
github.com/espressif/esptool esptool/cmds.py (master and v5.3.0).

**What they do well (mapped to our rules).**
1. **They do not trust the transport checksum.** The per-packet
   checksum is explicitly documented as inadequate; verification is a
   separate whole-region SPI_FLASH_MD5 pass, "recommended to always
   use". Our AGENTS rule 2 ("a write is not done until it is read
   back") is the same doctrine — but esptool applies it at ONE more
   granularity: even after an ack'd write sequence, the final
   `flash_md5sum` catch includes the fast-reflash retry loop.
2. **The empty-region check.** After verify, `res == md5(b"\xff" *
   base_size)` raises "Write failed, the written flash region is
   empty." — distinguishing *erased-0xFF* from *valid data* as a
   distinct failure class. This is EXACTLY our "zeros, erased 0xFF,
   and a valid header are THREE DIFFERENT boot outcomes" rule
   (AGENTS irreversible-write discipline), implemented as a one-line
   equivalence check. Cheap, load-bearing.
3. **Re-read before condemn (NAND).** Bad-block marking re-reads a
   mismatched first page once before condemning the block — a single
   transport corruption must not mark a healthy block bad. Our
   readback gates have the same shape in principle; the explicit
   *re-read-before-condemn* step is worth naming in our mtd verify
   paths.
4. **Stub-loader pattern.** Uploading a small smarter loader to RAM
   and having it take over (OHAI handshake) before doing the real
   work — the xmodem/serial-transfer cousin of our U-Boot tftp
   trigger images. Their lesson: the ROM path is a bootstrap for a
   capable path, never the workhorse.

**What to steal.** The empty-region equivalence check belongs in our
`mtd write`/trigger-image verify helpers: after readback, explicitly
test "readback == erased pattern" as its own error class ("write
silently no-op'd; region still erased") distinct from "readback
mismatch". Filed as an issue.

**What to avoid.** Their MD5-for-verify is a throughput choice
(UART-bound); our sha256 discipline stays — the check, not the
digest, is the steal.

## 2. labgrid — the board-farm architecture we already run

**What exists.** Targets own Resources (passive access info) and
Drivers (actions layered via Protocols — ConsoleProtocol under
ShellDriver/SSHDriver both implementing CommandProtocol, so higher
code is transport-agnostic); Strategies transition boards between
states (off → bootloader → shell) explicitly; the distributed plane
is coordinator (gRPC) + exporters (udev-tracked ManagedResources,
ser2net for serial) + clients, with PLACES as acquire/release
exclusion units and reservation queues with filters/tags/priority.
Sources: labgrid.readthedocs.io (overview, getting-started),
labgrid/remote/proto/labgrid-coordinator.proto.

**What they do well (and how we already match).**
- **CommandProtocol over ConsoleProtocol** is the same shape as our
  v6door's Door abstraction (FakeDoor ≈ their protocol indirection;
  adopt's gate ladder ≈ a Strategy). Our #751 design independently
  converged on their best idea — good sign, cite-worthy precedent.
- **ManagedResources appear/disappear at runtime and drivers
  deactivate with them.** Our serial-lane equivalent (FT232R
  break-condition reopen dance) is a hand-rolled special case of this
  general contract.
- **Place acquisition = the exclusion unit; reservations = the
  queue.** We adopted labgrid places for the bench (AGENTS labgrid
  coordination section) and #616/#753 wired `reserve --wait` into our
  test harness — aligned.

**Gaps their model exposes in ours.**
- **No Strategy layer in conwrt**: our flash/recover/adopt flows are
  scripts, not named state machines. The AGENTS dark-device playbook
  IS a strategy (its ladder is literally state transitions); encoding
  it as data (states + permitted transitions + per-transition
  verification) would make `conwrt discover run` output
  machine-checkable against the playbook instead of prose-parallel.
- **Exporter-tracked USB identity**: their udev match keys
  (ID_SERIAL_SHORT) are the pattern our macOS serial-aliasing and
  port-map issues kept re-solving by hand. The lab registry
  (conwrt-lab lab.yaml) should carry the udev match keys for bench
  USB serial adapters — then `lab_registry reconcile` could detect
  replugged adapters the way labgrid exporters do. (conwrt-lab is
  private-repo scope; noted here for the cross-reference.)

**What to avoid.** Their shared-filesystem + SSH-everywhere trust
model is the documented labgrid compromise; our bench already
inherits it via labgrid — no new dependency needed, but nothing
should copy it into any internet-facing path.

## Steal-these (digest 2)

1. **Empty-region equivalence check** in mtd/trigger readback gates —
   one line, names the silent-no-op failure class (issue filed).
2. **Re-read-before-condemn** named explicitly in the mtd verify
   helpers' contract (rides the same issue).
3. **Playbook-as-Strategy**: encode the dark-device ladder states as
   data so discover/listen verdicts are machine-checkable transitions
   (issue filed).
4. **udev match keys in the lab registry** for USB serial identity
   (cross-ref for conwrt-lab).

## Non-findings (this audit's other passes)

- `cargo audit`: 4 vulnerabilities found — 3 bumped in the same
  session (crypto-bigint 0.7.6, ctutils 0.4.8, url 2.5.9; workspace
  tests + clippy green), 1 tracked with an applicability verdict (rsa
  rc pinned by russh; client-side-verify only — issue filed).
- Unsafe inventory: 2 `unsafe` blocks in the whole workspace
  (providers/conwrt-local-std FFI-adjacent) — no embedded-side unsafe
  found; not audited line-by-line this pass.
- Stale-issue sweep: no additional fixed-but-open issues (the #353
  class was already caught); keyword sweeps against landed lanes
  found only live trackers (#100 parent, #769 batch).
