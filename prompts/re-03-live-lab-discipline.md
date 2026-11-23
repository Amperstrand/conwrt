# RE prompt 03 — live injection lab discipline

How to probe a live embedded web server for command injection without
bricking your own session. Every rule below was paid for.

Read [CONTEXT-footguns.md](CONTEXT-footguns.md) first — rules 11–13 below cost a full device session each.

## Establish observability before capability

In order of cost: (1) form response text (know exactly what it can and
cannot tell you — often nothing), (2) ICMP from the device (bounded
`ping -c N`), (3) an HTTP callback server on the bench logging every
request, (4) a config-store readback oracle (`nv set <key>=$(cmd)` + the
config-get endpoint reading the key back). Two independent channels before
anything clever.

## The single-threaded server rule

Many embedded web servers (goahead class) run handlers on the main event
loop. A payload that blocks — unbounded `ping`, a bare `sh` waiting on
stdin, any command that never exits — freezes the whole web UI while the
device keeps answering ICMP. Rules:

- every payload ends in `&` or is internally bounded (`-c`, `-m`, timeouts);
- never probe with a bare interactive shell;
- know the recovery (power cycle) and whether the target state survives it
  before you need it.

## Bounded, beaconed, one variable at a time

Each shot: bounded runtime, a distinct callback path or ICMP signature, one
hypothesis. Pace the shots; log every request/response with timestamps to an
append-only ledger (separate observed / reproduced / inferred / untested).
When a shot fails silently, do not blind-retry with bigger payloads — go
back to the observable ladder and add a channel.

## Watch for state that changes under you

- Config stores are live filesystems: your own readback writes mutate the
  partition you are imaging (snapshot twice, document drift as expected).
- Sessions/tokens rotate per request; re-read them each shot.
- A "working" technique can die after a reboot (handlers gated on boot
  state) and a dead one can come back after a power cycle.

## Readback oracles beat response text

A config key that stores command output, read back through the same web UI,
turns a blind channel into a shell-equivalent — and it costs one write per
query. Keep values single-line (word-splitting eats multiline), and remember
the gate charset applies to what you can *store* too.

## Evidence handling

Unit identifiers (MACs, serials, IMSIs), payloads and credentials stay in
the private repo; public write-ups use placeholders and behavior
descriptions. Pcaps are evidence: timestamp them, keep them with the ledger.
