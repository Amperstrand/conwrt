# RE prompt 02 — hunting command-injection sinks in embedded web servers

Static methodology for finding exec sinks (`system()`, `popen()`, backtick
scripts) fed from request parameters in firmware web servers (goahead-style
and friends). Bench-tested on an ARM goahead build with stripped sections.

## Find the sinks before the handlers

Scan the web-server binary and every library it loads for command-format
strings: `"adb %s"`, `"%s > /tmp/f"`, `"killall %s"`, `"iptables … %s"`,
`"wget %s"`, vendor script invocations. Every `%s` inside a string that
names a program is a candidate sink; the prefix length is your payload
budget if the buffer is bounded.

## The buffer-budget pattern

The recurring construction in these firmwares:

```c
char buf[N];
snprintf(buf, N, "<command prefix>%s", value);
system(buf);
```

Work out N from the disassembly (`sub sp` / memset size) and subtract the
prefix: that is the exact payload budget, and the copy **silently
truncates** — a longer form value does not error, it just never runs. Do not
conclude "no injection" from an over-budget probe.

## Charset gates live in the dispatcher, not the handler

Expect a pre-handler validation pass over the decoded form values (marketed
as XSS protection): typically a tiny character blacklist (quotes, angle
brackets). Read the gate function itself in the disassembly — the *exact*
blocked set is usually four or five characters, and everything else
(`; | & $() backticks spaces`) passes. The handler then often has its own
format validation (digit-only, enum strcmp) that kills the other fields —
enumerate every parameter of every handler, not just the famous ones.

## Read the response semantics

Determine what the form's `success`/`failure` actually means. A common trap:
the handler returns `success` unconditionally once past the gate — there is
**no exit-code oracle** and every "it worked" you didn't observe on the wire
is a guess. Establish observable channels first (ICMP, an HTTP callback
server, a config-store readback) before firing anything.

## Handler tables

Dispatch is usually a table of {fnptr, name} pairs in .data with a fixed
stride. Find one known goformId string, walk the table, and you get the full
handler inventory with function addresses — then check each handler for the
snprintf+system pattern. Multiple handlers often share one sprintf-style
helper with a **large** buffer; the small per-handler buffers get all the
attention, the shared helper is the jackpot.

## Verify against the exact target shell

BusyBox ash is not bash: no `/dev/tcp`, different option bundling, applet
sets vary per build. Resolve every behavioral question against the firmware
busybox binary (see re-01's qemu trick), not against host sh.

## Disclosure discipline

Sinks found this way are usually already-assigned CVEs on one variant and
live on others where nobody checked. Record findings with function
addresses, budgets and gate sets in the private repo; public docs get the
mitigation-relevant behavior without payloads.
