# Upstream issue draft: sunset 0.6 — no server-side API to actively close a channel or send exec exit-status

> **HUMAN SUBMISSION ONLY — DO NOT AUTOMATE.**
>
> This document is a DRAFT for a human operator to review, sanitize-check, and
> submit by hand to https://github.com/mkj/sunset/issues. Per the repository's
> external-etiquette rules (AGENTS.md), automation must NEVER open issues,
> comment, or interact with repositories outside the Amperstrand organization.
> The only acceptable automated action on this file is editing it in place.
>
> **Reference:** conwrt spike #112 (`docs/sunset-mcu-ssh-spike.md`, finding 6).
>
> **Sanitization status:** no secrets or private details.

## Title

Feature request: server-side API for exec `exit-status` (and an explicit channel close)

## Summary

In sunset 0.6.0 (async API), an SSH **server** application that handles
`ServEvent::SessionExec` can `succeed()`/`fail()` the request and write
payload via `SSHServer::stdio()`, but has no way to report the command's
*exit status*:

- We could not find any `ServEvent`/`ChanIO`/`Runner` path that sends
  `SSH_MSG_CHANNEL_REQUEST` with `exit-status` (or `exit-signal`) from the
  server side. `Runner::channel_done()` marks the channel done locally and
  discards input; it does not notify the peer of an exit status.
- The client side *can* receive exit status (`CliEvent::SessionExit` maps
  `ChannelReqType::ExitStatus`), but nothing on the server can produce one.
- Channel completion itself is only reachable implicitly: dropping the last
  `ChanIO` reference *and* continuing to poll `progress()` lets
  `clear_refcounts` drive the close — an explicit, discoverable
  `close()`/`finish()` would be nicer, but the primary gap is exit status.

Upstream demos only serve interactive shells until the client disconnects, so
the gap never shows there. For exec-style servers (run a command, return
output + exit status — `scp -t`/`-f` handlers, status endpoints, embedded
agents) the client cannot distinguish "command finished with status N" from
"stream ended" except via application-level payload framing.

## Ask

An API along the lines of:

- `ChanOut::finish(exit_status)` that sends `exit-status` and drives the
  channel close, and/or
- an explicit `ChanInOut::close()` complement to the current drop-driven
  close (which requires the caller to know it must keep polling
  `progress()` afterwards).

Is something like this planned? We're evaluating sunset for an embedded
agent use case and would be happy to test a prototype or contribute a PR
with guidance on the preferred shape.
