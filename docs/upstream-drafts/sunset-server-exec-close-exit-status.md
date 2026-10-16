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

Feature request: server-side API for active channel EOF/close and exec `exit-status`

## Summary

In sunset 0.6.0 (async API), an SSH **server** application that handles
`ServEvent::SessionExec` can `succeed()`/`fail()` the request and write
payload via `SSHServer::stdio()`, but there appears to be no way to
proactively signal command completion to the client:

- `ChannelEof` / `ChannelClose` are only emitted in *response* to the peer's
  packets (`handle_eof` / `handle_close` in `src/channel.rs` — passive close).
- No `ServEvent`/`ChanIO` method sends `SSH_MSG_CHANNEL_REQUEST` with
  `exit-status` (or `exit-signal`). `Runner::channel_done()` only marks the
  channel done locally and discards input; it doesn't notify the peer.
- The client side *can* receive exit status (`CliEvent::SessionExit` maps
  `ChannelReqType::ExitStatus`), but nothing on the server can produce one.

Upstream demos only serve interactive shells until the client disconnects, so
the gap never shows there. For exec-style servers (run a command, return
output + exit status — `scp -t`/`-f` handlers, status endpoints, embedded
agents) the client cannot distinguish "command finished successfully" from
"connection died" except via application-level payload framing.

## Ask

An API along the lines of:

- `ChanOut::finish(exit_status)` / `ChanInOut::close()` that sends
  `exit-status` + `ChannelEof` + `ChannelClose`, or
- a `ServEvent`-driven completion path where dropping the last `ChanIO`
  reference triggers the close handshake with an exit status.

Is something like this planned? We're evaluating sunset for an embedded
agent use case and would be happy to test a prototype or contribute a PR
with guidance on the preferred shape.
