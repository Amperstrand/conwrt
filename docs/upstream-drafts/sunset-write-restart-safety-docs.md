# Upstream issue draft: sunset — document that `Write` impls passed to `SSHClient`/`SSHServer::run` must be restart-safe

> **HUMAN SUBMISSION ONLY — DO NOT AUTOMATE.**
>
> This document is a DRAFT for a human operator to review, sanitize-check, and
> submit by hand to https://github.com/mkj/sunset/issues. Per the repository's
> external-etiquette rules (AGENTS.md), automation must NEVER open issues,
> comment, or interact with repositories outside the Amperstrand organization.
> The only acceptable automated action on this file is editing it in place.
>
> **Reference:** conwrt spike #112 (`docs/sunset-mcu-ssh-spike.md`, findings 2
> and 4 — corrected edition; regression tests on `Amperstrand/sunset`
> `ai-experiments`).
>
> **Sanitization status:** no secrets or private details.

## Title

Docs request: note that `embedded_io_async::Write` impls passed to `SSHClient::run` / `SSHServer::run` are re-created on every poll and must be restart-safe

## Summary

`AsyncSunset::output_loop` drives the socket write inside `poll_fn` by
constructing `wsock.write(buf)` fresh on every poll:

```rust
let res = {
    let w = wsock.write(buf);
    pin!(w);
    w.poll(cx)
};
```

A `Write` implementation that parks mid-buffer (returns `Pending` after
partially queueing bytes) and is then **re-polled as a new future** will start
over from offset 0 and duplicate the already-queued prefix. Real sockets are
safe (their writes are restart-tolerant), but any in-memory / test transport
built on a bounded queue silently corrupts every write larger than its
capacity — and the failure surfaces far away, as a KEX error.

We hit exactly this with an embassy-channel-backed test transport: writes
≤ 512 B (the queue capacity) always worked, the 1240-byte mlkem
`KexDHInit` was corrupted from byte ~503 onward, and the failure appeared as
`Error::BadKex` from `EncapsulationKey::new` server-side — which initially
looked like a crypto bug in sunset. Fixing the transport (resume from the
already-sent offset) made negotiated `mlkem768x25519-sha256` sessions pass
end-to-end.

## Ask

A short note in the `sunset-async` docs (README or `SSHClient::run` rustdoc)
stating the contract: `Write` implementations must tolerate being re-created
mid-write (track their own progress) or return short writes instead of parking
mid-buffer. That would save the next person a multi-hour crypto-shaped
goose chase. Happy to send a doc PR if preferred.
