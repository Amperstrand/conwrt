# Upstream issue draft: sunset-async re-enables sunset's `mlkem` default via feature unification

> **HUMAN SUBMISSION ONLY — DO NOT AUTOMATE.**
>
> This document is a DRAFT for a human operator to review, sanitize-check, and
> submit by hand to https://github.com/mkj/sunset/issues. Per the repository's
> external-etiquette rules (AGENTS.md), automation must NEVER open issues,
> comment, or interact with repositories outside the Amperstrand organization.
> The only acceptable automated action on this file is editing it in place.
>
> **Reference:** conwrt spike #112 (`docs/sunset-mcu-ssh-spike.md`, finding 1).
>
> **Sanitization status:** no secrets or private details; size numbers are
> from our public spike measurements.

## Title

`sunset-async`'s dependency edge defeats `sunset = { default-features = false }` in applications (feature unification re-enables `mlkem`)

## Summary

An application that depends on

```toml
sunset = { version = "0.6", default-features = false }
sunset-async = "0.6"
```

still gets sunset compiled **with** the default `mlkem` feature, because
sunset-async's own dependency edge
(`sunset = { version = "^0.6", features = ["embedded-io"] }`) contributes
sunset's default features under cargo feature unification. The app's
`default-features = false` only stops its own edge from contributing
defaults; it cannot disable what another edge enables.

## Why it matters on embedded

Measured on `thumbv7em-none-eabihf` (release, opt-level "s", LTO,
codegen-units 1, size-gated firmware): the mlkem code path costs
~14.5 KiB flash that an application which only wants the
curve25519/chacha20-poly1305/ed25519 floor cannot opt out of today.
(`mlkem768x25519` also has no interop partner on Dropbear ≤ 2024.86.)

## Suggested fix

Add `default-features = false` to sunset-async's `sunset` dependency edge
(`embedded-io` is purely additive, so nothing changes for std users), or
expose an explicit opt-in feature (e.g. `sunset-async/mlkem` →
`sunset/mlkem`) so embedded users can choose. Happy to send the one-line PR
either way.

## Workaround we use today

```toml
[patch.crates-io]
sunset-async = { path = "../patched-sunset-async" }  # same crate, sunset edge with default-features = false
```
