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

A plain `default-features = false` on sunset-async's sunset edge would
*remove* mlkem from applications that only depend on sunset-async — a
default-feature regression for current users. Better: keep the default
behavior and forward an explicit opt-out feature:

```toml
[features]
default = ["mlkem"]
mlkem = ["sunset/mlkem"]
```

so std users are unchanged, and embedded users can write
`sunset-async = { version = "0.6", default-features = false }` to keep
mlkem out of the binary. Happy to send the PR either way if a different
shape is preferred.

## Where we carry it today

Our org fork (`Amperstrand/sunset`, branch `ai-experiments`, based on the
`sunset-0.6.0` tag) implements exactly the suggested forwarded feature and
carries a negotiated-mlkem regression test. We'd happily retire the fork in
favor of an upstream release containing this.
