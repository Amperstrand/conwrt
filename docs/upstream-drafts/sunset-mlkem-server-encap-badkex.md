# Upstream issue draft: sunset 0.6.0 — mlkem768x25519 KEX fails server-side (`BadKex`) in in-memory client/server session

> **HUMAN SUBMISSION ONLY — DO NOT AUTOMATE.**
>
> This document is a DRAFT for a human operator to review, sanitize-check, and
> submit by hand to https://github.com/mkj/sunset/issues. Per the repository's
> external-etiquette rules (AGENTS.md), automation must NEVER open issues,
> comment, or interact with repositories outside the Amperstrand organization.
> The only acceptable automated action on this file is editing it in place.
>
> **Reference:** conwrt spike #112 (`docs/sunset-mcu-ssh-spike.md`, finding 2).
>
> **Sanitization status:** no secrets, passwords, or bench details; the
> harness uses throwaway keys generated per run; host paths are generic.

## Title

Server-side mlkem768x25519 KEX fails with `BadKex` (ml-kem 0.3.2 `EncapsulationKey::new` validation) while the same client completes fine against Dropbear 2026.94

## Environment

- sunset 0.6.0 (crates.io and tag `sunset-0.6.0`), ml-kem 0.3.2
- Rust 1.99.0, Linux x86_64 (host std build; real OS RNG via getrandom — no custom RNG hook involved)
- Client and server both sunset 0.6.0 default features (mlkem on), connected
  back-to-back over an in-memory `embedded_io_async` duplex (embassy-sync
  channels), `SSHClient::new` / `SSHServer::new` with 2000-byte buffers

## What happens

1. Both sides exchange KexInit; negotiated kex is `mlkem768x25519-sha256`
   (client preference), hostkey `ssh-ed25519`.
2. Client sends KexDHInit (`q_c` len 1216 = mlkem ek 1184 ‖ x25519 32).
3. Server `progress()` returns `ServEvent::Hostkeys`; answering it via
   `h.hostkeys(&[&ed25519_signkey])?` returns `Err(BadKex)`.
4. Sunset trace shows the failure inside
   `KexMlkemX25519::secret_encap_server` →
   `EncapsulationKey::<MlKem768>::new(ek)` (the ml-kem 0.3.2 key-decode
   validation rejecting the client's encapsulation key; the
   `split_at_checked(MLKEM768_PUBKEY_SIZE)` length check passes — the 1184
   bytes themselves are rejected).

The identical harness with sunset `default-features = false` (so
`curve25519-sha256` is negotiated) completes the full session: KEX, hostkey
verify, password auth, session open, exec, payload round-trip.

## Why we believe the server side is the culprit

`sunsetc` (tag `sunset-0.6.0`, default features, mlkem preferred) completes a
**full session against a real Dropbear 2026.94 server that also negotiated
`mlkem768x25519-sha256`**: hostkey verify, pubkey auth, exec all pass. That
means the client-side keypair generation (`init_pubkey_arr_client`) produces a
valid, accepted encapsulation key — the same code path our in-memory client
uses. This isolates the failure to sunset's server-side
`secret_encap_server` validation path.

## Minimal reproduction shape

```rust
// Two embassy-sync channel pairs as an embedded_io_async duplex.
// SSHClient::new(&mut rxbuf[..2000], &mut txbuf[..2000]) on one end,
// SSHServer::new(...) on the other; poll both with ProgressHolder loops.
// Server event loop:
ServEvent::Hostkeys(h) => {
    let hostkey = SignKey::generate(KeyType::Ed25519, None)?;
    h.hostkeys(&[&hostkey])?;   // <-- Err(BadKex) with mlkem negotiated
}
// Client event loop: Hostkey => accept, Username/Password => provide.
```

Happy to share the full ~350-line harness if useful.

## Suspicion (untested)

ml-kem 0.3.2's `EncryptionKey::from_bytes` implements the FIPS 203 key-decode
check (modulus/encoder bounds). If sunset generates the client ek from a seed
and serializes it in a form that trips the decode check when re-parsed
server-side (or if the `q_c` wire layout expected by `secret_encap_server`
doesn't match what the sunset client emits), the server rejects its own
client's key. Version skew between what sunset 0.6.0 was developed against
and ml-kem 0.3.2's validation strictness is a plausible cause.
