# Verifying the ES10B diagnostic before spending a paid activation code

Field record, 2026-11-27. The instrument described here was built for
conwrt#866. This note exists because **an unproven instrument is not worth
spending a single-use code on**, and the first version of it silently did
nothing for four separate reasons. All four are recorded, because each one
would independently produce a false "the card said nothing useful" conclusion.

## Why this matters

Every attempt so far failed at or before `authenticateClient`, so
`es10b_load_bound_profile_package` was never entered and the diagnostic added
in the previous session **never fired once**. Buying the $0.99 profile against
that would have been a bet on an untested instrument.

## The four failure modes, in the order they were found

### 1. `chip info` does not reach ES10B at all

The obvious zero-cost smoke test is to run `lpac chip info` with the diagnostic
enabled. It prints nothing. That is not a broken diagnostic — `chip info` reads
EUICCInfo2 via a different path and **never calls
`es10b_get_euicc_challenge_and_info`**. Only `profile download` and
`profile discovery` do. A diagnostic that only fires inside the paid path cannot
be validated with a free command, so the instrument had to be moved somewhere
free-*ish* — see §3.

### 2. The remote shell never received the variable

The relay builds a single `ssh` command string. Environment variables set on the
host do **not** cross `ssh`; they have to appear in the remote `export` line. The
original code was:

```python
"export LPAC_APDU=at LPAC_APDU_AT_DEVICE=/dev/ttyUSB2 LPAC_HTTP=stdio; "
"exec /usr/bin/lpac " + ...
```

so `LPAC_DEBUG_ES10B=1` on the caller side was inert. `lpac` on the router never
saw it, took the silent branch, and the hex dump never ran. Fixed by forwarding
it explicitly:

```python
dbg = " LPAC_DEBUG_ES10B=1" if os.environ.get("LPAC_DEBUG_ES10B") else ""
```

This is the failure mode most likely to fool the next person, because the
symptom is identical to "the card returned nothing": no output, no error.

### 3. The diagnostic was attached to the wrong function

It was first placed in `es10b_load_bound_profile_package_tx()` — the function
that actually produces the `unknown,unknown` — which is correct for the real
run but unreachable for testing. Moved a copy into
`es10b_get_euicc_challenge_r()`, which is called on **every** download attempt
*before* any SM-DP+ contact. That makes it fire even when the attempt is going
to die at `authenticateClient`, so the instrument can be proven with a code that
costs nothing (a test code that will be rejected anyway).

### 4. Piping stderr without draining it deadlocks

Once stderr was piped (`stderr=subprocess.PIPE`) to capture diagnostics, nothing
appeared and the run could hang: an undrained pipe blocks the child once the
buffer fills. Fixed with a drain thread that is **joined after** `p.wait()`,
otherwise the last buffered lines are lost on process exit:

```python
_t = threading.Thread(target=_drain, args=(p.stderr,), daemon=True)
_t.start()
...
p.wait()
_t.join(timeout=10)   # let buffered stderr finish before we exit
```

## Proof it now works

Through the relay, with the diagnostic forwarded:

```
$ LPAC_DEBUG_ES10B=1 python3 run_lpac_relay.py profile download -a '<test code>'
ES10B_RX[get_euicc_challenge] len=21 hex=BF2E128010EB3C8B98000970240971BBDBBD75B8AB
```

`BF2E 12 80 10 <16-byte nonce>` — a valid `EUICCChallengeResponse`, captured
end to end, with a different nonce on each run (two independent runs gave
`…EB3C8B98…` and `…106A241B…`, so it is live data, not a cached constant).

## Cost

Zero. The test code used (`TS48V1-A-UNIQUE`, sysmocom's free SGP.26 test
profile) is rejected at `initiateAuthentication` — by certificate chain, per
`docs/nr7101/SGP26-CI-MISMATCH-PROOF.md` — so the run burns nothing while still
exercising the diagnostic path. Card verified `profile list → []` afterwards.

## The rule

**Prove the instrument on the cheapest path that reaches it, before spending
anything on the expensive path it was built for.** In this case the only way to
reach ES10B is a download, so a code that is *known to fail early for an
unrelated reason* is the ideal probe: it reaches the instrument without
consuming anything.

Three of the four failure modes above produce **silence**, which reads exactly
like "the card produced no diagnostic". Silence is not a result.
