# Why every free/public activation code fails on this card

Field record, 2026-11-27. Captured from the SM-DP+ responses themselves, not
inferred. This closes the "is there a free profile we can still use?" question
for this eUICC.

## The card's PKI, which decides everything

```
euiccCiPKIdListForVerification: 81370f5125d0b1d408d4c3b232e6d25e795bebfb
euiccCiPKIdListForSigning:      81370f5125d0b1d408d4c3b232e6d25e795bebfb
euiccFirmwareVer: 4.2.0   svn: 2.2.2   profileVersion: 2.3.1
sasAcreditationNumber: ED-ZI-UP-0826
rspCapability: [additionalProfile, testProfileSupport]
```

That CI key is a **production (GSMA Live) CI**, not an SGP.26 test CI. Compare
the published test-CI key IDs:

| Server | Key ID |
|---|---|
| sysmocom `smdpp.test.rsp.sysmocom.de` | `f54172bdf98a95d65cbeb88a38a1c11d800a85c3` |
| Infineon `testsmdpplus.infineon.com` | `f54172bdf98a95d65cbeb88a38a1c11d800a85c3`, `c0bc70ba36929d43b467ff57570530e57ab8fcd8` |
| Google `prod.smdp-plus.rsp.goog` | `b60f0b897fd630b88cfed6161f8ea808c5382ac3`, `665a1433d67c1a2c5db8b52c967f10a057ba5cb2` |

**So the unlimited-download SGP.26 test servers are ruled out by hardware, not
by policy.** This card cannot authenticate to them and they cannot sign for it.
`testProfileSupport` in `rspCapability` is not the same thing as carrying an
SGP.26 test certificate — easy to conflate, and it misled me at first.

## The production-CI free codes, and exactly how each failed

All four codes published as "freely downloadable any number of times" were
tried. Each server answered with a specific GSMA status; these are the raw
`functionExecutionStatus` blocks.

**`rsp.truphone.com`** — `QR-G-5C-1LS-1W1Z9P7`, `QR-G-5C-KR-1PCDWP9`,
`QRF-BETTERROAMING-PMRDGIR2EARDEIT5`, `QRF-SPEEDTEST` all fail identically at
`authenticateClient`:

```json
{"functionExecutionStatus":{"status":"Failed","statusCodeData":{
  "subjectCode":"8.1.1","reasonCode":"3.8",
  "subjectIdentifier":"EID","message":"Refused"}}}
```

`8.1.1 / 3.8` decodes as **"EID doesn't match the expected value"**. The
`subjectIdentifier` is literally `EID`. This is the documented behaviour of a
code that has already been bound to a specific eUICC — and a code published on a
public docs page gets bound to the first card that uses it. Upstream confirms
this reading (estkme-group/lpac#239: "this profile has been downloaded onto
another eSIM card or locked to the fixed device identified by EID … it's not the
issue of lpac").

Worth recording alongside it: the follow-up `cancelSession` on that host returns
`8.1 / 6.1`, *"eUICC signature is invalid or serverChallenge is invalid"*. That
is expected here (the session was already dead, so the challenge no longer
matches) and is **not** evidence of a card fault — but it is exactly the kind of
secondary error that gets misread as one.

**`rsp-eu.redteamobile.com`** — `5901981126831169` gets *further* (it is not
EID-locked) and then fails at `authenticateClient`:

```json
{"functionExecutionStatus":{"status":"Failed","statusCodeData":{
  "subjectCode":"9.4","reasonCode":"10.1",
  "message":"campaign resource pool is empty",
  "subjectIdentifier":"5901981126831169"}}}
```

A completely different failure class: **the promotional pool is exhausted
server-side**. Not a card problem, not a tooling problem, and not something any
client change can fix.

## What this means

1. **There is no free profile obtainable for this card right now** through any
   of the published free codes. Two independent causes, both server-side:
   EID-lock (truphone) or exhausted supply (redteago).
2. **The SGP.26 route is closed by the card's own certificate**, so retrying
   sysmocom or Google is not a workaround.
3. **The next step requires an actual order** — a free trial through an RSP
   that issues a per-EID code, or the paid test profile. Nothing else will make
   progress.
4. **The install-stage failure is still unexplained and still unreachable.**
   Every current attempt dies at `authenticateClient`, before ES10b is ever
   entered — so the `LPAC_DEBUG_ES10B` diagnostic built for #866 has not fired
   once, and the question of whether the ES10b load failure (and the MSS theory
   in estkme-group/lpac#474) is the real cause remains open. It cannot be
   settled without a code that gets past authentication.

## Method note

The relay logs the full request/response body of every ES9+ exchange to
`runs/http-exchange.log`. That is what turned "Refused", a one-word summary
from `lpac`, into `8.1.1/3.8 subjectIdentifier=EID` and then into
`9.4/10.1 campaign resource pool is empty`. **Log the transport bodies.** A
client's summarized error string is not diagnostic; the server's own status
block is.
