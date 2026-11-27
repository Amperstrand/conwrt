# SGP.26 test servers: proven unusable on this card (server-side rejection)

Field record, 2026-11-27. This is **not** an inference from key IDs — the
SM-DP+ itself returns the mismatch as a GSMA status code. It settles the
"can we use the free unlimited test profiles?" question with a hard negative.

## The exchange

Pointed `lpac` at sysmocom's free SGP.26 test SM-DP+ with their published
`TS48V1-A-UNIQUE` activation code. The LPA sent (captured from the relay log):

```json
{"smdpAddress":"smdpp.test.rsp.sysmocom.de",
 "euiccChallenge":"Ri0Z7b+vdJ3N6TyVUFrpaw==",
 "euiccInfo1":"vyA1ggMCAgKpFgQUgTcPUSXQsdQI1MOyMubSXnlb6/uqFgQUgTcPUSXQsdQI1MOyMubSXnlb6/s="}
```

Decoding that `euiccInfo1` (it is a `BF20` EUICCInfo1 DER structure):

```
BF20 3582 0302 0202A9 1604 1481370F5125D0B1D408D4C3B232E6D25E795BEBFB
                          AA1604 1481370F5125D0B1D408D4C3B232E6D25E795BEBFB
```

- `BF20` — EUICCInfo1
- `A9` — euiccCiPKIdListForVerification → **`81370f51…5bebfb`**
- `AA` — euiccCiPKIdListForSigning → **`81370f51…5bebfb`**

So the card advertises exactly one CI, for both directions, and it is a
**production (GSMA Live) CI**.

The server's verdict:

```json
{"header":{"functionExecutionStatus":{"status":"Failed","statusCodeData":{
  "subjectCode":"8.8.4","reasonCode":"3.7",
  "message":"The SM-DP+ has no CERT.DPauth.SIG which chains to one of the eSIM CA Root CA Certificate with a Public Key supported by the eUICC"}}}}
```

`8.8.4 / 3.7` names the failure precisely: the test SM-DP+ holds a
`CERT.DPauth.SIG` under the SGP.26 **test** CI, and this eUICC trusts only the
production CI. There is no client-side fix, no flag, and no ordering change —
the certificate chains are disjoint by construction.

## The certificate observation

`smdpp.test.rsp.sysmocom.de` presents an issuer that makes the split visible at
the TLS layer too:

```
subject: O = sysmocom, CN = smdpp.test.rsp.sysmocom.de
issuer:  CN = Test CI, OU = TESTCERT, O = RSPTEST, C = IT
```

`Test CI / TESTCERT / RSPTEST` is the SGP.26 test hierarchy. Production RSPs
present `O = GSM Association, CN = GSM Association - RSP2 Root CI1` instead.
Different roots, different keys, no cross-signing.

For reference, the published test-CI key IDs:

| Server | Key ID |
|---|---|
| sysmocom `smdpp.test.rsp.sysmocom.de` | `f54172bdf98a95d65cbeb88a38a1c11d800a85c3` |
| Infineon `testsmdpplus.infineon.com` | `f54172bd…`, `c0bc70ba36929d43b467ff57570530e57ab8fcd8` |
| Google `prod.smdp-plus.rsp.goog` | `b60f0b897fd630b88cfed6161f8ea808c5382ac3`, `665a1433d67c1a2c5db8b52c967f10a057ba5cb2` |

None of these appear in this card's `euiccInfo1`.

## Corollary worth writing down

`rspCapability` on this card includes **`testProfileSupport`**, which is easy to
read as "this card can use test profiles". It does not mean that. Test-profile
*support* (the card can host a profile whose policies mark it as a test profile)
is unrelated to whether the card trusts the **SGP.26 test CI**. Conflating the
two sends you down a dead end; it cost a detour here.

## A separate tool bug found on the way

sysmocom publishes matching IDs containing underscores (`TS48v1_A`,
`TS48v2-SAIP2-1-NoBERTLV-unique`). `lpac` 2.3.0 rejects them before any network
call:

```
{"code":-1,"message":"matching_id",
 "data":"invalid format, contains character not alphanumeric or dash"}
```

`is_strict_matching_id()` in `src/applet/profile/download.c` allows only
alphanumerics and `-`. SGP.22's MatchingID grammar is more permissive than that,
and a real RSP's own published codes violate lpac's validator — so legitimate
codes become unusable. The `-UNIQUE` variants (`TS48V1-A-UNIQUE`) do pass the
validator, which is how the exchange above was obtained at all.

## Conclusion

**The free SGP.26 test route is closed for this card by its own certificate
chain, and the SM-DP+ says so in its own words.** Combined with the earlier
finding that the production-CI free codes are EID-bound (truphone, `8.1.1/3.8`)
or exhausted (redteaGO, `9.4/10.1`), there is **no free profile obtainable for
this eUICC**. The remaining step requires an actual per-EID order.
