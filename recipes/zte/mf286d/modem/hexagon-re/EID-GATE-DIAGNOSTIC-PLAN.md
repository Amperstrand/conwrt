# EID-Gate Diagnostic Plan (EXP-042) — read first

## The question
0x67 register SUCCEEDS but 0x65 GET_EID returns INTERNAL (0x03) = the
m2m_euicc client-state gate (qmi_uim_m2m_euicc.c:167). Why?

## Decoded facts (uim-protocol-spec.json)
- 0x67 register REQ = {TLV01 slot} + **TLV10 u64 OPTIONAL — NEVER SENT in
  any probe**. If it is an event-mask (register-for-events convention),
  omitting it = registered-for-nothing; if a client token, omitting = 0.
- 0x65 EID REQ = {TLV01 slot} only — no token field, so the gate must be
  keyed by connection or by the register's state.
- type#0 session aggregate = {slot, ICCID[32], u8} — sessions key by slot+ICCID.
- 0x6b REQ = {slot + MANDATORY u8 TLV02 + optional u32} — bare {slot} starved
  a handler that then crashed the modem (device drop). RULE: never call
  messages with mandatory TLVs omitted.

## The ONE decisive diagnostic: DIAG F3 capture during a 0x65 attempt
Watch-list (ssid 21, hash = Qshrink line index):
| hash | line | meaning |
|---|---|---|
| 80675 | m2m:137 | GET_EID response sending (would mean SUCCESS path) |
| 80676 | m2m:143 | Null userdata ptr in response |
| **80677** | m2m:167 | **Transaction ptr or client state pointer NULL (our current failure)** |
| **81270** | lpalib:463 | **LPA get EID queued, status=0x%x (read the status arg!)** |
| **82975** | lpa_cmd:1034 | **LPA task STOPPED — cannot queue** |
| 79886 | mmgsdi_euicc_m2m:250 | get_eid_cb status=0x%x (internal card result) |
| 84299 | mmgsdi_euicc:205 | SELECT ISDR failed (modem's own ISD-R open failed!) |
| 78841 | lpa.c:483 | QMI modem task ready (boot) |
| 76843 | lpa_state.c:94 | LPA state change cur->next |
Decision table:
- See 82975 -> LPA task not running (lpa_support EFS? task spawn?) -> fix = task init
- See 81270 with status!=0 -> LPA queued but card op failed -> read status + 79886
- See 80677 only -> pure qmi-layer state gate -> the register semantics are wrong (token)
- See 84299 -> the modem's INTERNAL ISD-R session failed = the compiled
  deny hitting the modem's own LPA (would be campaign-final irony)

## Probe queue for next device window (in order, all read-only)
1. regcall2 67 65 1  (register WITH u64 token, EID, EID-with-token)
2. DIAG F3 capture running during (1) — watch-list above
3. callslot 63 4b 41 (state/version/ATR sanity between attempts)
4. If 81270 fires with status=0: retry 0x65 after 5s (async completion)
5. 0x4f full body: {slot=1, TLV02 u8=0, TLV03 u32=0} — the info query
   with u8[255] varlen response (may reveal the euicc info dump)

---

## ⛔ CRASHER REGISTER (2026-11-10, EXP-042 live)

**0x67 register with VALID u64 TLV10 token (8 bytes, any value) = MODEM QMI KILLER**

- v7 (truncated 4B token): safe — MALFORMED at decode, never reaches handler
- v8 (proper 8B u64, value 0xFFFFFFFFFFFFFFFF): **QMI subsystem died immediately**
  - `read: No such device` during probe
  - ALL QMI services dead after ("Failed to connect to service")
  - AT port still works, USB device present
  - Same SMEM/IPC partial-outage pattern as mtd1/mtd2 panics
  - Recovery: cold power cycle required (may or may not survive)

**Implication**: the u64 TLV10 in 0x67's register is NOT an event mask or
client token — it reaches code that corrupts shared-memory state. The IDL
spec says it's optional u64, but the handler treats nonzero/any values
destructively. This is a FIRMWARE BUG or a deliberately booby-trapped field.

**CRASHER LIST (never do these)**:
1. Read mtd1 (mibib) or mtd2 (efs2) from modem Linux
2. Call UIM 0x6b with bare {slot} (missing mandatory u8 TLV02)
3. Call UIM 0x67 with valid u64 TLV10 token (8 bytes)
