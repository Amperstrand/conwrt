# Cellular Access Without a Subscription — Negotiation, Test SIMs, JIT Activation (2026-09-27)

Research note for the TollGate-for-cellular concept. Companion to
`docs/NR7101-FLEET.md` (bench hardware/RF state). Sources verified 2026-09-27;
rates change — re-verify at purchase.

## 1. What an un/subscribed device can and cannot do (taxonomy)

| Device state | What works on a commercial tower | Negotiation possible? |
|---|---|---|
| **No SIM (IMEI-only)** | Emergency attach (voice/SMS to emergency only, no data bearers). Broadcast reads (SIB/MIB), RACH responses, scans. | **No.** No AKA keys → network has nothing to authenticate; NAS has no "enroll me" primitive. |
| **Dead/dummy SIM** (HLR record absent/expired) | Same as above + attach attempts answered with reject causes (bench-evidenced: Telenor quiet-fail, ice `+CEREG: 1,3` deny). | **No.** AKA fails — the operator's AuC does not hold the matching `Ki`. |
| **Test SIM** (MCC 001 test PLMN, sysmocom/GCF USIMs) | Nothing on commercial networks (no subscription; usually PLMN-barred). Everything on a **test core you control**. | **Yes — if you are the tower.** See §4. |
| **Dormant-but-provisioned SIM/eSIM profile** | Full auth succeeds; service gated by OCS/PCRF *policy* (billing state), not by cryptography. | **Yes — this is the JIT window.** Payment flips policy server-side in seconds. See §3. |

Why radio-side activation cannot exist: the eNB/gNB is subscription-blind (it
ferries NAS); every decision is MME→HSS (LTE) / AMF→AUSF/UDM (5G); attach is a
challenge-response against a pre-shared key, not a negotiation; and no data
bearer exists before auth succeeds, so there is no channel to carry payment.
Emergency service is the single policy exception (voice/SMS only — not used
here).

## 2. Key insight, correctly located

> "If we can settle payment through ecash or a voucher, the tower could
> just-in-time activate and allow the device to communicate."

Correct insight, wrong layer: **the gate is never the tower — it is the
HLR/UDM/OCS subscription+policy state.** JIT activation works exactly as
imagined **iff the device already holds valid credentials** (dormant SIM or
downloaded eSIM profile). Then: payment → API → policy flip → next attach
succeeds. Existing precedents:

- Scratch-card top-up = voucher redemption (USSD) — the original JIT model.
- Zero-balance walled gardens: 5G UPF redirects out-of-credit sessions to a
  DNS-spoofed captive portal with payment-processor whitelist; instant
  restore on payment (OmniUPF docs; LinkIT Zero Balance product).
- Soracom: SIM in `Standby` auto-flips to `Active` on first connection
  attempt; `activateSim`/`suspendSim` REST APIs.
- emnify: prepaid-quota API — "customer pays, service instantly available".
- silent.link: balance-based PAYG eSIM, top-up in BTC/LN/XMR, **balance never
  expires** — a voucher-balance model, crypto-native (§3).

## 3. Provider comparison for the bench build (Norway)

| | silent.link | Onomondo | Soracom plan01s | NO consumer prepaid |
|---|---|---|---|---|
| Model | PAYG balance eSIM, 160+ countries | IoT MVNO, API-first PAYG | Global IoT, lifecycle APIs | Retail prepaid |
| **Data cost (Norway)** | ~$1.33–1.55/GB on main EU networks ("as low as $1.50/GB" Europe); **rate depends on which network the modem roams onto — you cannot choose**; check NO rate on silent.link/rates before relying | **€0.003/MB ≈ €3.07/GB** (market-rate PAYG; ICE + Telenor + Tampnet in NO) | **€0.05/MB ≈ €51/GB in Norway** (100 kB billing unit). planX3-EU €3.50/mo per 1GB is EU-only — NO coverage doubtful | cheapest per GB, but zero API, KYC, expiry |
| Fees | $9 eSIM fee; no expiry, no plan fee | no inactive-SIM fees | $0.06/day when Active; renewal fee after 1 yr dormant | SIM ~kr 50–100 |
| Payments | **BTC / Lightning / XMR / USDT**, no KYC, self-hosted BTCPay, works over Tor | invoice/card (business) | card/invoice | card/cash |
| APIs | **bulk provisioning API** (`GET /api/v1/bulk/stock`, `POST /api/v1/order/new`, order poll, CSV) + order-page balance mgmt | full REST + webhooks (activation, quotas, network selection) | richest lifecycle API (activate/standby/suspend, event handlers, metadata DNS) | none |
| Fit | cheapest data + crypto rails; rate unpredictability | **best engineering option for NO** | best API playground; data cost in NO prohibitive | baseline only |

**Cashu bridge (buildable today):** Cashu `Melt` → Lightning invoice →
silent.link BTCPay top-up → eSIM balance active. Storefront = TollGate portal
that mints data access for ecash; silent.link absorbs the telco side. Their
bulk API even fits fleet provisioning of NR7101 SIMs.

## 4. Test SIMs + your own core: "be the tower"

The only world where a tower truly negotiates is one you operate:

- **SDR + srsRAN (or OpenAirInterface) + open5GS**: run your own eNB/EPC
  (LTE) or gNB/5GC on the bench. Test USIMs (sysmocom, programmable: you
  write IMSI/Ki/OPC into both SIM and your HSS) attach to *your* cell.
- Then JIT activation is a database write in **your** HSS: device pays ecash
  → your gateway inserts the subscriber → attach succeeds → data. Full
  TollGate-for-cellular prototype with zero telco dependency.
- NR7101 locks to a band/CPI, so it can camp a lab cell deliberately.
- **Caution**: transmitting on licensed LTE/NR bands requires low power,
  shielding/enclosure, and legality awareness (test setups belong in shielded
  boxes or with appropriate licenses). Keep RF power minimal; prefer receive-only
  experiments (scans, SIB decode) unless properly shielded.

## 5. Recommended bench sequence

1. **Now, zero cost**: continue unauthenticated surveys (COPS/QCSQ/QENG), all
   documented in NR7101-FLEET.md.
2. **Cheapest live data**: one silent.link DATA.PLUS eSIM (~$9 + balance) —
   crypto-paid, never expires; confirm the Norway per-network rate at order
   time. Glue Cashu→LN later for the full TollGate loop.
3. **Engineering rig**: one Onomondo SIM (€3/GB, REST/webhooks, NO networks
   incl. ICE) for scripted attach/detach/quota experiments.
4. **Research endgame**: SDR + srsRAN + test USIMs in a shielded enclosure —
   own the whole gate.

## 6. The 5G walled-garden mechanism (TollGate semantics in the carrier core)

Modern 5G cores (AMF/SMF/UPF/PCF/OCS) implement out-of-credit gating exactly
like a captive portal:

1. Normal: SMF programs the UPF (via PFCP) to FORW (forward) all session
   traffic.
2. Zero balance: OCS/PCF flags it -> SMF sends PFCP Session Modification with
   a FAR containing `redirect_information`.
3. UPF then: spoofs ALL DNS answers to the portal IP (this trips the OS
   captive-portal probes: connectivitycheck.gstatic.com / captive.apple.com /
   msftconnecttest.com -> portal auto-opens); whitelists payment processors
   (Stripe, CAPTCHA, CDNs); drops everything else. Session stays up.
4. Payment lands -> OCS credits -> FAR flips back to FORW -> traffic resumes
   on the same session, instantly.

Gotcha (documented in OmniUPF): the probe's HTTP request keeps its original
`Host:` header, so the portal must be the default vhost on the portal IP.
LTE equivalent: PGW/Gx PCEF redirect (the classic zero-balance top-up page).

Mapping to our stack: nodogsplash <-> UPF FAR redirect; dnsmasq redirect <->
UPF DNS spoofer; portal uhttpd <-> portal server (default vhost); Cashu
settlement <-> OCS credit; release-on-payment <-> FAR flip. Bench-verified
2026-09-27: TollGate NR7101 runs nodogsplash 5.0.2 + dnsmasq + uhttpd;
house-net probes return clean 204/200/200 (portal-detection mechanism
demonstrated client-side).

## 7. What is observable per credential state

| State | Radio layer | User plane (DNS/APN/ping/portal) |
|---|---|---|
| No SIM | scans, SIB/MIB (SDR), RACH | none (emergency attach = voice/SMS only; NOT used) |
| Dead SIM (ours) | + attach reject causes | **none — no IP path exists pre-auth, by design** |
| Registered SIM | + serving/neighbour cells, band lock | full: DNS, walled garden, APN tests, QPING |
| SDR receive-only | full SIB decode, paging | (observation only) |

## 8. Test endpoints & emergency-adjacent research (2026-09-27)

Question: any emergency-services test interfaces, test DNS endpoints, or test
APNs reachable as a ping? Findings:

- **No public 112/110/113 test numbers or SMS test keywords exist in Norway.**
  Emergency-call testing happens through organized, operator/regulator-led
  trials only. We will not send any traffic to real emergency services.
- **Caution precedent (Nkom, Sep 2026)**: after Telia's 2G shutdown (autumn
  2025), phones that misuse emergency roaming ("nødgjesting") are being
  identified and can be **blocked from the networks**. Any experimentation
  that touches emergency-attach semantics risks IMEI-level barring. Do not.
- **Test APNs are lab artifacts, not services**: the "test" APN entries in
  Android's carrier DB (MCC 001 Test Network: VZWINTERNET "Test Internet",
  AT&T/T-Mobile "TEST SIM", etc.) pair with test SIMs on lab cores. On
  commercial networks they do not exist as reachable endpoints; APN selection
  happens after auth anyway. Offline APN reference for live SIMs:
  GNOME `mobile-broadband-provider-info` and apn.how.
- **With the dead bench SIM: nothing is ping-able. No DNS, no APN, no portal
  is reachable pre-authentication — this is architecture (no bearer before
  AKA), not configuration.** The staged `AT+QPING` path activates the moment
  any registering SIM is seated.
- **Legitimate paths to ping capability**: (a) dormant-provisioned IoT/MVNO
  SIM (Onomondo/silent.link/Soracom — attach + ping for pennies);
  (b) own core (srsRAN + open5GS + test USIMs) — unlimited test APNs/DNS of
  our own design.
- **Future institutional test infra (context)**: Norway's new Nødnett is the
  world's first multi-operator, multi-core 5G emergency network (Nkom +
  Telenor/Telia/Lyse agreements 2025-12/2026-03), with dedicated **5G test
  slices** and a data-services test platform (Norsk Helsenett, SimulaMet);
  first users ~end 2029. Institutional access only — but network slicing is
  exactly the mechanism that could someday carry authorized third-party test
  access.
- **JIT-activation precedent in the wild (Telia, SAR61°N June 2026)**:
  rescue personnel provisioned onto Telia's network in minutes via an
  app-issued eSIM — operator-sanctioned just-in-time activation, backend +
  eSIM, zero tower negotiation. Commercial proof that the TollGate-style
  "pay/trust -> instant attach" model works; payment rails are the only
  missing piece for a civilian version.

SIM disposition (bench): the seated Telenor ICCID 89470000220307358484 is
confirmed dead (home-PLMN quiet-fail; ice explicit deny). Retained as inert
hardware; replace when live testing is wanted.

## 9. Voucher-bootstrapped access (SIM-less negotiation) — research 2026-09-27

Question: can a device WITHOUT a SIM present a voucher/token to a network and
be provisioned just-in-time ("I am authorized for this exercise/event")?

**Commercial PLMNs: no, by design.** AKA needs a symmetric pre-shared key
(Ki) in both SIM and AuC; NAS has no voucher-presentation message;
provisioning is operator-internal. Norway's emergency answer (Telia SAR61°N
eSIM test) pre-stages credentials for exactly this reason.

**3GPP Rel-17 standardized the concept — for private networks:**

- **SNPN Onboarding** (TS 33.501 Annex I.9; TS 23.501 5.30.2.10): a UE
  configured with **Default UE Credentials** ("information configured in the
  UE to make it uniquely identifiable and verifiably secure to perform UE
  onboarding") attaches to an **Onboarding SNPN**, authenticates against a
  Default Credentials Server (AUSF/UDM or AAA flavor), gets a PDU session for
  "User Plane Remote Provisioning", and receives real network credentials
  over the air. This is the voucher-bootstrap pattern, standardized.
- **Anonymous SUCI** (TS 23.003): certificate UEs encrypt before revealing
  identity; **realm-based AAA routing** on the SUCI/NAI realm is literally
  "which organization/event is this device claiming membership in".
- **EAP-TLS for SIM-less UEs** (TS 33.501): mutual certificate auth; key
  hierarchy (K_AUSF) extended to any key-generating EAP method; EAP-TTLS in
  Annex U. Rel-18 adds SNPN access for non-3GPP/N5CW (WLAN-only) devices.
- Open-source state: **free5GC + UERANSIM EAP-TLS implementation for
  non-SIM devices** (NYCU 2025/2026; ~11% latency overhead vs 5G-AKA);
  Open5GS EAP-TLS prototype (thesis, via N3IWF).

**Bench demo design (zero RF, zero spectrum, no emergency involvement):**

srsRAN **ZMQ virtual radios** run eNB+EPC+UE entirely in software; srsUE
defaults to a **virtual USIM** (IMSI/Ki/OP in `ue.conf` — no physical SIM).
Loop to demonstrate:

    Cashu voucher -> redemption webhook -> insert subscriber
    (open5GS DB / srsEPC user_db.csv) -> srsUE attaches -> data flows

Optional upgrade path: free5GC+EAP-TLS patch + UERANSIM = certificate (true
SIM-less) attach. Runs on ai-legion in containers/netns; nothing transmits.

**Fundamental limit that remains:** a *totally blank* device can never
bootstrap on an *arbitrary* network — something pre-agreed (default
credential, client certificate, or dormant profile) must already exist,
because the voucher proves policy, not cryptographic identity. A voucher can
flip a gate instantly; it cannot conjure the shared secret from nothing. For
emergencies this means the receiving infrastructure must pre-honor the
voucher system — Norway's Nødnett 5G test slices (Nkom/Telenor/Telia/Lyse,
2026 agreements) are the plausible future home for exactly this pattern.

## 10. Future research: NR7101 compatibility + open-source landscape (2026-09-27)

### Would voucher/SNPN-style bootstrapping ever work on OUR NR7101?

**Verdict: no for certificate/SIM-less onboarding; yes for the dormant-USIM
voucher pattern — the NR7101 always needs a USIM.**

Why (hardware facts):
- NR7101's modem = Quectel RG502Q-EA: **3GPP Rel-15**. SNPN onboarding,
  EAP-TLS/EAP-TTLS NAS auth, anonymous SUCI for certs, Credentials Holder —
  all **Rel-17** UE features. A Rel-15 module cannot speak them, ever.
- The entire cellular auth stack (NAS, AKA, EAP) runs inside the modem
  firmware; OpenWrt only shuttles IP (qmi_wwan) and AT commands. There is no
  AT command to load a client certificate for NAS primary authentication.
- What the RG502Q-EA DOES support: 5G SA + NSA (Options 2, 3x/3a) with
  UICC-based 5G-AKA / EAP-AKA'. That is enough to attach to a private SA
  network of our own — with a USIM.

How the NR7101 still fits the research (dormant-credential voucher pattern):
1. Obtain a **programmable test USIM** (e.g., sysmocom sysmoISIM — we get
   IMSI/Ki/OPc in the clear) and seat it in the NR7101.
2. Write the same credentials into OUR core (srsRAN `user_db.csv` or
   open5GS subscriber DB).
3. Voucher/ecash redemption = provisioning webhook inserts/flips the
   subscriber record; the seated USIM is the pre-staged trust.
4. Optional real-RF stage: SDR eNB on a supported band + modem band lock,
   low power, shielded enclosure only (licensed spectrum).
5. Future hardware note: Rel-17+ modules advertising SNPN/onboarding would
   enable true certificate attach; revisit module specs then.

### Open-source landscape (verified 2026-09-27)

| Project | What it gives us |
|---|---|
| `aligungr/UERANSIM` | 5G-SA UE + gNB simulator, NR radio over UDP (no SDR), software USIM |
| `open5gs/open5gs` | EPC/5GC core (5G-AKA, EAP-AKA'); docs rich; v2.7.5 baseline in papers |
| `free5gc/free5gc` | 5GC core, webconsole subscriber mgmt (5G-AKA, EAP-AKA') |
| `CriXson/Open5GS-EAP-TLS` | Thesis fork: EAP-TLS in Open5GS via N3IWF (non-3GPP), prototype-grade |
| NYCU free5GC+UERANSIM EAP-TLS patch (Cheng/Tang/Liu/Li 2025-26 paper) | Non-SIM devices attach over NAS w/ mutual TLS, ~11% latency overhead; code release status to verify when building |
| REBICTE 2025 (vamsi krishna) | EAP-AKA' added to Open5GS for SNPN/IIoT; EAP-TLS/TTLS flagged as next |
| `netlabufjf/wd-2025-pcaps` | PCAP archive: 5G-AKA + EAP-AKA', 3GPP + non-3GPP (TNGFUE) — study material |
| `srsRAN/srsRAN_Project` + srsRAN 4G | eNB/gNB/UE; ZMQ virtual radios (no SDR, no spectrum); srsUE virtual USIM; COTS-UE app note shows `user_db.csv` HSS model |

OpenWrt's role: none in cellular auth (modem-internal), but the OpenWrt
router is the natural host for glue (voucher webhook, qmicli/uqmi/AT control,
captive UX) — and ai-legion/ai-legion-small can host the whole software rig.

### Suggested exploration roadmap (when we pick this up)

1. **Software loop (no RF)**: srsRAN-4G ZMQ (or UERANSIM+free5GC) on
   ai-legion; software/virtual USIM; ecash-voucher webhook inserts
   subscriber; watch attach/detach end-to-end. 1-2 evenings.
2. **Real device, dormant credential**: sysmocom test USIM into the NR7101;
   credentials mirrored in our core; voucher flips HSS record. Same loop,
   real hardware, still no RF (needs the SDR stage for the air interface).
3. **RF stage (shielded)**: SDR eNB, band-locked modem, enclosure.
4. **Certificate track**: study/port the free5GC EAP-TLS patch; UERANSIM as
   the non-SIM UE. This is the true "no USIM" research line — software UEs
   only until Rel-17 hardware exists on the bench.

## Follow-up issues (filed 2026-09-27)

- #17 NR7101 as remote SIM programming terminal (pySim over AT+CSIM)
- #18 lpac without PCSCD: silent.link provisioning through the NR7101
- #19 Voucher research: 4-stage roadmap execution
- #20 Lab collaboration shortlist (Berlin/Oslo)
- #21 pcscd IFD driver: NR7101 as a general PC/SC reader (supersedes the
  per-tool adapters in #17/#18 — stock lpac/pySim/OpenSC against the modem slot)
