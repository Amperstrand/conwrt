# Recovery-flash runbook — D-Link COVR-X1860 (and similar) from the bench

Versioned operational checklist consolidating the 2026-10-14/15/16 sessions.
Built from the recorded evidence in #230, the trust-on-first-boot problem
statement (#228), and the authorized_keys/SSH-lockout findings (#229).
Flash-matrix rig details: PR #198; dual-port doctrine: PR #222.

**Scope**: recovery-flashing a D-Link unit (case-sealed, **no serial console**)
from the bench network. Every step exists because its absence cost a session —
cite the issue when in doubt.

**Coordination**: the uci-defaults fix for the SSH-lockout failure mode
(#229) is being worked separately; this runbook *detects and classifies* that
failure, it does not fix it.

---

## Phase 0 — Pre-flight (before touching the unit)

- [ ] **Image freshness vs key rotation**: the image must have been built
      after the last fleet key rotation. Verify the baked key:
      ```sh
      # extract the baked authorized_keys from the image (mount or unsquashfs),
      # then compare fingerprints:
      ssh-keygen -lf <baked-key-file>
      ssh-keygen -lf ~/.ssh/id_ed25519.pub   # current fleet key
      ```
      A stale image boots but is **completely inaccessible** — the June 2026
      image carried the decommissioned laptop's key: no SSH, no web, no
      telnet, password auth disabled, and no serial on the x1860 (#228).
- [ ] **Image sanity**: flash to a known-healthy unit first if uncertain, or
      use a cached verified image (one that has booted AND accepted SSH).
- [ ] **Egress address**: `192.168.0.10` on the correct seat SVI —
      **one VLAN at a time; NEVER flip the egress VLAN mid-upload**
      (mid-flight flips cause connection resets, see failure table).
- [ ] **Hop-1 tunnel**: x280 → ai-legion-small on `:8180` (self-healing in
      the fire script).
- [ ] **Hop-2 tunnel**: ai-legion-small → switch → recovery server on `:8180`
      (self-healing).
- [ ] **DHCP responder**: dnsmasq on the seat SVI, with a leasefile — needed
      by the boot watcher's DHCP path.
- [ ] **PCAP**: tcpdump on the seat VLAN for byte-delivery verification
      (start it BEFORE the flash; you cannot retroactively capture).
- [ ] **Boot watcher**: running on all three paths —
      static `192.168.1.1` + DHCP lease + pcap MAC.

## Phase 1 — Arming and flash (unit blinking red)

- [ ] **Detect arming by ARP only**: `ip neigh` for `192.168.0.1` — the
      soft MAC is `3e:85:be:87:55:42`.
- [ ] **NEVER GET the recovery page** — it is a one-request server; a curl
      or browser refresh burns it and the unit must be re-armed.
- [ ] **Fire Chromium headless (Playwright)** with a **LOCAL form** as the
      first (and only) request.
- [ ] **Verify upload**: HTTP 200 **and** pcap byte count == image size.
      HTTP 200 alone is not proof (see failure table).

## Phase 2 — Boot window (15–45 minutes — do NOT declare failure early)

- [ ] Dual-image first boot: kernel boots from main → copies main→backup →
      reboots → OpenWrt comes up. This alone can take 20+ minutes.
- [ ] Watch **all three paths** (static IP / DHCP lease / pcap MAC) for
      45+ minutes before concluding failure.
- [ ] On a healthy boot the order is: ARP appears with the real MAC →
      ICMP answers → SSH accepts.

## Phase 3 — Post-flash verification

- [ ] **SSH from a fleet-key host** (ai-legion-small), NOT from the switch —
      the switch has no fleet keys and its failure means nothing.
- [ ] **Authorized-key / lockout classification** (#228 / #229) — if SSH is
      rejected, classify before acting:
      ```sh
      ssh -v root@192.168.1.1
      ```
      1. Compare the *offered* key fingerprint (ssh -v) against the *baked*
         key fingerprint from Phase 0.
      - **Offered ≠ baked** → stale image (the #228 class): stop, rebuild the
        image with current keys, re-flash. No amount of waiting helps.
      - **Offered == baked and still `Permission denied (publickey)`** → the
         #229 class: the unit ARP+ICMP answers, the baked key material is
         correct, but uci-defaults did not apply (`authorized_keys` not
         written / dropbear not restarted with the new config). Do NOT
         re-flash blindly — record the evidence (ssh -v transcript, image
         build id) on #229 and coordinate with that lane. Serial console is
         the documented last resort — the x1860 is case-sealed, so in
         practice: re-flash with a diagnostic image (password auth ON, keys
         also baked) to recover the unit.
      2. Note whether the SSH host key looks like a fresh dropbear (it
         restarted with new config) or a stale one — diagnostic signal for
         #229's hypothesis 2.
- [ ] **Set the static seat IP + gateway** for the unit's bench seat.
- [ ] **Update the labgrid exporter + registry** (the unit's place must
      reflect the new management address before release).
- [ ] **Reconcile the pcap** against the expected byte count; archive the
      capture with the session log.

## Phase 4 — Rollback and failure handling

| Symptom | Cause | Fix |
|---|---|---|
| HTTP 200 + no boot | One-request server burned earlier, or transfer corruption | Check pcap byte count vs image size; re-arm and re-flash |
| ARP answers + no ICMP | Dual-image still copying main→backup | Wait 20+ minutes |
| Boots + SSH rejected, offered ≠ baked key | Stale image key (#228) | Rebuild image with current fleet keys; re-flash |
| Boots + SSH rejected, offered == baked key | uci-defaults did not apply keys (#229) | Record evidence on #229; diagnostic re-flash (password auth ON) to recover |
| Connection reset mid-upload | Egress address flipped VLAN mid-flight | Lock to one VLAN per flash; restart from Phase 0 |

**Re-Flash decision**: after any classified failure, re-enter at Phase 0 with
a fresh image check — do not reuse an image whose provenance the failure has
put in doubt.

**Unit recovery last resort** (no serial on x1860): a diagnostic image with
password auth enabled AND current keys baked — restores operator access for
reconfiguration; remove password auth once the unit is back under fleet-key
management.

---

## References

- #230 — this runbook's tracking issue (session evidence 2026-10-14/15/16)
- #228 — trust-on-first-boot problem; stale-image dead-key lockout
- #229 — uci-defaults authorized_keys failure (fix in-flight, separate lane)
- PR #198 (merged) — flash matrix + rig documentation
- PR #222 — dual-port doctrine
