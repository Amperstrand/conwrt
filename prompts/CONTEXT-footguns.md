# Bench & RE footguns — context file

Read this before any bench session on embedded targets. Every entry below
cost us real time; most cost hours. Entries are generic (no vendor
detail); session references live in the private research repos.

## Network / bench infrastructure

1. **Host firewall default-deny masks itself.** A service tested from the
   bench host itself takes the loopback path and works; the device's
   inbound packets are silently dropped by ufw/nftables INPUT policy.
   Always test the serve path from an external source (or the device)
   before a flash window.
2. **Never alias the bench's own IP inside the client subnet.** A local
   address (e.g. a secondary `192.0.0.2/8`) captures replies-to-client and
   delivers them to loopback — the client starves while everything looks
   "up" locally.
3. **One IP per subnet.** The same IP on a bridge *and* its port gives
   ambiguous routes and dueling ARP answers.
4. **Short frames (runts).** Some bridge stacks emit ARP replies below
   Ethernet minimum; embedded MACs may drop them silently. Symptom:
   client's requests arrive, client never completes resolution. Fix:
   inject padded (60-byte) replies yourself on the physical port.
5. **Anti-bot WAFs fingerprint TLS stacks.** python-requests gets 405'd
   where curl passes; some vendor endpoints additionally require a
   mobile-network source IP. Routing through the router's own LTE uplink
   (SSH SOCKS proxy) satisfies both and is the authentic path.
6. **Vendor DNS leftovers.** Old capture setups leave `/etc/hosts`
   entries redirecting vendor domains to localhost — "connection
   refused" to a service that should be reachable. Check before
   debugging the service.
7. **scp to dropbear needs `-O`** (legacy SCP protocol; no sftp-server
   on the target).

## Timing & boot behavior

8. **Cold-boot recovery windows can open minutes after power-on.**
   Bootloader update-path timeout ladders run first. A watcher that gives
   up after 1–2 minutes misreads a live device as dead. Watch ≥10 minutes
   before concluding anything.
9. **Recovery clients may derive a fresh identity per boot** (IP and MAC
   from sprintf builders). Never hardcode `192.0.0.2`-style addresses in
   allowlists or static ARP; match the subnet or MAC pattern.
10. **Warm reset ≠ cold boot.** Different components re-init, and
    recovery paths can differ between them. Record which one you did.

## Live-device safety

11. **Embedded web servers are often single-threaded.** A payload that
    blocks (unbounded ping, bare `sh` on stdin, any command that never
    exits) freezes the whole UI while the device still answers ICMP.
    Every payload ends in `&` or is internally bounded.
12. **Form responses are not exit-code oracles.** Many handlers reply
    `success` unconditionally once past validation. Establish observable
    channels (ICMP, HTTP callback, config-readback) before capability
    claims.
13. **Checksum-first downloads.** Official images truncate silently over
    flaky links (one sysupgrade image arrived at exactly 6 MiB, short).
    Verify sha256 against the manifest on the bench AND on the device
    before writing.
14. **The PoE/link-state trap.** Link "up" on the bench NIC proves the
    bench↔injector path only; device power state needs its own evidence
    (carrier-change counters, LED reports, ARP).

## Session hygiene

15. **tmpfs purges mid-session are real.** Consolidate irreplaceable
    artifacts to non-tmpfs in the first 15 minutes; keep the location in
    the worklog.
16. **Known-plaintext pairs are gold — track them explicitly** (which
    source/target/delta triples you own). Also: state *where* you
    searched when reporting "bytes not found" (which decode layer, which
    offsets) — layer confusion produces false negatives.
17. **Vendor code beats black-box guessing.** The product ships the
    decoder for every format it consumes (bootloader update engines,
    update daemons). Anchor-string disasm converges faster than codec
    guessing.
18. **Community dumps answer species questions, never unit questions.**
    Record provenance and generation for every dump; component matrices
    can differ between units of the same model (field updates touch only
    some partitions).
19. **Version strings lie.** A single firmware label can hide a hybrid
    component matrix (rootfs tag ≠ web partition ≠ modem version).
    Trust partition contents.
20. **Two-repo discipline from the first commit**: private gets payloads,
    addresses, unit identifiers, per-version attack surfaces; public
    gets species procedures and methodology. Redaction later is much
    more expensive than separation now.
