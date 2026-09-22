# Bench Forensics 02 — Session Archaeology (mining past agent sessions for device history)

The technique that cracked the lan7/lan8 case (2026-09-22): four months of
"network-dead" was disproven in minutes by finding the units' May-era IPs and
passwords in past coding-agent session transcripts. Use this whenever a
device's history matters and the repo's records (inventory, recipes) don't
answer it.

## Where device history hides

| Store | Location | Notes |
|---|---|---|
| Claude Code transcripts | `~/.claude/transcripts/*.jsonl` | flat, tens of thousands of files; the richest store on this bench |
| OpenCode sessions | `opencode` DB / `session` storage | current-project index may MISS months-old content that Claude transcripts contain |
| Session records | `data/sessions/*.md` in this repo | curated, but only as good as what was written down |
| Inventory | `data/inventory.jsonl` | specimen-level notes: past IPs, passwords, keys (grep IPv4s in notes) |
| Shell history | `~/.zsh_history`, `~/.bash_history` | IPs and ssh invocations |

## Query lanes (run them in parallel)

Search terms that discriminate best, in order of power:

1. **MAC addresses** — full form and suffix (`25:47:a2`, `25:86:bd`). Unique
   to one physical unit; appears in tool output (arp, tcpdump, neigh) that
   transcripts captured verbatim.
2. **Distinctive strings** — stock passwords (`new2day`), tool names
   (`rdwr_boot_cfg`), model strings (`ap3915i`).
3. **Old IPs / subnets** — every IPv4 ever associated with the bench
   (192.168.13.x, 192.168.1.x, 10.0.0.x).
4. **Config verbs near device terms** — `ipaddr`, `chown`, `authorized_keys`,
   `DROPBEAR_PASSWORD`.

```bash
# transcripts: MAC-suffix and distinctive-string lanes
rg -l "25:47:a2" ~/.claude/transcripts/
rg -l "new2day|rdwr_boot_cfg" ~/.claude/transcripts/

# then extract context around hits (line-delimited JSON: parse, don't raw-grep)
python3 - <<'EOF'
import json
p = "/Users/macbook/.claude/transcripts/<ses_id>.jsonl"
for i, line in enumerate(open(p)):
    if "25:47:a2" not in line:
        continue
    e = json.loads(line)
    c = e.get("content") or e.get("tool_output") or ""
    idx = str(c).find("25:47:a2")
    print(f"L{i} {e.get('timestamp','')[:19]} {e.get('type')}:", str(c)[max(0,idx-200):idx+300])
EOF
```

## Reading rules

- ARP/neigh table output in old tool results is the gold: `IP ↔ MAC`
  adjacency maps a unit to its historical addresses (watch for DHCP-era
  drift — the LAST sighting before the device went quiet is the one to try,
  but try them all).
- Credential history: grep for `passwd`, `DROPBEAR_PASSWORD`, "password"
  near the device MAC/model. Fleet password patterns (conwrt, Conwrt2026!,
  vendor defaults) belong in the `bench_discover.py` credential ladder.
- Distrust your memory of "what we did back then" — trust the transcript.
  The May bench being flat VLAN 1 on 192.168.13.0/24 was ONLY recoverable
  from the transcripts; every later summary got details wrong.
- Cross-check findings against live state before acting: an IP from May may
  be stale (DHCP era) — the recovery sweep tries them in order.

## Feeding the results forward

1. Append corrected specimen entries to `data/inventory.jsonl`
   (`python3 scripts/inventory.py add ...`) — future sessions start from
   these, not from re-mining.
2. Species-level lessons go into the model JSON `warnings` + recipes.
3. If a password/IP lineage is stable, add it to the ladder in
   `scripts/bench_discover.py` (`credential_ladder`) or the playbook.
