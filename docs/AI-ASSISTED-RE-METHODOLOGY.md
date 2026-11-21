# AI-Assisted Hardware Reverse Engineering: The MF286D Campaign Methodology

How we used coordinated AI agents, Ghidra, and structured prompts to crack
an eSIM management problem in 48 hours that the community had declared
impossible. This document is for anyone who wants to replicate the approach
on other locked devices.

## The setup: multi-agent research

We used [Herdr](https://github.com/user/herdr) (a terminal multiplexer for
AI agents) to run multiple coordinated OpenCode sessions simultaneously:

- **Device lane** (me): SSH access to the router, hardware interaction,
  backup/recovery orchestration. The ONLY agent touching the device.
- **RE lane**: firmware analysis, Ghidra work, protocol RE. Software-only.
- **Research lane**: web search, community archaeology, tooling discovery.
  Software-only.

The key discipline: **one owner per surface**. The device lane is the only
agent that SSHes to the router or touches hardware. This prevents port
contention (two agents reading the same serial port = garbage data for both)
and ensures every state-changing operation has one accountable agent.

Coordination via Herdr's agent-to-agent messaging:
```
herdr agent prompt <pane_id> "message" --wait --timeout 120000
```

## The prompt patterns that worked

### 1. Continuation prompts (the "pick up where I left off" pattern)

Every research thread got a continuation prompt — a self-contained document
that a FRESH session (or a human) could execute without any prior context.

Example structure:
```markdown
# MF286D B14 rootfs diff — continuation research kit

## State of knowledge (all verified on artifacts)
- The B14 .up package is acquired and unpacked...
- modem.mld = 163-file per-file delta...
- system.mld touches the data-path stack...

## Hypotheses (ranked)
- H2 — firmware data-path stack change (STRONG)...
- H3 — carrier-policy change via MCFG (MODERATE)...

## Experiments (each: how, expected outcome, cost)
1. E1 dsi_config.xml diff — extract, diff, expect H2 changes...
```

Why this matters: AI sessions die, context windows fill up, operators step
away. The continuation prompt is the **durable knowledge artifact** — the
next session (or a human collaborator) picks up warm, not cold.

### 2. Oracle prompts (the "design an experiment, not a solution" pattern)

When a theory needed testing, the prompt asked for an EXPERIMENT DESIGN,
not a fix:

```markdown
OPERATOR REFRAME: goal is NOT to solve B14 — it is to hand a future
agent a complete research kit. Your FINDINGS.md becomes the HANDOFF
DOCUMENT with this exact structure: (1) STATE, (2) ARTIFACTS,
(3) HYPOTHESES ranked, (4) EXPERIMENTS, (5) BLOCKERS,
(6) NEXT-AGENT CONTINUATION PROMPT.
```

This prevented the common AI failure mode of confidently proposing a
"fix" without evidence. Instead, every claim had to point to an artifact.

### 3. Safety-gate prompts (the "fail-closed checklist" pattern)

Before any device operation:
```markdown
SAFETY: read-only probe only. Do NOT write to flash/EFS/NV.
Do NOT reboot. If any operation could change state, STOP and report.
```

For flash operations:
```markdown
Preconditions (all must be true before proceeding):
- [ ] SSH access verified
- [ ] Full backup exists with sha256
- [ ] Trigger image verified (sha256 match)
- [ ] Fence armed and reachable
- [ ] Firewall rule for UDP 69 confirmed
- [ ] Recovery path documented
```

## The Ghidra workflow

### What we analyzed
- 58MB reassembled Hexagon baseband image (MDM9650)
- The modem's Qshrink debug database (250K entries with file:line:string)

### The process
1. **Ghidra 12.2 with native Hexagon plugin** on ai-legion-small
2. Headless analysis: `analyzeHeadless /path/to/project -import image.bin -processor Hexagon`
3. The Qshrink DB was the breakthrough: decompressed with zlib (found the
   magic at offset 0x40), yielding 250,312 log entries that map every
   function call to its source file and line number
4. We used the Qshrink strings as a **symbol table** — searching for known
   API names (like `qmi_uim_m2m_euicc.c`) to locate the relevant code
5. Cross-referenced the Qshrink entries with the Ghidra disassembly to
   identify function addresses and decode struct layouts

### What the AI contributed
- **Pattern recognition**: scanning 6.5M lines of disassembly for specific
  struct initialization patterns (u16 LE, TLV layouts)
- **String analysis**: extracting and categorizing 91K function names from
  the disassembly
- **Hypothesis generation**: "the sizes suggest this is the LPA download
  handler" — then proposing targeted verification
- **Format reverse engineering**: cracking the ZFD delta codec by
  recognizing the LZMA magic bytes pattern in the compressed payloads

### What the human contributed
- Deciding WHICH questions to ask (the operator's "what about the managed
  LPA?" redirect was the campaign's turning point)
- Safety judgment (when to stop, when to try a different angle)
- Community context (knowing that eko.one.pl had already mapped the
  hardware quirks)

## The evidence-first methodology

Every claim pointed to an artifact:
- Firmware analysis → the extracted binary + the disassembly
- Live probes → tcpdump captures + tool output files
- Recovery → the trigger image + the fence logs + the run record
- Lessons → the postmortem documents

Nothing was asserted without evidence. When theories died, they died
with named experiments (not "we think" but "proven by E4: zero behavioral
change after EFS write + reboot").

## Key lessons

1. **Diff against a reference beats theorizing** — three major questions
   fell to simple comparisons (B14 package, flash drift, volume diff)
2. **A tool's 'empty' is not 'absent'** — the bench switch wasn't wiped;
   the monitoring tool couldn't reach it and reported total drift
3. **Error codes are oracles** — INVALID_QMI_CMD vs MALFORMED_MSG as a
   presence/absence signal for proprietary QMI messages
4. **Capture the healthy baseline BEFORE you need it** — we spent hours
   diagnosing boot-log lines that turned out to be normal on every boot
5. **The firmware ships its own debug symbols** — the Qshrink database was
   sitting on the flash the entire time; nobody had looked
6. **Multi-agent works when each agent owns one surface** — the device
   lane SSHes, the RE lane disassembles, the research lane searches

## Tooling inventory (all open source)

| Tool | Purpose |
|---|---|
| OpenCode | AI coding/research agent |
| Herdr | Multi-agent terminal coordination |
| Ghidra 12.2 (+ Hexagon plugin) | Firmware disassembly |
| QCSuper | QMI/DM protocol client (Python) |
| qfenix | EFS management over DM (Linux) |
| zte-blankdl-flashd | TFTP flash fence (our hardened fork) |
| uim_bitmap | QMI UIM probe tool (our custom static ARM binary) |

## Conclusion

The problem wasn't impossible — it was just never attacked from the right
angle. The community tried raw APDU access (blocked by compiled Qualcomm
policy). We found the managed LPA interface (35 QMI messages externally
reachable). The methodology — coordinated AI agents + Ghidra + the Qshrink
DB + the oracle pattern — is replicable on any locked device with a
Qualcomm baseband.

We share this to invite collaboration. The remaining EID gate is a
client-state initialization sequence that the Hexagon disassembly can
answer. More eyes on that code = faster resolution.
