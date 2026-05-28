# conwrt Agent Rules

Safety-critical rules for AI agents operating on real hardware.

## NEVER Force Sysupgrade

**`sysupgrade -F` is FORBIDDEN.** No exceptions.

The `-F` flag bypasses hardware validation and can brick devices by writing firmware for the wrong hardware. If sysupgrade rejects an image with "Device X not supported by this image", the image is wrong for the hardware. STOP.

Do NOT:
- Use `sysupgrade -F` or `--force`
- Override hardware validation checks
- Assume board.json is accurate (it reflects firmware, not hardware)

Instead:
- Investigate why the identity doesn't match
- Use `cat /tmp/sysinfo/board_name` to check device identity
- Download the correct firmware for the actual hardware
- If hardware identity is ambiguous, ask the operator before proceeding

## Always Identify Before Flashing

1. SSH to the device and read board.json AND `/tmp/sysinfo/board_name`
2. Cross-reference with the operator's claimed device model
3. If there's a mismatch, STOP and report it to the operator
4. Never assume the operator's claim is correct if the device says otherwise

## Trust Hardware Checks Over Firmware State

- `board.json` = what firmware was flashed (can be wrong)
- `/tmp/sysinfo/board_name` = firmware's device identity (can be wrong)
- `sysupgrade` validation = authoritative hardware check (trust this)
- Physical labels / MAC OUI = ground truth

When in doubt, trust sysupgrade's hardware validation. It is the last line of defense against bricking.

## Test Before You Commit (Post-Flash Configuration Safety)

**New features MUST be manually verified on a live device before being automated.**

Any shell script that modifies device state (uci set, network config, IP changes) must be tested end-to-end via SSH **before** being committed to automated flows (conwrt configure, ASU first-boot scripts, builder.py).

**Mandatory verification sequence for new configuration steps:**

1. **SSH manually first**: Run the exact shell commands on the device and verify the result
2. **Read back the value**: After `uci set`, run `uci get` to confirm the value was set correctly — not the literal variable name
3. **Test persistence**: Reboot and verify the change survives
4. **Verify recovery**: Confirm you know how to undo the change (firstboot, uci revert, failsafe)
5. **Then automate**: Only after steps 1-4 pass, commit the commands to the automation

**Why this matters**: A single-quote bug in `uci set network.lan.ipaddr='$_host'` wrote a literal string as the IP address, making the device unreachable. If this had been an ASU first-boot script baked into firmware, there would be NO recovery without serial. Always ensure changes are reversible before automating them.

**Specific rules:**
- Never `uci commit` a network IP change without verifying `uci get` returns the expected value first
- Shell variables in uci commands MUST use double quotes (not single quotes) for expansion
- On-device shell scripts use BusyBox tools only (`md5sum`, not `sha256sum`; no `chpasswd`, no `hostname`)
- Python-side hash algorithms MUST match what BusyBox provides (md5, not sha256)
- For UBIFS overlay devices: `uci commit` is permanent after reboot — there is no "undo" after reboot

## Related Projects

- **realtek-poe fork**: [Amperstrand/realtek-poe](https://github.com/Amperstrand/realtek-poe) — AI experimentation workspace for PoE research on OpenWrt switches. All AI work happens on the `ai-experiments` branch. `main` is a pristine upstream mirror. **Never interact with the upstream `Hurricos/realtek-poe` repo** — only humans may create issues or submit PRs there.
- **Test hardware**: Two GS1900-8HP A1 devices — one running OpenWrt (SSH), one running ZyXEL stock V2.90 (HTTP). Both accessible via USB ethernet.

## External Repository Etiquette

**Never contribute to, comment on, or file issues against repositories outside the Amperstrand organization.** This includes starring, fork-sync PRs, issue comments, and discussion posts. We reference external repos for research only — we don't want to spam maintainers.
