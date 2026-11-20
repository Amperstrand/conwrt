# Pi probe fixtures

Inputs for `tests/test_pi_boot.py`: each file is the exact stdout shape the
`pi_boot.py probe` script emits (`@@section` blocks), so the parser can be
tested end-to-end without hardware.

**Provenance:** these are *shape* fixtures. They reproduce documented output
formats (`vcgencmd bootloader_version` / `bootloader_config`, `lsblk -P`,
`/proc/cmdline` on Raspberry Pi OS / Ubuntu, and a netboot initramfs with no
block root), not captures from a specific board. Serial numbers and PARTUUIDs
are invented. Do not cite them as hardware evidence — put captures from real
units under the run's evidence directory, not here.

Replaying a real dump is a supported workflow:

```bash
scripts/pi_boot.py probe --from-file /path/to/probe.txt
```
