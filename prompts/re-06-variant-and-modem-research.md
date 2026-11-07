# RE prompt 06 — vendor-variant and periphery research (modem, voice, variant enablement)

Use when the router is a two-SoC product (host SoC + cellular modem
module) or when features differ between carrier variants of the same
model. The MF286D session that produced this prompt answered "how do the
phone lines work and can OpenWrt drive them" without opening the case.

Read [CONTEXT-footguns.md](CONTEXT-footguns.md) rule 19 (version strings lie) and [CONTEXT-re-methods.md](CONTEXT-re-methods.md) first.

## Map the second computer first

A cellular router is usually two Linux systems back-to-back. Before
researching any feature, establish which side owns it:

- extract BOTH rootfs images (host + modem — modem images often hide
  inside the vendor's factory/repair kit as FOTA_FS tarballs or
  partition-image tgz files);
- grep both for the feature's keywords (voice: slic, alsa, auxpcm,
  voice, dial);
- check the host device trees (stock FIT carries the reference DTBs; the
  running system exposes /proc/device-tree) — but remember vendor drivers
  often attach with hardcoded platform data, so absence from DT is not
  absence from hardware.

## Let the scripts name the stack

Vendor init scripts are catalogs of the stack: one `voice.sh` listed the
full driver chain (SLIC + TDM + codec modules), the daemons, the nvram
gate (`voice_work_type`), and — by *which files were missing from which
carrier image* — the fact that feature binaries ship per-variant. A
modem-side `slic_up.sh` then revealed the true owner: the modem's ALSA
card, its PCM device numbers, and the sysfs control interface.

## Identify the control plane

One strings-pass over the feature daemon named the exact protocol (QMI
VOICE v2 over libqmi_cci). That single fact converts "mystery feature"
into "standard interface OpenWrt already speaks" — or shows you what
would need writing. Do this before any hardware probing.

## Variant comparison

Same model, different carrier = a natural A/B experiment set:

- collect at least two variants' images (community mirrors, the vendor's
  per-carrier update packages);
- diff the binary lists — the delta IS the feature enablement list;
- check which side gates the feature (host nvram key vs modem firmware
  capability) — that determines whether an OpenWrt port needs drivers,
  config bridging, or just a different modem image.

## Probing etiquette on live units

Read-only identity commands first (ATI, CPIN?, COPS?); never dial, never
send SMS, never touch modem firmware on the only unit. Record the AT
command surface you observed (CLAC often unsupported on vendor builds —
absence is a finding, not a dead end).

## Deliverable

An architecture diagram (which SoC owns what), the control-plane
protocol, the variant matrix, and an honest feasibility verdict with the
smallest experiment that would prove it.
