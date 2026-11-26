# NR7101 preflight evidence checklist

This is an evidence checklist, not permission to flash or a record of a completed test.
Keep specimen identities, host addresses, keys and raw evidence in a private operator record.
No permanent flash boot or eSIM test is claimed by this document.

## Identity and isolation

- [ ] Match the exact device to the private specimen record using physical identity and live observations; firmware-reported model alone is insufficient.
- [ ] Verify the exact host interface, its physical path to the device, and isolation from other devices; preserve the host's working uplink.
- [ ] Record administrative state separately from physical connectivity: admin-DOWN does not mean unplugged.
- [ ] Treat initramfs settings as volatile; their presence does not prove persistence after flash or reboot.

## NAND and recovery evidence

- [ ] Capture the live partition map and NAND geometry, including page, eraseblock and OOB sizes; resolve partitions by name, not remembered numbers.
- [ ] Back up Factory twice with ECC enabled and padbad handling; retain read status, sizes and SHA-256 hashes and compare both captures.
- [ ] Retain a separate rawOOB capture with its exact tool/options, geometry, read status and SHA-256 hash; distinguish its layout from ECC-corrected data.
- [ ] Record bad-block and ECC warnings without hiding failures; successful reads or matching hashes are not restore proof.
- [ ] Account for Kernel/ubi overlap in the partition map; do not treat overlapping ranges as independent restore targets.
- [ ] Document the recovery path and its verified versus untested steps before authorizing any write; backups alone do not demonstrate recovery.

## Firmware and configuration artifacts

- [ ] Verify the firmware against a signed manifest using a trusted signing key; record image identity, hash and verification result privately.
- [ ] Record the exact image and `sysupgrade -T` result; manifest verification and image acceptance do not prove an actual flash or successful boot. Never force an upgrade.
- [ ] Inspect configuration archive syntax, expected key material and file modes without publishing secrets; archive checks do not prove installation or boot-time behavior.
- [ ] Require separate post-flash boot and persistence evidence before claiming permanent boot success.

## eSIM state and result reporting

- [ ] Preserve the private eSIM profile map before and after any authorized eSIM operation, including profile identity and enabled/disabled state.
- [ ] Treat even free profile downloads and profile deletions as mutations, not read-only tests; require explicit authorization and a recovery plan.
- [ ] Keep verified, failed and untested results separate; attach timestamps, method and private evidence references to each actual observation.
- [ ] Mark absent permanent-boot or eSIM execution evidence as untested, not passed; do not infer it from preflight artifacts.
