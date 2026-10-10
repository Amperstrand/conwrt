# Raspberry Pi — species-level model

Conwrt started as a router flashing framework. This directory extends it to
single-board computers, starting with the Raspberry Pi 4 family. The goal:
**detect, rescue, provision, and manage Pis over the network** — whether they
run Ubuntu Server, Raspberry Pi OS, or OpenWrt.

- Model definition: `models/raspberrypi-4b.json` (authoritative boot/netboot facts)
- Tooling: `scripts/pi_netboot.py`, `scripts/pi_image.py`, `scripts/pi_eeprom.py`
- Playbooks in this directory:
  - [`netboot-rescue.md`](netboot-rescue.md) — recover a netboot-looping Pi headlessly
  - [`ubuntu-server-provisioning.md`](ubuntu-server-provisioning.md) — Ubuntu Server onto a Pi-attached disk
  - [`eeprom-and-security.md`](eeprom-and-security.md) — BOOT_ORDER policy, the arm/disarm switch, secure-boot outlook, labgrid outlook

Everything here was validated on a Pi 4 4GB over a home VLAN with an OpenWrt
router as the dnsmasq/TFTP host (2026-10-08). Species-level facts only — put
unit MACs/serials/topology in your private inventory, never in git (see
`AGENTS.md`).
