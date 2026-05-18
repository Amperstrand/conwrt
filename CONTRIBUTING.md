# Contributing

conwrt controls real OpenWrt routers. Development and CI must stay hardware-safe by default.

## Safe local workflow

```bash
python -m pip install -e '.[dev]'
make ci
```

`make ci` runs linting, static type checks, model validation, unit tests, and the existing local smoke test. It must not require router hardware, root privileges, SSH access, TFTP, tcpdump, serial devices, ASU access, or firmware flashing.

## Hardware-mutating commands

Do not run flash, sysupgrade, SSH, SCP, TFTP, tcpdump, serial, ASU, or other network-mutating commands from automated tests. Use mocks/stubs and local fixtures instead.

## Adding or changing models

- Add or update `models/*.json` and validate with `make validate-models`.
- Include evidence in `tested_hardware` only for hardware that was actually tested.
- Do not commit specimen-specific serial numbers, MAC addresses, captures, private keys, inventory, firmware images, or `config.toml`.
- Mark experimental capabilities clearly rather than deleting notes.

## Pull requests

- Keep changes small and reviewable.
- Add tests for current behavior before changing uncertain behavior.
- Document whether changes were validated with mocks only or with real hardware.
