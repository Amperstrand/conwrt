# Ansible workflows

Ansible roles/workflows for post-flash configuration of OpenWrt routers.

These are **optional convenience wrappers** around conwrt's use-case presets —
the preset (e.g. `scripts/use_cases/openvpn_pia.py`) remains the source of truth.

## Design constraints

- **No Python on target.** Stock OpenWrt images rarely ship a Python interpreter,
  so roles here use `ansible.builtin.raw` for every remote action instead of the
  `command`/`shell`/`copy` modules. Use `gather_facts: false`.
- **No SFTP.** OpenWrt's dropbear has no `sftp-server`; the roles stream files
  with `raw` heredocs rather than the `copy`/`template` modules.
- **Reversible.** Configuration steps keep a known-good backup and are safe to
  re-run (idempotent `uci` operations and `while`-loop section cleanup).

## Roles

| Role | Purpose |
|------|---------|
| [`pia_openvpn`](roles/pia_openvpn/) | Private Internet Access (OpenVPN) full tunnel, phased fail-open → fail-closed, IPv6 off |

## Quick start

```bash
ansible-playbook -i inventory.ini ansible/playbooks/pia-openvpn.yml \
  -e pia_username=p1234567 -e @vault.yml
```

See [`docs/vpn-setup-library.md`](../docs/vpn-setup-library.md) for the
provider-agnostic credential/login-method model and roadmap.
