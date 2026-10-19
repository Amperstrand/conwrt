#!/usr/bin/env python3
"""Build and push Raspberry Pi EEPROM update packages (bootloader config changes).

The Pi 4/5 bootloader (EEPROM) controls the boot device order via BOOT_ORDER.
conwrt uses this to give lab Pis a "network boot first, fall back to USB disk"
policy: the netboot rescue server becomes a remote management switch, and the
OS lives on a USB/SD medium.

EEPROM updates can be delivered WITHOUT touching the Pi:
- over the network: place recovery.bin + pieeprom.upd + pieeprom.sig in the
  netboot (TFTP) root; the bootloader applies them on the next boot, or
- on-device: `sudo rpi-eeprom-config --edit` from a booted OS, or
- via SD-card recovery image.

This tool builds the update package (pieeprom.upd + pieeprom.sig) from the
official EEPROM image plus a small config overlay, and verifies the signature
file the same way the bootloader does (sha256 first line, `ts:` second line).

Secure boot (SIGNED_BOOT / FLASH-LOCKED OTP keys) is intentionally NOT handled
here — see recipes/raspberry-pi/eeprom-and-security.md for the outlook.

Usage:
    pi_eeprom.py decode --order 0xf142
    pi_eeprom.py encode --modes network usb sd
    pi_eeprom.py build --boot-order 0xf142 --out data/cache/pi-eeprom \
                       [--pieeprom PATH] [--recovery PATH] [--set KEY=VALUE ...]
    pi_eeprom.py push   --router 192.168.1.1 --tftp-root <dir> --package-dir DIR
"""

from __future__ import annotations

import argparse
import hashlib
import shutil
import sys
import time
import urllib.request
from pathlib import Path

DEFAULT_BASE = ("https://raw.githubusercontent.com/raspberrypi/rpi-eeprom/"
                "master/firmware-2711/default")
DEFAULT_PIEEPROM = "pieeprom-2026-09-23.bin"

BOOT_MODES: dict[str, int] = {
    "sd": 0x1,
    "network": 0x2,
    "rpiboot": 0x3,
    "usb": 0x4,
    "bcm-usb-msd": 0x5,
    "nvme": 0x6,
    "http": 0x7,
    "stop": 0xE,
    "restart": 0xF,
}
MODE_NAMES = {v: k for k, v in BOOT_MODES.items()}


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable)
# ---------------------------------------------------------------------------

def decode_boot_order(value: str | int) -> list[str]:
    """Decode BOOT_ORDER into boot modes, tried from first to last.

    The bootloader reads nibbles from least-significant to most-significant,
    so 0xf142 means: network (2), usb (4), sd (1), restart (f).
    """
    text = format(value, "x") if isinstance(value, int) else value.lower()
    text = text.removeprefix("0x")
    if not text:
        raise ValueError("empty BOOT_ORDER")
    modes: list[str] = []
    for ch in reversed(text):
        num = int(ch, 16)
        name = MODE_NAMES.get(num)
        if name is None:
            raise ValueError(f"unknown boot mode nibble: 0x{ch} (in {text})")
        modes.append(name)
    return modes


def encode_boot_order(modes: list[str]) -> str:
    """Encode boot modes (first tried first) into a BOOT_ORDER hex string.

    A trailing 'restart' is appended automatically if not present, matching
    the upstream convention (e.g. ['network','usb','sd'] -> 0xf142).
    """
    for mode in modes:
        if mode not in BOOT_MODES:
            raise ValueError(f"unknown boot mode: {mode}")
    seq = list(modes)
    if not seq or seq[-1] != "restart":
        seq = seq + ["restart"]
    nibbles = "".join(format(BOOT_MODES[m], "x") for m in reversed(seq))
    return f"0x{nibbles}"


def render_boot_conf(settings: dict[str, str]) -> str:
    lines = ["[all]"]
    lines += [f"{key}={value}" for key, value in settings.items()]
    return "\n".join(lines) + "\n"


def make_sig(data: bytes, ts: int | None = None) -> bytes:
    """Generate bootloader .sig content: sha256 line + ts line.

    This matches the format produced by upstream rpi-eeprom-digest and
    validated by recovery.bin / the bootloader.
    """
    digest = hashlib.sha256(data).hexdigest()
    timestamp = int(time.time()) if ts is None else ts
    return f"{digest}\nts: {timestamp}\n".encode()


def verify_sig(data: bytes, sig: bytes) -> bool:
    first_line = sig.splitlines()[0].decode().strip() if sig else ""
    return first_line == hashlib.sha256(data).hexdigest()


def parse_boot_order_arg(value: str) -> list[str]:
    """Accept either hex (0xf142) or space-separated mode names (network usb sd)."""
    cleaned = value.lower().strip()
    if set(cleaned.removeprefix("0x")) <= set("0123456789abcdef"):
        return decode_boot_order(cleaned)
    return [m.strip() for m in cleaned.split() if m.strip()]


# ---------------------------------------------------------------------------
# I/O helpers
# ---------------------------------------------------------------------------

def fetch(url: str, dest: Path) -> Path:
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"fetching {url}")
    with urllib.request.urlopen(url, timeout=120) as resp, \
            dest.open("wb") as fh:
        while chunk := resp.read(1 << 16):
            fh.write(chunk)
    return dest


def resolve_pieeprom(pieeprom_arg: str | None, out_dir: Path) -> Path:
    """Local path is used in place; URLs/default are fetched into the cache."""
    if pieeprom_arg and not pieeprom_arg.startswith("http"):
        local = Path(pieeprom_arg).expanduser()
        if not local.is_file():
            raise SystemExit(f"pieeprom image not found: {local}")
        return local
    return fetch(pieeprom_arg or f"{DEFAULT_BASE}/{DEFAULT_PIEEPROM}",
                 out_dir / DEFAULT_PIEEPROM)


def resolve_recovery(recovery_arg: str | None, out_dir: Path) -> Path:
    """recovery.bin must END UP in the package: copy local, fetch URL/default."""
    if recovery_arg and not recovery_arg.startswith("http"):
        local = Path(recovery_arg).expanduser()
        if not local.is_file():
            raise SystemExit(f"recovery image not found: {local}")
        dest = out_dir / "recovery.bin"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(local, dest)
        return dest
    return fetch(recovery_arg or f"{DEFAULT_BASE}/recovery.bin",
                 out_dir / "recovery.bin")


def find_tool(out_dir: Path, name: str) -> Path:
    """Locate an upstream helper script (rpi-eeprom-config), download if needed."""
    local = Path(__file__).resolve().parent.parent / "scripts" / name
    if local.is_file():
        return local
    cached = out_dir / name
    if cached.is_file():
        return cached
    return fetch(f"https://raw.githubusercontent.com/raspberrypi/rpi-eeprom/"
                 f"master/{name}", cached)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_decode(args: argparse.Namespace) -> int:
    modes = decode_boot_order(args.order)
    print(" -> ".join(modes))
    return 0


def cmd_encode(args: argparse.Namespace) -> int:
    print(encode_boot_order(args.modes))
    return 0


def cmd_build(args: argparse.Namespace) -> int:
    out_dir = Path(args.out).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    modes = parse_boot_order_arg(args.boot_order)
    settings = {kv: v for kv, v in (s.split("=", 1) for s in (args.set or []))}
    settings["BOOT_ORDER"] = encode_boot_order(modes)
    if args.boot_uart:
        settings["BOOT_UART"] = "1"

    pieeprom = resolve_pieeprom(args.pieeprom, out_dir)
    recovery = resolve_recovery(args.recovery, out_dir)

    boot_conf = out_dir / "boot.conf"
    boot_conf.write_text(render_boot_conf(settings))

    tool = find_tool(out_dir, "rpi-eeprom-config")
    upd = out_dir / "pieeprom.upd"
    import subprocess
    proc = subprocess.run(
        [sys.executable, str(tool), "--config", str(boot_conf),
         "--out", str(upd), str(pieeprom)],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0 or not upd.is_file():
        print(proc.stdout + proc.stderr, file=sys.stderr)
        raise SystemExit("rpi-eeprom-config failed")

    sig = out_dir / "pieeprom.sig"
    sig.write_bytes(make_sig(upd.read_bytes()))
    if not verify_sig(upd.read_bytes(), sig.read_bytes()):
        raise SystemExit("internal error: sig verification failed")

    print(f"package ready in {out_dir}:")
    for name in ("recovery.bin", "pieeprom.upd", "pieeprom.sig"):
        f = out_dir / name
        print(f"  {name:14} {f.stat().st_size:>8} bytes")
    print(f"boot order : {' -> '.join(modes)}")
    print(f"settings   : {settings}")
    return 0


def cmd_push(args: argparse.Namespace) -> int:
    import subprocess
    pkg = Path(args.package_dir)
    missing = [n for n in ("recovery.bin", "pieeprom.upd", "pieeprom.sig")
               if not (pkg / n).is_file()]
    if missing:
        raise SystemExit(f"missing files in {pkg}: {missing}")
    proc = subprocess.run(
        ["scp", "-O", "-o", "BatchMode=yes",
         str(pkg / "recovery.bin"), str(pkg / "pieeprom.upd"),
         str(pkg / "pieeprom.sig"),
         f"root@{args.router}:{args.tftp_root}/"],
        capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return 1
    print(f"EEPROM update staged on {args.router}:{args.tftp_root} — "
          f"power-cycle the Pi to apply")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("decode", help="BOOT_ORDER hex -> boot mode list")
    sp.add_argument("--order", required=True)
    sp.set_defaults(func=cmd_decode)

    sp = sub.add_parser("encode", help="boot mode list -> BOOT_ORDER hex")
    sp.add_argument("--modes", nargs="+", required=True,
                    help="e.g. network usb sd")
    sp.set_defaults(func=cmd_encode)

    sp = sub.add_parser("build", help="build recovery.bin+pieeprom.upd+sig package")
    sp.add_argument("--boot-order", required=True,
                    help="hex (0xf142) or let --modes style list; see decode")
    sp.add_argument("--set", action="append", default=[],
                    help="extra EEPROM settings, KEY=VALUE (repeatable)")
    sp.add_argument("--boot-uart", action="store_true",
                    help="enable bootloader UART output")
    sp.add_argument("--pieeprom", default=None,
                    help="local path or URL (default: upstream default image)")
    sp.add_argument("--recovery", default=None,
                    help="local path or URL for recovery.bin")
    sp.add_argument("--out", required=True, help="output package directory")
    sp.set_defaults(func=cmd_build)

    sp = sub.add_parser("push", help="stage a built package on a router TFTP root")
    sp.add_argument("--router", required=True)
    sp.add_argument("--tftp-root", required=True)
    sp.add_argument("--package-dir", required=True)
    sp.set_defaults(func=cmd_push)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
