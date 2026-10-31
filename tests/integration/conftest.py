"""QEMU OpenWrt VM fixtures for integration testing.

Boots a real OpenWrt x86_64 VM in QEMU (with KVM if available) and provides
SSH access for conwrt configure + verification tests.

Requires: qemu-system-x86_64, losetup, mount
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from vm_port import port_from_env, require_free  # noqa: E402

VM_IMAGE = REPO_ROOT / "tests" / "integration" / ".openwrt.img"
# file-based consumers (tests/test_integration_image_gate.py loads this
# conftest via spec_from_file_location — no sys.path entry) resolve the
# pin by path, keeping the single-source contract for both import styles
import importlib.util as _ilu
from pathlib import Path as _Path

_pins_spec = _ilu.spec_from_file_location(
    "_pins", _Path(__file__).with_name("_pins.py")
)
_pins = _ilu.module_from_spec(_pins_spec)
_pins_spec.loader.exec_module(_pins)
IMAGE_URL, OPENWRT_VERSION = _pins.IMAGE_URL, _pins.OPENWRT_VERSION
PACKAGES_URL, PKG_MANAGER = _pins.PACKAGES_URL, _pins.PKG_MANAGER

VM_BASE = REPO_ROOT / "tests" / "integration" / ".openwrt-base.qcow2"
VM_OVERLAY = REPO_ROOT / "tests" / "integration" / ".openwrt-session.qcow2"
# #460: digest of the PREPPED image, recorded at creation time. Reuse
# requires this sidecar to exist AND match — a legacy .openwrt.img from
# the direct-boot era (accumulated mutations, no record) is untrusted
# and forces a from-scratch re-download + base rebuild.
# keyed by the REQUESTED release (Codex #608 P2): a digest-only cache
# would let a CONWRT_TEST_OPENWRT_VERSION override boot the previously
# cached image — the sidecar must miss when the release changes
DIGEST_SIDECAR = VM_IMAGE.with_name(
    VM_IMAGE.name + f".sha256-{OPENWRT_VERSION}"
)


def _image_digest() -> str:
    import hashlib

    h = hashlib.sha256()
    with VM_IMAGE.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _image_cache_valid() -> bool:
    if not VM_IMAGE.exists():
        return False
    if not DIGEST_SIDECAR.exists():
        return False
    return DIGEST_SIDECAR.read_text().strip() == _image_digest()
VM_PIDFILE = REPO_ROOT / "tests" / "integration" / ".openwrt-session-vm.pid"
SSH_PORT = port_from_env("CONWRT_VM_SESSION_PORT", 2222)
SSH_HOST = "127.0.0.1"
# Host UDP port forwarded to the guest's WireGuard listen port (51820) for
# the VM-as-server E2E test (tests/integration/test_wireguard_e2e.py).
# Best-effort: if the port is busy on this host (a real wireguard server or a
# sibling QEMU session), the forward is omitted and that test skips — boot
# behavior for every other test is unchanged.
WG_FWD_PORT = port_from_env("CONWRT_VM_WG_FWD_PORT", 51820)
SSH_KEY = REPO_ROOT / "tests" / "integration" / ".vm_ssh_key"
SERIAL_LOG = REPO_ROOT / "tests" / "integration" / ".serial.log"
PREBAKE_PACKAGES = ["sqm-scripts", "luci-app-sqm", "iperf3", "libiperf3", "libatomic1",
                    "wireguard-tools", "luci-proto-wireguard", "qrencode"]


def pytest_collection_modifyitems(config, items):
    """Auto-mark every test under tests/integration as `integration`.

    Lets `pytest tests -m "not integration"` run the fast unit tier without
    the QEMU-backed tests sneaking in on KVM-capable hosts (they only skip
    on machines without qemu — see _available checks below).

    Path-scoped: when the whole `tests` tree is collected in one session,
    this hook also receives items from outside tests/integration, and
    marking those would deselect the entire unit tier (verified: 3778
    deselected with pytest 7.4.4 before the guard).
    """
    integration_root = Path(__file__).resolve().parent
    for item in items:
        try:
            item_path = Path(str(item.path))
        except (AttributeError, TypeError):
            continue
        if integration_root in item_path.parents:
            item.add_marker(pytest.mark.integration)


def _available(cmd: str) -> bool:
    return subprocess.run(["which", cmd], capture_output=True).returncode == 0


def _ssh(command: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh",
         "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5",
         "-i", str(SSH_KEY),
         "-p", str(SSH_PORT),
         f"root@{SSH_HOST}", command],
        capture_output=True, text=True, timeout=timeout,
    )


def _prepare_image(image_path: Path) -> None:
    """Inject SSH key and configure eth0 as LAN DHCP so QEMU NAT can reach it.

    OpenWrt's default config puts eth0 in the WAN zone (firewall blocks SSH)
    and sets LAN to a static 192.168.1.1 bridge that QEMU user-mode NAT can't
    route to. We rewrite the network config so the single eth0 acts as LAN
    with DHCP (QEMU provides 10.0.2.15), and disable the firewall entirely
    so dropbear is reachable on port 22 via the hostfwd port forward.
    """
    # Prep is keyed on the image, not the SSH key: a version bump replaces
    # the image and must re-run injection even when the key pair persists
    # (a 24.10→25.12 bump silently skipped prep and left the VM's dropbear
    # behind the default WAN firewall — unreachable via hostfwd).
    stamp = image_path.with_name(image_path.name + f".prepped-{OPENWRT_VERSION}")
    if stamp.exists():
        return
    if not SSH_KEY.exists():
        subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(SSH_KEY)],
                       capture_output=True, check=True)
    pubkey = (SSH_KEY.with_suffix(".pub")).read_text().strip()

    r = subprocess.run(
        ["bash", "-c", f"""
        set -e
        LOOP=$(sudo losetup -fP --show {image_path})
        sudo mkdir -p /mnt/owrt
        sudo mount ${{LOOP}}p2 /mnt/owrt || sudo mount ${{LOOP}}p1 /mnt/owrt

        sudo mkdir -p /mnt/owrt/etc/dropbear
        echo '{pubkey}' | sudo tee -a /mnt/owrt/etc/dropbear/authorized_keys > /dev/null
        sudo chmod 600 /mnt/owrt/etc/dropbear/authorized_keys

        # Replace network config: eth0 as LAN with DHCP
        sudo tee /mnt/owrt/etc/config/network > /dev/null <<'NETCFG'
config interface 'loopback'
        option device 'lo'
        option proto 'static'
        option ipaddr '127.0.0.1'
        option netmask '255.0.0.0'

config interface 'lan'
        option device 'eth0'
        option proto 'dhcp'
NETCFG

        # Replace firewall: open zone accepting everything
        sudo tee /mnt/owrt/etc/config/firewall > /dev/null <<'FWCFG'
config defaults
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'

config zone
        option name 'lan'
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'
        option device 'eth0'

config zone
        option name 'wan'
        option input 'ACCEPT'
        option output 'ACCEPT'
        option forward 'ACCEPT'
        option masq '1'
        option mtu_fix '1'
FWCFG

        # Allow root login with password and keys in dropbear
        sudo tee /mnt/owrt/etc/config/dropbear > /dev/null <<'DROPBEAR'
config dropbear
        option PasswordAuth 'on'
        option RootPasswordAuth 'on'
        option Port '22'
        option Interface 'lan'
DROPBEAR

        sudo mkdir -p /mnt/owrt/etc/uci-defaults
        sudo tee /mnt/owrt/etc/uci-defaults/99-install-sqm > /dev/null <<'INSTALL'
#!/bin/sh
apk update >/dev/null 2>&1
apk add sqm-scripts luci-app-sqm >/dev/null 2>&1 || true
exit 0
INSTALL
        sudo chmod +x /mnt/owrt/etc/uci-defaults/99-install-sqm

        # Pre-bake: inject .apk files into image — QEMU guest can't reach apk repos
        sudo mkdir -p /mnt/owrt/tmp/prebake
        for pkg in {" ".join(PREBAKE_PACKAGES)}; do
            apk_file=$(ls /tmp/conwrt-prebake/$pkg*.apk 2>/dev/null | head -1)
            if [ -n "$apk_file" ]; then
                sudo cp "$apk_file" /mnt/owrt/tmp/prebake/
            fi
        done
        if sudo ls /mnt/owrt/tmp/prebake/*.apk >/dev/null 2>&1; then
            sudo tee /mnt/owrt/etc/uci-defaults/98-prebake-packages > /dev/null <<'PREBAKE'
#!/bin/sh
cd /tmp/prebake 2>/dev/null || exit 0
apk add --allow-untrusted ./*.apk >/dev/null 2>&1 || true
rm -rf /tmp/prebake
exit 0
PREBAKE
            sudo chmod +x /mnt/owrt/etc/uci-defaults/98-prebake-packages
        fi

        sudo umount /mnt/owrt
        sudo losetup -d $LOOP
        """],
        capture_output=True, text=True, timeout=60,
    )
    if r.returncode != 0:
        pytest.fail(f"Image preparation failed: {r.stderr}")
    stamp.touch()


def _download_prebake_packages() -> None:
    prebake_dir = Path("/tmp/conwrt-prebake")
    prebake_dir.mkdir(parents=True, exist_ok=True)
    if any(prebake_dir.glob("*.apk")):
        return
    print("Downloading pre-bake packages...", flush=True)
    listing = subprocess.run(
        ["curl", "-sfL", PACKAGES_URL + "/"],
        capture_output=True, text=True, timeout=30,
    )
    if listing.returncode != 0:
        print(f"  Warning: could not fetch package listing: {listing.stderr}")
        return
    import re
    available = set(re.findall(r'href="([^"]+\.apk)"', listing.stdout))
    for pkg in PREBAKE_PACKAGES:
        match = next((a for a in available if a.startswith(pkg + "_")), None)
        if not match:
            print(f"  Warning: {pkg} not found in package repo")
            continue
        subprocess.run(
            ["curl", "-sfL", "-o", str(prebake_dir / match), f"{PACKAGES_URL}/{match}"],
            capture_output=True, timeout=30,
        )
    print(f"  Pre-baked {len(list(prebake_dir.glob('*.ipk')))} packages", flush=True)


def _vm_layer_supported() -> bool:
    """README contract for the VM layers: Linux with KVM (/dev/kvm).

    qemu being installed (e.g. homebrew on macOS) is not enough — the image
    preparation path needs losetup/mount and the boot path assumes KVM.
    """
    return sys.platform.startswith("linux") and os.path.exists("/dev/kvm")


def _udp_port_free(port: int) -> bool:
    """True if the host can bind the UDP port (QEMU hostfwd binds 0.0.0.0)."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind(("0.0.0.0", port))
        except OSError:
            return False
        return True


@pytest.fixture(scope="session")
def openwrt_vm():
    if not _vm_layer_supported():
        pytest.skip("VM integration layer needs Linux with KVM (/dev/kvm) — run via `make integration`")
    if not _available("qemu-system-x86_64") or not _available("qemu-img"):
        pytest.skip("qemu-system-x86_64 / qemu-img not installed")

    if not _image_cache_valid():
        # #460: an invalid cache (missing sidecar = legacy direct-boot era
        # image with accumulated mutations; digest mismatch = corruption or
        # tampering) must not leak into the one-time base — purge ALL
        # derived state so nothing derived from the dirty image survives.
        for stale in (VM_IMAGE, VM_IMAGE.with_suffix(".img.gz"),
                      VM_IMAGE.with_name(VM_IMAGE.name + f".prepped-{OPENWRT_VERSION}"),
                      VM_BASE, DIGEST_SIDECAR):
            stale.unlink(missing_ok=True)
        print("Downloading OpenWrt x86_64 image...", flush=True)
        VM_IMAGE.parent.mkdir(parents=True, exist_ok=True)
        gz_path = VM_IMAGE.with_suffix(".img.gz")
        r = subprocess.run(
            ["curl", "-fL", "--retry", "3", "--retry-delay", "2",
             "-o", str(gz_path), IMAGE_URL],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            pytest.fail(f"curl download failed: {r.stderr}")
        # gunzip exit 2 = warning (e.g. "trailing garbage ignored"), not a real failure
        r = subprocess.run(["gunzip", "-f", str(gz_path)], capture_output=True, text=True)
        if r.returncode not in (0, 2) or not VM_IMAGE.exists():
            pytest.fail(f"gunzip failed (exit {r.returncode}): {r.stderr}")
        print(f"OpenWrt image ready: {VM_IMAGE} ({VM_IMAGE.stat().st_size} bytes)", flush=True)
        _download_prebake_packages()
        _prepare_image(VM_IMAGE)
        # recorded AFTER prep (prep mutates the image in place): this is
        # the digest the one-time base is built from (#460)
        DIGEST_SIDECAR.write_text(_image_digest() + "\n")

    kvm_args = ["-enable-kvm", "-cpu", "host"] if os.path.exists("/dev/kvm") else []

    # Pristine raw image → one-time qcow2 base → fresh per-session overlay.
    # The overlay (deleted at teardown) absorbs all mutations, so every session
    # boots a clean VM and the base is never dirtied (pattern proven in PRTA).
    if not VM_BASE.exists():
        print("Converting pristine image to qcow2 base (one-time)...", flush=True)
        r = subprocess.run(
            ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(VM_IMAGE), str(VM_BASE)],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            pytest.fail(f"qemu-img convert failed: {r.stderr}")
    if VM_OVERLAY.exists():
        VM_OVERLAY.unlink()
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(VM_BASE), str(VM_OVERLAY)],
        capture_output=True, text=True, timeout=30, check=True,
    )

    require_free(SSH_PORT, SSH_HOST, "CONWRT_VM_SESSION_PORT",
                 "session VM (QEMU OpenWrt integration fixture)")

    # Optional UDP forward for the WireGuard VM-as-server E2E test. Omitted
    # (never fatal — every other test boots exactly as before) when the host
    # port is taken.
    wg_fwd_port = WG_FWD_PORT if _udp_port_free(WG_FWD_PORT) else None
    if wg_fwd_port is None:
        print(f"  UDP {WG_FWD_PORT} busy — WireGuard hostfwd omitted "
              f"(test_wireguard_e2e vm-as-server test will skip)", flush=True)
    hostfwds = [f"tcp::{SSH_PORT}-:22"]
    if wg_fwd_port is not None:
        hostfwds.append(f"udp::{wg_fwd_port}-:51820")

    qemu_cmd = [
        "qemu-system-x86_64",
        "-drive", f"file={VM_OVERLAY},format=qcow2,if=virtio",
        "-m", "512M",
        "-netdev", "user,id=net0," + ",".join(f"hostfwd={h}" for h in hostfwds),
        "-device", "virtio-net-pci,netdev=net0",
        "-display", "none",
        "-serial", f"file:{SERIAL_LOG}",
        "-pidfile", str(VM_PIDFILE),
        "-daemonize",
        *kvm_args,
    ]

    print("Booting OpenWrt VM...", flush=True)
    # The root conftest's session-autouse egress stub shadows ssh/scp in
    # PATH unless CONWRT_REAL_NETWORK=1 — polling through it ALWAYS fails
    # and used to surface as a misleading "VM did not become reachable"
    # after a full 300s window. Fail fast with the actual cause instead.
    if "CONWRT_SSH_STUB_LOG" in os.environ:
        pytest.fail(
            "openwrt_vm needs real ssh, but the test session's network-egress "
            "stub is on PATH (set CONWRT_REAL_NETWORK=1 for VM tests)"
        )
    r = subprocess.run(qemu_cmd, capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        pytest.fail(f"QEMU failed to start: {r.stderr}")

    # The SSH wait sits INSIDE the try/finally: a fixture that gives up
    # here must still tear its QEMU down — the fail-before-yield path used
    # to leak the VM (and its host port) onto shared-host sessions
    # (observed twice on the night-queue 2026-10-29 lane).
    try:
        # Slow hosts (nested-virt CI runners) can take several minutes from
        # kernel boot to first SSH; fast KVM hosts finish in well under a
        # minute. Env-tunable so a slow exclusive-runner slot (#583) can
        # widen the window without code changes.
        wait_loops = int(os.environ.get("CONWRT_VM_SSH_WAIT_LOOPS", "60") or 60)
        print(f"Waiting for SSH (up to ~{wait_loops * 5}s)...", flush=True)
        for i in range(wait_loops):
            r = _ssh("true")
            if r.returncode == 0:
                print(f"SSH ready after ~{i * 5}s", flush=True)
                break
            time.sleep(5)
        else:
            serial_tail = ""
            if SERIAL_LOG.exists():
                serial_tail = SERIAL_LOG.read_text()[-2000:]
            pytest.fail(
                f"OpenWrt VM did not become reachable via SSH after "
                f"{wait_loops * 5}s.\n"
                f"Serial log tail:\n{serial_tail}"
            )
        yield {"host": SSH_HOST, "port": SSH_PORT, "key": str(SSH_KEY),
               "wg_fwd_port": wg_fwd_port}
    finally:
        _capture_evidence()
        if VM_PIDFILE.exists():
            try:
                pid = int(VM_PIDFILE.read_text().strip())
                cmdline = Path(f"/proc/{pid}/cmdline")
                if cmdline.exists() and "qemu-system-x86_64" in cmdline.read_text():
                    subprocess.run(["kill", str(pid)], capture_output=True)
            except (ValueError, OSError):
                pass
            VM_PIDFILE.unlink(missing_ok=True)
        if VM_OVERLAY.exists():
            VM_OVERLAY.unlink()


def _capture_evidence() -> None:
    """Snapshot VM state into $CONWRT_EVIDENCE_DIR (set by scripts/local-tests.sh).

    Local-only debugging aid: serial log, UCI state, and firmware identity for
    every run — written before the VM is killed at session teardown."""
    ev = os.environ.get("CONWRT_EVIDENCE_DIR")
    if not ev:
        return
    try:
        ev_dir = Path(ev)
        ev_dir.mkdir(parents=True, exist_ok=True)
        if SERIAL_LOG.exists():
            shutil.copy(SERIAL_LOG, ev_dir / "serial.log")
        r = _ssh("uci show 2>/dev/null", timeout=20)
        (ev_dir / "uci-show.txt").write_text(r.stdout or "")
        r = _ssh("cat /etc/openwrt_release 2>/dev/null", timeout=10)
        (ev_dir / "openwrt-release.txt").write_text(r.stdout or "")
    except Exception as exc:  # noqa: BLE001 — evidence capture must never fail a run
        print(f"Evidence capture failed (non-fatal): {exc}", flush=True)


@pytest.fixture(scope="session")
def ssh_cmd(openwrt_vm):
    def _run(command: str, timeout: int = 30) -> str:
        return _ssh(command, timeout=timeout).stdout
    return _run


def vm_ssh_cmd(command: str, timeout: int = 60):
    import subprocess as _sp
    return _sp.run(
        ["ssh", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null",
         "-o", "ConnectTimeout=5", "-o", "LogLevel=ERROR",
         "-i", str(SSH_KEY), "-p", str(SSH_PORT), f"root@{SSH_HOST}", command],
        capture_output=True, text=True, timeout=timeout,
    )


@pytest.fixture(scope="session")
def wireguard_installed(openwrt_vm):
    # OpenWrt 24.10 = opkg; 25.x = apk (see AGENTS.md package-era map)
    def vm(command: str, timeout: int = 60) -> str:
        r = vm_ssh_cmd(command, timeout)
        assert r.returncode == 0, f"vm command failed: {command}\n{r.stderr}"
        return r.stdout.strip()

    if "opkg" in vm("command -v opkg || true"):
        if "wireguard-tools" not in vm("opkg list-installed"):
            vm("opkg update >/dev/null 2>&1 && "
               "opkg install wireguard-tools kmod-wireguard curl >/dev/null 2>&1", timeout=180)
    else:
        if "wireguard-tools" not in vm("apk info 2>/dev/null"):
            vm("apk update >/dev/null 2>&1 && "
               "apk add wireguard-tools kmod-wireguard curl >/dev/null 2>&1", timeout=180)
    assert "wg" in vm("command -v wg || true"), "wireguard-tools not installable on the VM"
    return vm


# --- Venue fixture (PRTA transition plan §3, step S2) --------------------------

import sys as _sys

_sys.path.insert(0, str(REPO_ROOT / "tests"))
from venues import (  # noqa: E402
    direct_device,
    flash_lease as flash_lease_ctx,
    venues_from_env,
)

VENUES = venues_from_env()

_VENUE_UNREACHABLE_MARKERS = (
    "Timeout while waiting for ssh connection",
    "NoDriverFoundError",
    "Connection timed out",
    "Connection refused",
    "No route to host",
    "Traceback (most recent call last)",
    # a place without a usable NetworkService (or with a resource class the
    # local labgrid install doesn't know) is an environment condition, not
    # a test failure — the sweep evidence 2026-10-15 hit both shapes
    "no NetworkService resource found",
    "unknown resource class",
)


def _venue_unreachable(stderr: str) -> bool:
    return any(marker in stderr for marker in _VENUE_UNREACHABLE_MARKERS)


class VenueHandle:
    """The whole venue contract a venue-agnostic test sees: a name + run().

    ``ssh_target`` (host, port, key) is the optional direct-SSH capability:
    present for venues reachable with plain ssh from this host (the QEMU
    session VM), None for exporter-proxied-only venues (bench places on
    unrouted VLANs). Flows that shell out to conwrt CLI tools need it.
    """

    def __init__(self, name: str, run, ssh_target=None, model_id=None):
        self.name = name
        self._run = run
        self.ssh_target = ssh_target
        self.model_id = model_id

    def run(self, command: str, timeout: int = 30):
        return self._run(command, timeout=timeout)


def _qemu_venue_runner(vm: dict):
    def _run(command: str, timeout: int):
        return vm_ssh_cmd(command, timeout=timeout)
    return _run


def _labgrid(args: list[str], place: str, timeout: int = 40):
    client = os.environ.get("CONWRT_LABGRID_CLIENT", "labgrid-client")
    coordinator = os.environ.get("CONWRT_LABGRID_COORDINATOR", "ai-legion:20408")
    return subprocess.run(
        [client, "-x", coordinator, "-p", place, *args],
        capture_output=True, text=True, timeout=timeout, check=False,
    )


@pytest.fixture(params=VENUES, ids=[v.key for v in VENUES])
def venue(request):
    """A device to run commands on — QEMU VM, labgrid place, or direct SSH.

    Selected by the runner via CONWRT_VENUES (default: qemu-session only).
    Dark labgrid venues SKIP (never fail) — on a multi-agent host the place
    may be held by a sibling session or the device itself dark.
    """
    chosen = request.param
    if chosen.kind == "qemu-session":
        vm = request.getfixturevalue("openwrt_vm")
        yield VenueHandle(
            name=f"virtual-x86-64@qemu(127.0.0.1:{vm['port']})",
            run=_qemu_venue_runner(vm),
            ssh_target=(vm["host"], vm["port"], vm["key"]),
            model_id="virtual-x86-64",
        )
        return

    if chosen.kind == "direct":
        dev = direct_device(chosen.place or "")
        host = dev["host"]
        port = int(dev.get("port", 22))
        if dev.get("key"):
            dev["key"] = str(Path(dev["key"]).expanduser())

        def _direct_run(command: str, timeout: int):
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no",
                   "-o", "UserKnownHostsFile=/dev/null",
                   "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
                   "-o", "LogLevel=ERROR"]
            if dev.get("key"):
                cmd += ["-i", str(dev["key"])]
            cmd += ["-p", str(port), f"root@{host}", command]
            return subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=timeout, check=False)

        yield VenueHandle(
            name=f"direct:{chosen.place}({host})",
            run=_direct_run,
            ssh_target=(host, port, dev.get("key")),
            model_id=dev.get("model"),
        )
        return

    place = chosen.place or ""
    acquired = _labgrid(["acquire"], place, timeout=25)
    if acquired.returncode != 0:
        pytest.skip(
            f"labgrid place {place!r} not acquirable on "
            f"{os.environ.get('CONWRT_LABGRID_COORDINATOR', 'ai-legion:20408')} "
            f"(held by a sibling session or coordinator down): "
            f"{acquired.stderr.strip()[-200:]}"
        )

    def _run(command: str, timeout: int):
        # Exporter-proxied SSH: this host has no route to the bench VLANs;
        # the labgrid client tunnels through the exporter host.
        r = _labgrid(["ssh", "--", command], place, timeout=timeout)
        if _venue_unreachable(r.stderr):
            pytest.skip(f"{place}: venue unreachable via labgrid "
                        f"(rc={r.returncode}): {r.stderr.strip()[-300:]}")
        return r

    try:
        yield VenueHandle(name=f"labgrid:{place}", run=_run)
    finally:
        _labgrid(["release"], place, timeout=25)


@pytest.fixture
def flash_lease(request):
    """§4.3 lease factory for MUTATING work on a hardware place.

    Usage: ``with flash_lease("x1860-1", story="sysupgrade") as lease: ...``.
    Protected places raise ProtectedPlaceError (before any coordinator
    call); CONWRT_FLASH_LEASE_DRY=1 keeps the lease local (zero subprocess)
    — CI and hardware-safe development must set it. VM venues don't take
    leases (the QEMU overlay is its own isolation).
    """
    def _make(place: str, story: str = ""):
        session = os.environ.get("CONWRT_SESSION_ID") or f"pid{os.getpid()}"
        return flash_lease_ctx(
            place,
            session=session,
            story=story or request.node.name,
        )
    return _make
