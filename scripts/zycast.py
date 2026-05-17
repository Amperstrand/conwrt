#!/usr/bin/env python3
"""zycast — Compile, cache, and invoke the ZyXEL multicast flash utility.

Downloads zycast.c from the openwrt/firmware-utils repository, compiles it,
and caches the binary. Provides a Python interface to run zycast as a subprocess
for flashing ZyXEL devices (e.g. NR7101) via the multicast Multiboot protocol.

Protocol details:
  - UDP multicast to 225.0.0.0:5631
  - 30-byte header with magic "zyx\\0"
  - 1024-byte payload chunks
  - GPL-2.0 license (upstream: openwrt/firmware-utils)

Usage:
    from zycast import ensure_zycast_binary, run_zycast

    binary = ensure_zycast_binary()
    proc = run_zycast(binary, image_path, interface="en0")
    proc.wait()
"""

import hashlib
import logging
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Optional, Union

logger = logging.getLogger(__name__)

ZYCAST_SOURCE_URL = (
    "https://raw.githubusercontent.com/openwrt/firmware-utils/"
    "master/src/zycast.c"
)
ZYCAST_SOURCE_SHA256 = "ea597f11d5128bcbda8576be1f2a011f6d6c0b6ca0b4f0a57dcd6faa2c7d5f0d"

CACHE_DIR = Path.home() / ".cache" / "conwrt"
ZYCAST_BINARY = CACHE_DIR / "zycast"
ZYCAST_SOURCE_CACHED = CACHE_DIR / "zycast.c"
ZYCAST_HASH_FILE = CACHE_DIR / "zycast.c.sha256"


def _download_source() -> Path:
    """Download zycast.c from upstream, verify SHA-256, and cache it."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    if ZYCAST_SOURCE_CACHED.is_file() and ZYCAST_HASH_FILE.is_file():
        existing_hash = ZYCAST_HASH_FILE.read_text().strip()
        current_hash = hashlib.sha256(ZYCAST_SOURCE_CACHED.read_bytes()).hexdigest()
        if existing_hash == current_hash and existing_hash == ZYCAST_SOURCE_SHA256:
            logger.info(f"Using cached zycast source: {ZYCAST_SOURCE_CACHED}")
            return ZYCAST_SOURCE_CACHED

    logger.info(f"Downloading zycast.c from {ZYCAST_SOURCE_URL}")
    with urllib.request.urlopen(ZYCAST_SOURCE_URL) as resp:
        source_bytes = resp.read()

    source_hash = hashlib.sha256(source_bytes).hexdigest()
    logger.info(f"zycast.c SHA-256: {source_hash}")

    if source_hash != ZYCAST_SOURCE_SHA256:
        raise RuntimeError(
            f"zycast.c SHA-256 mismatch!\n"
            f"  Expected: {ZYCAST_SOURCE_SHA256}\n"
            f"  Got:      {source_hash}\n"
            f"  The upstream source may have changed. Verify and update ZYCAST_SOURCE_SHA256."
        )

    ZYCAST_SOURCE_CACHED.write_bytes(source_bytes)
    ZYCAST_HASH_FILE.write_text(source_hash)

    return ZYCAST_SOURCE_CACHED


def _compile(source_path: Path, output_path: Path) -> bool:
    """Compile zycast.c to a binary using the system C compiler."""
    cc = os.environ.get("CC", "cc")
    cmd = [cc, "-o", str(output_path), str(source_path)]

    import platform
    if platform.system() != "Linux":
        cmd.append("-DMSG_MORE=0")

    logger.info(f"Compiling zycast: {' '.join(cmd)}")
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        logger.error(f"zycast compilation failed:\n{result.stderr}")
        return False

    logger.info(f"zycast binary compiled: {output_path}")
    return True


def _binary_matches_source(binary: Path, source: Path) -> bool:
    """Check if the cached binary is newer than the source file."""
    if not binary.is_file():
        return False
    return binary.stat().st_mtime >= source.stat().st_mtime


def ensure_zycast_binary(force_rebuild: bool = False) -> Path:
    """Ensure the zycast binary is available, downloading and compiling if needed.

    Returns the path to the zycast binary.

    Raises RuntimeError if compilation fails.
    """
    source = _download_source()

    if not force_rebuild and _binary_matches_source(ZYCAST_BINARY, source):
        try:
            result = subprocess.run(
                [str(ZYCAST_BINARY), "--help"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode < 128:
                logger.info(f"Using cached zycast binary: {ZYCAST_BINARY}")
                return ZYCAST_BINARY
        except (subprocess.TimeoutExpired, OSError):
            pass

    logger.info("Building zycast binary...")
    success = _compile(source, ZYCAST_BINARY)
    if not success:
        raise RuntimeError(
            "Failed to compile zycast.c. Ensure a C compiler (cc/gcc/clang) is installed."
        )

    ZYCAST_BINARY.chmod(0o755)
    return ZYCAST_BINARY


def run_zycast(
    binary_path: Path,
    image_path: str,
    interface: str = "",
    multicast_group: str = "225.0.0.0",
    multicast_port: int = 5631,
    image_type: str = "ras",
    extra_args: Optional[list[str]] = None,
) -> subprocess.Popen:
    """Run zycast as a subprocess to flash firmware via multicast.

    zycast invocation: zycast [-i iface] [-g group] [-p port] [-t type] <image>

    Args:
        binary_path: Path to the compiled zycast binary.
        image_path: Path to the firmware image file.
        interface: Network interface to use for multicast (empty = default).
        multicast_group: Multicast group address (default 225.0.0.0).
        multicast_port: Multicast port (default 5631).
        image_type: Image type string (default "ras" for ZyXEL routers).
        extra_args: Additional arguments to pass to zycast.

    Returns:
        subprocess.Popen for the running zycast process.
    """
    cmd = [str(binary_path)]

    if interface:
        cmd.extend(["-i", interface])
    if multicast_group:
        cmd.extend(["-g", multicast_group])
    if multicast_port:
        cmd.extend(["-p", str(multicast_port)])
    if image_type:
        cmd.extend(["-t", image_type])

    if extra_args:
        cmd.extend(extra_args)

    cmd.append(image_path)

    logger.info(f"Running zycast: {' '.join(cmd)}")

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return proc


def read_zycast_progress(proc: subprocess.Popen) -> Optional[str]:
    """Non-blocking read of zycast stderr for progress output.

    Returns any available output, or None if nothing available.
    """
    import selectors
    sel = selectors.DefaultSelector()
    sel.register(proc.stderr, selectors.EVENT_READ)
    output = ""
    for key, _ in sel.select(timeout=0.1):
        if key.data == selectors.EVENT_READ:
            chunk = proc.stderr.read1(4096)  # type: ignore
            if chunk:
                output += chunk
    sel.close()
    return output or None


# ---------------------------------------------------------------------------
# Pure Python multicast zycast sender (fallback for OpenWrt/MIPS)
# ---------------------------------------------------------------------------

# Image type bitmap from zycast.c enum
_IMAGE_TYPE_MAP = {
    "bootbase": 0x01,   # BIT(0) — bootloader partition
    "rom":      0x02,   # BIT(1) — data partition
    "ras":      0x04,   # BIT(2) — kernel partition
    "romd":     0x08,   # BIT(3) — rom-d partition
    "backup":   0x10,   # BIT(4) — kernel2 partition
}

_ZYCAST_MAGIC = 0x7A797800  # "zyx\0" big-endian

# Header layout (packed, big-endian, 30 bytes):
#   uint32 magic | uint16 chksum | uint32 pid | uint32 plen |
#   uint32 flen  | uint16 unused | uint8 type | uint8 images |
#   char[2] cc   | uint8 flags   | char[5] reserved
_ZYCAST_HEADER_FMT = "!IHIIIHBB2sB5s"
_ZYCAST_HEADER_SIZE = struct.calcsize(_ZYCAST_HEADER_FMT)  # 30
_ZYCAST_CHUNK_SIZE = 1024
_ZYCAST_PKT_DELAY = 0.01  # 10 ms inter-packet delay


def _zycast_checksum(data: bytes) -> int:
    """Checksum matching the C implementation: sum bytes, fold to 16-bit."""
    total = sum(data)
    return ((total >> 16) + total) & 0xFFFF


def zycast_send_python(
    image_path: str,
    interface: str = "",
    multicast_group: str = "225.0.0.0",
    multicast_port: int = 5631,
    image_type: str = "ras",
    _stop_event: Optional[threading.Event] = None,
) -> None:
    """Pure Python zycast multicast sender.

    Implements the ZyXEL multicast flash protocol using only Python stdlib.
    Designed as a fallback for OpenWrt/MIPS systems where the C binary
    cannot be compiled.

    UNTESTED on actual ZyXEL hardware.  Protocol reverse-engineered from
    zycast.c (openwrt/firmware-utils, GPL-2.0).

    The sender loops the full transfer until stopped (matching the C
    behaviour where the process repeats until Ctrl-C), making it suitable
    for the unreliable UDP multicast environment.

    Args:
        image_path: Path to the firmware image file.
        interface:  Network interface name (e.g. ``"br-lan"``, ``"eth0"``).
        multicast_group: Multicast destination address.
        multicast_port:  Multicast destination port.
        image_type: One of ``"bootbase"``, ``"rom"``, ``"ras"``,
                    ``"romd"``, ``"backup"``.
        _stop_event: Threading event used by `ZycastPythonSender` to
                     signal a graceful stop.
    """
    stop = _stop_event or threading.Event()

    with open(image_path, "rb") as f:
        image_data = f.read()

    file_len = len(image_data)
    type_bit = _IMAGE_TYPE_MAP.get(image_type, 0x04)

    logger.info(
        f"Python zycast: {image_path} ({file_len} B), "
        f"type={image_type}(0x{type_bit:02x}), "
        f"dst={multicast_group}:{multicast_port}, "
        f"iface={'default' if not interface else interface}"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        if interface:
            try:
                # Same as C: SO_BINDTODEVICE (needs root / CAP_NET_RAW)
                sock.setsockopt(
                    socket.SOL_SOCKET,
                    socket.SO_BINDTODEVICE,
                    interface.encode() + b'\0',
                )
                logger.debug(f"Bound to device: {interface}")
            except (OSError, AttributeError) as exc:
                # Fallback: IP_MULTICAST_IF with interface IP via ioctl
                logger.debug(
                    f"SO_BINDTODEVICE failed ({exc}), trying IP_MULTICAST_IF"
                )
                try:
                    import fcntl as _fcntl  # noqa: WPS433
                    # SIOCGIFADDR (0x8915) on Linux
                    ifreq = struct.pack('256s', interface.encode()[:15])
                    res = _fcntl.ioctl(sock.fileno(), 0x8915, ifreq)
                    iface_ip = socket.inet_ntoa(res[20:24])
                    sock.setsockopt(
                        socket.IPPROTO_IP,
                        socket.IP_MULTICAST_IF,
                        socket.inet_aton(iface_ip),
                    )
                    logger.debug(f"IP_MULTICAST_IF set to {iface_ip}")
                except (OSError, ImportError, AttributeError) as exc2:
                    logger.warning(
                        f"Cannot bind to '{interface}' ({exc2}). "
                        f"Multicast may exit via wrong interface."
                    )

        sock.connect((multicast_group, multicast_port))

        loop_count = 0
        chunks_per_loop = 0
        while not stop.is_set():
            offset = 0
            packet_id = 0

            while offset < file_len and not stop.is_set():
                chunk = image_data[offset:offset + _ZYCAST_CHUNK_SIZE]
                chunk_len = len(chunk)
                checksum = _zycast_checksum(chunk)

                header = struct.pack(
                    _ZYCAST_HEADER_FMT,
                    _ZYCAST_MAGIC,    # magic  "zyx\0"
                    checksum,         # chksum
                    packet_id,        # pid
                    chunk_len,        # plen
                    file_len,         # flen
                    0,                # unusedbits
                    type_bit,         # type
                    type_bit,         # images bitmap
                    b'FF',            # country code
                    0x01,             # flags  (FLAG_SET_DEBUG)
                    b'\x00' * 5,      # reserved
                )

                # Single datagram = header + payload (the C code uses
                # MSG_MORE to batch two send() calls; in Python we just
                # concatenate and send once).
                sock.send(header + chunk)

                offset += chunk_len
                packet_id += 1

                # Interruptible delay (returns immediately when stopped)
                stop.wait(timeout=_ZYCAST_PKT_DELAY)

            chunks_per_loop = packet_id
            loop_count += 1
            if not stop.is_set():
                logger.debug(f"Transfer loop {loop_count} complete, repeating")
                stop.wait(timeout=0.1)

        logger.info(
            f"Python zycast stopped after {loop_count} loop(s), "
            f"{chunks_per_loop} chunk(s) per loop"
        )
    finally:
        sock.close()


class ZycastPythonSender:
    """Popen-like wrapper around the pure Python zycast multicast sender.

    Provides ``.poll()``, ``.wait()``, ``.terminate()``, ``.kill()``,
    ``.returncode``, ``.stdout``, ``.stderr`` matching the interface
    of ``subprocess.Popen`` so that callers (e.g. ``conwrt.py``) can
    treat it as a drop-in replacement.

    The sender runs in a daemon thread and repeats the multicast
    transfer until ``.terminate()`` is called.
    """

    def __init__(
        self,
        image_path: str,
        interface: str = "",
        multicast_group: str = "225.0.0.0",
        multicast_port: int = 5631,
        image_type: str = "ras",
    ) -> None:
        self._stop_event = threading.Event()
        self.returncode: Optional[int] = None
        # conwrt.py reads stdout/stderr after process completes.
        # Pure Python has no separate stdio — set to None so that
        # the ``if proc.stdout else ""`` guard in conwrt yields "".
        self.stdout = None   # type: ignore[assignment]
        self.stderr = None   # type: ignore[assignment]

        self._thread = threading.Thread(
            target=self._run,
            args=(
                image_path,
                interface,
                multicast_group,
                multicast_port,
                image_type,
            ),
            daemon=True,
            name="zycast-python",
        )
        self._thread.start()

    # -- internal -------------------------------------------------------

    def _run(
        self,
        image_path: str,
        interface: str,
        multicast_group: str,
        multicast_port: int,
        image_type: str,
    ) -> None:
        try:
            zycast_send_python(
                image_path=image_path,
                interface=interface,
                multicast_group=multicast_group,
                multicast_port=multicast_port,
                image_type=image_type,
                _stop_event=self._stop_event,
            )
            self.returncode = 0
        except Exception as exc:
            logger.error(f"Python zycast sender failed: {exc}")
            self.returncode = 1

    # -- Popen-compatible API -------------------------------------------

    def poll(self) -> Optional[int]:
        """Returns ``None`` while running, *returncode* when done."""
        if self._thread.is_alive():
            return None
        return self.returncode

    def wait(self, timeout: Optional[float] = None) -> Optional[int]:
        """Block until the sender finishes.  Returns *returncode*."""
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            return None
        return self.returncode

    def terminate(self) -> None:
        """Signal the sender to stop at the next inter-packet delay."""
        self._stop_event.set()

    def kill(self) -> None:
        """Alias for ``terminate()`` (Popen compatibility)."""
        self.terminate()


def ensure_zycast_sender(
    force_rebuild: bool = False,
) -> tuple[str, object]:
    """Ensure a zycast sender is available, preferring the C binary.

    Returns:
        ``(sender_type, sender_ref)`` where *sender_type* is ``"binary"``
        or ``"python"`` and *sender_ref* is either the binary `Path`
        (for use with :func:`run_zycast`) or the :func:`zycast_send_python`
        callable.
    """
    try:
        binary = ensure_zycast_binary(force_rebuild=force_rebuild)
        return ("binary", binary)
    except RuntimeError:
        logger.info("C binary unavailable, will use pure Python multicast sender")
        return ("python", zycast_send_python)


def run_zycast_auto(
    image_path: str,
    interface: str = "",
    multicast_group: str = "225.0.0.0",
    multicast_port: int = 5631,
    image_type: str = "ras",
    extra_args: Optional[list[str]] = None,
) -> Union[subprocess.Popen, ZycastPythonSender]:
    """Run zycast — try the C binary first, fall back to pure Python.

    Drop-in replacement for the ``ensure_zycast_binary()`` +
    ``run_zycast()`` two-step pattern used by ``conwrt.py``.

    Returns either a ``subprocess.Popen`` (C binary) or a
    :class:`ZycastPythonSender`.  Both expose ``.poll()``, ``.wait()``,
    ``.terminate()``, and ``.returncode``.
    """
    try:
        binary = ensure_zycast_binary()
        return run_zycast(
            binary_path=binary,
            image_path=image_path,
            interface=interface,
            multicast_group=multicast_group,
            multicast_port=multicast_port,
            image_type=image_type,
            extra_args=extra_args,
        )
    except RuntimeError:
        logger.info("C binary unavailable, using pure Python multicast sender")
        return ZycastPythonSender(
            image_path=image_path,
            interface=interface,
            multicast_group=multicast_group,
            multicast_port=multicast_port,
            image_type=image_type,
        )
