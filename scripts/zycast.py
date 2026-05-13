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
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Optional

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
