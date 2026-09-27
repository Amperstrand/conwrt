"""HTTP/SSH firmware upload helpers."""
from __future__ import annotations
import os
import secrets
import subprocess
import tempfile
from types import SimpleNamespace

from flash.context import DEFAULT_IP, log


def detect_uboot_http(recovery_ip: str = DEFAULT_IP,
                      interface: str | None = None,
                      client_ip: str | None = None) -> tuple[bool, str]:
    """Probe the recovery HTTP server.

    On routed seats (fixture SVI, VLAN subinterface, ...) the probe source
    must be on-link for the recovery subnet. When *interface* and *client_ip*
    are given, the client alias is armed first (idempotent) — without it the
    curl routes via the default route and the recovery page is invisible,
    which made the "already live → skip power cycle" fast path unreachable
    and forced the manual power-cycle dance (bench-verified 2026-09-27).
    """
    if interface and client_ip:
        try:
            from platform_utils import configure_interface_ip
            configure_interface_ip(interface, client_ip, "24")
        except Exception as e:  # noqa: BLE001 — probe must not die on alias setup
            log(f"client-alias setup failed ({e}); probing anyway")
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "2", f"http://{recovery_ip}/"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        # U-Boot recovery pages contain these distinctive markers.
        # D-Link stock firmware also returns HTML but with "D-LINK" in title,
        # so exclude that to avoid false "uboot" classification.
        if "FIRMWARE UPDATE" in r.stdout or "firmware" in r.stdout.lower():
            if "D-LINK" not in r.stdout and "D-Link" not in r.stdout:
                return True, "firmware page"
        if "Recovery" in r.stdout and ("D-Link" not in r.stdout or "Recovery Mode" in r.stdout):
            return True, "recovery page"
        if r.stdout.strip().startswith("<!DOCTYPE"):
            if "HNAP1" not in r.stdout and "D-LINK" not in r.stdout:
                return True, "HTML response"
        return False, r.stdout[:100] if r.stdout.strip() else "no response"
    except (subprocess.SubprocessError, OSError) as e:
        return False, str(e)[:80]


def build_webkit_multipart(image_path: str, field: str = "firmware") -> tuple[bytes, str]:
    """Build a Chromium-shaped multipart/form-data body for *image_path*.

    Some U-Boot recovery HTTP servers mishandle curl's default multipart
    framing while accepting browser uploads (documented on D-Link COVR/DAP
    recovery: Firefox/curl-shaped uploads land wrong in NAND despite an
    "Upgrade successfully!" response). This builder emits the exact
    WebKit layout: a ``----WebKitFormBoundary`` token, CRLF framing, and a
    single octet-stream part.
    """
    token = "----WebKitFormBoundary" + secrets.token_hex(8)
    marker = b"--" + token.encode("ascii")
    with open(image_path, "rb") as fh:
        payload = fh.read()
    body = bytearray()
    body += marker + b"\r\n"
    body += (f'Content-Disposition: form-data; name="{field}"; '
             f'filename="{os.path.basename(image_path)}"\r\n').encode("ascii")
    body += b"Content-Type: application/octet-stream\r\n\r\n"
    body += payload + b"\r\n"
    body += marker + b"--\r\n"
    return bytes(body), f"multipart/form-data; boundary={token}"


def upload_firmware(image_path: str, profile: SimpleNamespace, timeout: int = 300,
                    client: str = "curl") -> tuple[bool, str]:
    """Upload *image_path* to the recovery server.

    ``client="curl"`` uses curl's default multipart framing. ``client="webkit"``
    sends a Chromium-shaped multipart body (see :func:`build_webkit_multipart`)
    for recovery servers that accept browser uploads but mangle curl's.
    """
    file_size = os.path.getsize(image_path)
    size_mb = file_size / 1024 / 1024
    endpoint = f"http://{profile.recovery_ip}{profile.upload_endpoint}"
    log(f"Uploading {os.path.basename(image_path)} ({size_mb:.1f} MB, {file_size} bytes) to {profile.upload_endpoint}...")
    tmp_path: str | None = None
    try:
        if client == "webkit":
            body, content_type = build_webkit_multipart(image_path, profile.upload_field)
            fd = tempfile.NamedTemporaryFile(prefix="conwrt-webkit-", suffix=".body", delete=False)
            fd.write(body)
            fd.close()
            tmp_path = fd.name
            cmd = [
                "curl", "-sk", "--show-error",
                "-H", "Expect:",
                "-H", "Connection: close",
                "-H", f"Content-Type: {content_type}",
                "--data-binary", f"@{tmp_path}",
                "--max-time", str(timeout),
                "-w", "\n%{size_upload}",
                endpoint,
            ]
        else:
            cmd = [
                "curl", "-sk", "--show-error",
                "-H", "Expect:",
                "--max-time", str(timeout),
                "-w", "\n%{size_upload}",
                "-F", f"{profile.upload_field}=@{image_path};type=application/octet-stream",
                endpoint,
            ]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 30, check=False)
        if r.returncode == 0 and r.stdout.strip():
            # Split response body from curl write-out (last line is size_upload)
            lines = r.stdout.rsplit("\n", 1)
            response_text = lines[0].strip()
            uploaded_bytes_str = lines[1].strip() if len(lines) > 1 else ""

            if uploaded_bytes_str:
                try:
                    uploaded_bytes = int(uploaded_bytes_str)
                    # Multipart form adds ~500 bytes overhead; tolerance 5%
                    min_expected = file_size * 0.95
                    max_expected = file_size * 1.10
                    if uploaded_bytes < min_expected:
                        log(f"WARNING: Upload may be truncated! File={file_size} bytes, "
                            f"uploaded={uploaded_bytes} bytes ({uploaded_bytes/file_size*100:.1f}%). "
                            f"Router may fail to boot.")
                        return False, f"truncated upload: {uploaded_bytes}/{file_size} bytes"
                    elif uploaded_bytes > max_expected:
                        log(f"NOTE: Upload larger than file (multipart overhead): "
                            f"file={file_size}, uploaded={uploaded_bytes}")
                    else:
                        log(f"Upload size verified: {uploaded_bytes} bytes "
                            f"({uploaded_bytes/file_size*100:.1f}% of file)")
                except ValueError:
                    log(f"Could not parse upload size from curl write-out: '{uploaded_bytes_str}'")

            if not response_text:
                log("Upload returned empty response body")
                return False, "empty response"

            # D-Link and similar routers return HTML instead of "size md5hash"
            if response_text.lower().startswith("<!doctype") or response_text.lower().startswith("<html"):
                log("Upload accepted (HTML response)")
                return True, response_text[:200]
            # GL.iNet format: "size md5hash"
            parts = response_text.split()
            uboot_md5 = parts[1] if len(parts) > 1 else "?"
            log(f"Upload accepted: size={parts[0]} bytes, uboot_md5={uboot_md5}")
            return True, response_text
        log(f"Upload failed (exit {r.returncode}): {r.stderr[:300]}")
        return False, r.stderr[:300]
    except subprocess.TimeoutExpired:
        log("Upload timed out.")
        return False, "timeout"
    except (subprocess.SubprocessError, OSError) as e:
        log(f"Upload error: {e}")
        return False, str(e)
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


def trigger_flash(profile: SimpleNamespace) -> bool:
    if not profile.trigger_flash_endpoint:
        return True
    endpoint = profile.trigger_flash_endpoint
    flash_timeout = profile.flash_time_seconds + 60
    log(f"Triggering flash via {endpoint} (timeout: {flash_timeout}s)...")
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", str(flash_timeout),
             f"http://{profile.recovery_ip}{endpoint}"],
            capture_output=True, text=True, timeout=flash_timeout + 30, check=False,
        )
        response = r.stdout.strip()
        if response == "success":
            log(f"Flash completed successfully ({endpoint} returned 'success').")
            return True
        if "Update in progress" in r.stdout:
            log("Flash triggered — 'Update in progress' page returned.")
            return True
        if response:
            log(f"Flash response: {response[:100]}")
            if "success" in response.lower():
                return True
        else:
            log(f"Empty response from {endpoint} — flash may have been consumed already.")
            return True
    except subprocess.TimeoutExpired:
        log(f"Flash trigger timed out after {flash_timeout}s — flash may still be in progress.")
        return True
    except (subprocess.SubprocessError, OSError) as e:
        log(f"Flash trigger error: {e}")
    return False

