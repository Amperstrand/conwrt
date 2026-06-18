"""HTTP/SSH firmware upload helpers."""
from __future__ import annotations
import os
import subprocess
from types import SimpleNamespace

from flash.context import DEFAULT_IP, log

def detect_uboot_http(recovery_ip: str = DEFAULT_IP) -> tuple[bool, str]:
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


def upload_firmware(image_path: str, profile: SimpleNamespace, timeout: int = 300) -> tuple[bool, str]:
    file_size = os.path.getsize(image_path)
    size_mb = file_size / 1024 / 1024
    endpoint = f"http://{profile.recovery_ip}{profile.upload_endpoint}"
    log(f"Uploading {os.path.basename(image_path)} ({size_mb:.1f} MB, {file_size} bytes) to {profile.upload_endpoint}...")
    try:
        r = subprocess.run(
            [
                "curl", "-sk", "--show-error",
                "-H", "Expect:",
                "--max-time", str(timeout),
                "-w", "\n%{size_upload}",
                "-F", f"{profile.upload_field}=@{image_path};type=application/octet-stream",
                endpoint,
            ],
            capture_output=True, text=True, timeout=timeout + 30, check=False,
        )
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

