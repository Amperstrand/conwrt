#!/usr/bin/env python3

import argparse
import hashlib
import json
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "extreme-ap391x-analysis"
REPORT_COPY_PATH = REPO_ROOT / "reports" / "extreme-ap391x-firmware-analysis.md"
AP_MODEL_TOKENS = ("ap391x", "ap3915", "ap3912", "ap3916", "ap3917", "ap7662")
STRING_TERMS = (
    "image_upgrade",
    "firmware",
    "validate",
    "signature",
    "x509",
    "rsa",
    "ecdsa",
    "openssl",
    "manifest",
    "ap391x",
    "ap3915",
)
UIMAGE_MAGIC = 0x27051956
PRINTABLE_MIN = 4
TREE_ENTRY_LIMIT = 200
STRING_HIT_LIMIT = 80

UIMAGE_OS = {
    0: "invalid",
    5: "linux",
}
UIMAGE_ARCH = {
    0: "invalid",
    2: "arm",
    5: "mips",
    20: "arm64",
}
UIMAGE_TYPE = {
    0: "invalid",
    2: "kernel",
    4: "multi",
    5: "firmware",
    7: "filesystem",
}
UIMAGE_COMP = {
    0: "none",
    1: "gzip",
    2: "bzip2",
    3: "lzma",
    4: "lzo",
    5: "lz4",
    6: "zstd",
}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def run_command(command: list[str], timeout: int = 60) -> dict[str, Any]:
    if not shutil.which(command[0]):
        return {
            "available": False,
            "command": command,
            "returncode": None,
            "stdout": "",
            "stderr": f"{command[0]} not available",
        }
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        return {
            "available": True,
            "command": command,
            "returncode": None,
            "stdout": exc.stdout or "",
            "stderr": "command timed out",
        }
    return {
        "available": True,
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def sanitize_filename(name: str, fallback: str) -> str:
    base = Path(name).name or fallback
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip(".-")
    return safe or fallback


def looks_like_login_page(head: bytes, content_type: str) -> bool:
    lowered = head.lower()
    if "html" in content_type.lower():
        return True
    html_markers = (b"<html", b"<!doctype html", b"<form", b"<body")
    if any(marker in lowered for marker in html_markers):
        return True
    login_markers = (b"login", b"sign in", b"password", b"support portal", b"authenticate")
    return any(marker in lowered for marker in login_markers)


def download_url(url: str, temp_dir: Path) -> tuple[Optional[Path], dict[str, Any], Optional[str]]:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "conwrt-extreme-ap391x-analyze/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            final_url = response.geturl()
            content_type = response.headers.get_content_type()
            disposition = response.headers.get("Content-Disposition", "")
            filename = "downloaded-firmware.bin"
            match = re.search(r'filename="?([^";]+)"?', disposition)
            if match:
                filename = sanitize_filename(match.group(1), filename)
            else:
                parsed = urllib.parse.urlparse(final_url)
                if parsed.path:
                    filename = sanitize_filename(Path(parsed.path).name, filename)
            head = response.read(8192)
            if looks_like_login_page(head, content_type):
                return None, {
                    "requested_url": url,
                    "final_url": final_url,
                    "content_type": content_type,
                    "blocked": True,
                    "reason": "download resolved to HTML/login content",
                }, "Download stopped: URL appears to require login or returned HTML instead of firmware."
            dest = temp_dir / filename
            with open(dest, "wb") as f:
                f.write(head)
                shutil.copyfileobj(response, f)
            return dest, {
                "requested_url": url,
                "final_url": final_url,
                "content_type": content_type,
                "blocked": False,
            }, None
    except urllib.error.HTTPError as exc:
        body = exc.read(4096)
        if looks_like_login_page(body, exc.headers.get_content_type()):
            return None, {
                "requested_url": url,
                "final_url": url,
                "content_type": exc.headers.get_content_type(),
                "blocked": True,
                "reason": f"HTTP {exc.code} login/html response",
            }, f"Download stopped: HTTP {exc.code} appears to be login-gated HTML."
        return None, {"requested_url": url, "blocked": True, "reason": f"HTTP {exc.code}"}, f"Download failed: HTTP {exc.code}"
    except urllib.error.URLError as exc:
        return None, {"requested_url": url, "blocked": True, "reason": str(exc.reason)}, f"Download failed: {exc.reason}"


def safe_relative_path(base_dir: Path, target_path: Path) -> Optional[str]:
    try:
        return str(target_path.resolve().relative_to(base_dir.resolve()))
    except ValueError:
        return None


def extract_tar_member(archive: tarfile.TarFile, member: tarfile.TarInfo, dest_root: Path) -> Optional[Path]:
    if not member.isfile():
        return None
    relative = Path(member.name)
    target = (dest_root / relative).resolve()
    try:
        target.relative_to(dest_root.resolve())
    except ValueError:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    extracted = archive.extractfile(member)
    if extracted is None:
        return None
    with extracted, open(target, "wb") as f:
        shutil.copyfileobj(extracted, f)
    return target


def extract_zip_member(archive: zipfile.ZipFile, name: str, dest_root: Path) -> Optional[Path]:
    info = archive.getinfo(name)
    if info.is_dir():
        return None
    relative = Path(name)
    target = (dest_root / relative).resolve()
    try:
        target.relative_to(dest_root.resolve())
    except ValueError:
        return None
    target.parent.mkdir(parents=True, exist_ok=True)
    with archive.open(name) as src, open(target, "wb") as dst:
        shutil.copyfileobj(src, dst)
    return target


def extract_tar_archive(image_path: Path, dest_dir: Path) -> tuple[bool, list[str]]:
    notes: list[str] = []
    tar_cmd = run_command(["tar", "-xf", str(image_path), "-C", str(dest_dir)], timeout=120)
    if tar_cmd["available"] and tar_cmd["returncode"] == 0:
        notes.append("tar extraction succeeded via external tar")
        return True, notes
    if tarfile.is_tarfile(image_path):
        try:
            with tarfile.open(image_path) as archive:
                archive.extractall(dest_dir, filter="data")
            notes.append("tar extraction succeeded via tarfile module")
            if tar_cmd["available"] and tar_cmd["returncode"] not in (0, None):
                notes.append(f"external tar failed first: {tar_cmd['stderr'] or 'unknown error'}")
            return True, notes
        except (tarfile.TarError, OSError, ValueError) as exc:
            notes.append(f"tar extraction failed: {exc}")
            return False, notes
    if tar_cmd["available"] and tar_cmd["returncode"] not in (0, None):
        notes.append(f"external tar failed: {tar_cmd['stderr'] or 'not a tar archive'}")
    else:
        notes.append("not recognized as tar archive")
    return False, notes


def build_tree(root: Path) -> str:
    if not root.exists():
        return "(not extracted)"
    entries: list[str] = [f"{root.name}/"]
    all_paths = sorted(root.rglob("*"))
    for index, path in enumerate(all_paths[:TREE_ENTRY_LIMIT], start=1):
        relative = path.relative_to(root)
        depth = len(relative.parts) - 1
        indent = "  " * depth
        suffix = "/" if path.is_dir() else ""
        entries.append(f"{indent}{relative.name}{suffix}")
        if index == TREE_ENTRY_LIMIT and len(all_paths) > TREE_ENTRY_LIMIT:
            entries.append("...")
    return "\n".join(entries)


def is_printable_byte(value: int) -> bool:
    return 32 <= value <= 126


def find_string_hits(path: Path, root_label: str) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    current = bytearray()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                for byte in chunk:
                    if is_printable_byte(byte):
                        current.append(byte)
                        continue
                    if len(current) >= PRINTABLE_MIN:
                        text = current.decode("ascii", errors="ignore")
                        lowered = text.lower()
                        matching = [term for term in STRING_TERMS if term in lowered]
                        if matching:
                            hits.append(
                                {
                                    "path": root_label,
                                    "terms": ", ".join(matching),
                                    "text": text[:240],
                                }
                            )
                            if len(hits) >= STRING_HIT_LIMIT:
                                return hits
                    current.clear()
            if len(current) >= PRINTABLE_MIN:
                text = current.decode("ascii", errors="ignore")
                lowered = text.lower()
                matching = [term for term in STRING_TERMS if term in lowered]
                if matching:
                    hits.append({"path": root_label, "terms": ", ".join(matching), "text": text[:240]})
    except OSError:
        return hits
    return hits


def collect_string_hits(paths: list[tuple[Path, str]]) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    for path, label in paths:
        if not path.is_file():
            continue
        hits.extend(find_string_hits(path, label))
        if len(hits) >= STRING_HIT_LIMIT:
            return hits[:STRING_HIT_LIMIT]
    return hits[:STRING_HIT_LIMIT]


def parse_uimage_header(path: Path) -> Optional[dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            header = f.read(64)
            if len(header) < 64:
                return None
            unpacked = struct.unpack(">IIIIIIIBBBB32s", header)
            magic, header_crc, timestamp, size, load_addr, entry_addr, data_crc, os_id, arch_id, image_type, comp_id, raw_name = unpacked
            if magic != UIMAGE_MAGIC:
                return None
            zeroed = bytearray(header)
            zeroed[4:8] = b"\x00\x00\x00\x00"
            computed_header_crc = zlib.crc32(bytes(zeroed)) & 0xFFFFFFFF
            data = f.read(size)
            computed_data_crc = None
            data_crc_matches = None
            if len(data) == size:
                computed_data_crc = zlib.crc32(data) & 0xFFFFFFFF
                data_crc_matches = computed_data_crc == data_crc
            return {
                "path": str(path),
                "magic": f"0x{magic:08x}",
                "header_crc": f"0x{header_crc:08x}",
                "header_crc_computed": f"0x{computed_header_crc:08x}",
                "header_crc_matches": computed_header_crc == header_crc,
                "data_crc": f"0x{data_crc:08x}",
                "data_crc_computed": None if computed_data_crc is None else f"0x{computed_data_crc:08x}",
                "data_crc_matches": data_crc_matches,
                "timestamp": timestamp,
                "size": size,
                "load_address": f"0x{load_addr:08x}",
                "entry_address": f"0x{entry_addr:08x}",
                "os": UIMAGE_OS.get(os_id, f"unknown({os_id})"),
                "arch": UIMAGE_ARCH.get(arch_id, f"unknown({arch_id})"),
                "type": UIMAGE_TYPE.get(image_type, f"unknown({image_type})"),
                "compression": UIMAGE_COMP.get(comp_id, f"unknown({comp_id})"),
                "image_name": raw_name.rstrip(b"\x00").decode("ascii", errors="replace"),
            }
    except OSError:
        return None
    return None


def locate_uimage_paths(primary_image: Path, extract_dir: Path) -> list[Path]:
    matches: list[Path] = []
    preferred_names = ("vmlinux.gz.uImage", "vmlinux.uImage", "uImage")
    if extract_dir.exists():
        for candidate in sorted(extract_dir.rglob("*")):
            if not candidate.is_file():
                continue
            lower_name = candidate.name.lower()
            if any(name.lower() == lower_name for name in preferred_names) or "uimage" in lower_name:
                matches.append(candidate)
    if not matches:
        header = parse_uimage_header(primary_image)
        if header is not None:
            matches.append(primary_image)
    return matches


def classify_image(uimage: Optional[dict[str, Any]], string_hits: list[dict[str, str]], file_paths: list[Path]) -> tuple[str, list[str], list[str]]:
    positive: list[str] = []
    negative: list[str] = []
    rationale: list[str] = []
    joined_strings = "\n".join(hit["text"].lower() for hit in string_hits)
    crypto_terms_found = [term for term in ("signature", "x509", "rsa", "ecdsa", "openssl") if term in joined_strings]
    checksum_terms_found = [term for term in ("image_upgrade", "firmware", "validate", "manifest") if term in joined_strings]
    signature_files = []
    for path in file_paths:
        lower_name = path.name.lower()
        if lower_name.endswith((".sig", ".p7s", ".pem", ".crt", ".cer", ".der")):
            signature_files.append(str(path))
    if crypto_terms_found:
        positive.append(f"crypto-related validation strings found: {', '.join(sorted(set(crypto_terms_found)))}")
    if signature_files:
        positive.append(f"signature-related files present: {', '.join(signature_files[:8])}")
    if uimage is not None:
        negative.append("uImage legacy CRC fields were present and parsed")
        rationale.append("uImage header/data CRC values are integrity checks, not vendor cryptographic signatures.")
    if checksum_terms_found:
        negative.append(f"upgrade/checksum-related strings found: {', '.join(sorted(set(checksum_terms_found)))}")
    if positive:
        rationale.append("Cryptographic verification indicators were found in image contents or filenames.")
        return "signed-likely", positive, rationale + negative
    if negative:
        rationale.append("Only checksum/integrity style evidence was found, without clear cryptographic signature verification markers.")
        return "checksum-only-likely", negative, rationale
    rationale.append("No strong checksum-only or cryptographic-signing evidence was found.")
    return "inconclusive", [], rationale


def analyze_ap_image(image_path: Path, temp_dir: Path, label: str) -> dict[str, Any]:
    file_info = run_command(["file", "-b", str(image_path)])
    sha_cmd = run_command(["sha256sum", str(image_path)])
    sha256 = sha256_file(image_path)
    extraction_dir = temp_dir / f"extract-{sanitize_filename(label, 'image')}"
    extraction_dir.mkdir(parents=True, exist_ok=True)
    extracted, extraction_notes = extract_tar_archive(image_path, extraction_dir)
    if not extracted and extraction_dir.exists() and not any(extraction_dir.iterdir()):
        extraction_dir.rmdir()
    uimage_paths = locate_uimage_paths(image_path, extraction_dir)
    uimage_headers = [header for header in (parse_uimage_header(path) for path in uimage_paths) if header is not None]
    search_paths: list[tuple[Path, str]] = [(image_path, label)]
    file_paths = [image_path]
    if extraction_dir.exists():
        for extracted_path in sorted(extraction_dir.rglob("*")):
            if extracted_path.is_file():
                relative = extracted_path.relative_to(extraction_dir)
                search_paths.append((extracted_path, f"{label}:{relative}"))
                file_paths.append(extracted_path)
    string_hits = collect_string_hits(search_paths)
    classification, signature_evidence, rationale = classify_image(
        uimage_headers[0] if uimage_headers else None,
        string_hits,
        file_paths,
    )
    return {
        "label": label,
        "path": str(image_path),
        "filename": image_path.name,
        "size": image_path.stat().st_size,
        "sha256": sha256,
        "file_command": file_info,
        "sha256sum_command": sha_cmd,
        "tar_extraction": {
            "attempted": True,
            "succeeded": extracted,
            "notes": extraction_notes,
            "tree": build_tree(extraction_dir) if extracted else "(not extracted)",
        },
        "uimage_headers": uimage_headers,
        "string_hits": string_hits,
        "signature_evidence": signature_evidence,
        "classification": classification,
        "classification_rationale": rationale,
    }


def analyze_controller_image(image_path: Path, temp_dir: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "filename": image_path.name,
        "path": str(image_path),
        "size": image_path.stat().st_size,
        "sha256": sha256_file(image_path),
        "embedded_ap_images": [],
        "archive_type": "unknown",
        "archive_members": [],
    }
    member_extract_dir = temp_dir / "controller-members"
    member_extract_dir.mkdir(parents=True, exist_ok=True)
    candidate_names: list[str] = []
    if tarfile.is_tarfile(image_path):
        result["archive_type"] = "tar"
        with tarfile.open(image_path) as archive:
            members = [member.name for member in archive.getmembers() if member.isfile()]
            result["archive_members"] = members[:TREE_ENTRY_LIMIT]
            for member in archive.getmembers():
                lower_name = member.name.lower()
                if member.isfile() and any(token in lower_name for token in AP_MODEL_TOKENS):
                    extracted = extract_tar_member(archive, member, member_extract_dir)
                    if extracted is not None:
                        candidate_names.append(member.name)
                        result["embedded_ap_images"].append(
                            analyze_ap_image(extracted, temp_dir / "embedded-analysis", f"embedded:{member.name}")
                        )
    elif zipfile.is_zipfile(image_path):
        result["archive_type"] = "zip"
        with zipfile.ZipFile(image_path) as archive:
            members = [name for name in archive.namelist() if not name.endswith("/")]
            result["archive_members"] = members[:TREE_ENTRY_LIMIT]
            for name in members:
                lower_name = name.lower()
                if any(token in lower_name for token in AP_MODEL_TOKENS):
                    extracted = extract_zip_member(archive, name, member_extract_dir)
                    if extracted is not None:
                        candidate_names.append(name)
                        result["embedded_ap_images"].append(
                            analyze_ap_image(extracted, temp_dir / "embedded-analysis", f"embedded:{name}")
                        )
    result["candidate_names"] = candidate_names
    return result


def aggregate_classification(ap_result: Optional[dict[str, Any]], controller_result: Optional[dict[str, Any]]) -> tuple[str, list[str]]:
    reasons: list[str] = []
    classifications: list[str] = []
    if ap_result is not None:
        classifications.append(ap_result["classification"])
        reasons.extend(ap_result["classification_rationale"])
    if controller_result is not None:
        for embedded in controller_result.get("embedded_ap_images", []):
            classifications.append(embedded["classification"])
            reasons.extend(embedded["classification_rationale"])
    if "signed-likely" in classifications:
        return "signed-likely", reasons
    if classifications and all(value == "checksum-only-likely" for value in classifications):
        return "checksum-only-likely", reasons
    if classifications:
        return "inconclusive", reasons
    return "inconclusive", ["No AP391x/AP3915i/AP3912/AP3916/AP3917/AP7662 firmware evidence was found."]


def choose_primary_uimage(ap_result: Optional[dict[str, Any]], controller_result: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
    if ap_result and ap_result.get("uimage_headers"):
        return ap_result["uimage_headers"][0]
    if controller_result:
        for embedded in controller_result.get("embedded_ap_images", []):
            headers = embedded.get("uimage_headers", [])
            if headers:
                return headers[0]
    return None


def aggregate_tree(ap_result: Optional[dict[str, Any]], controller_result: Optional[dict[str, Any]]) -> str:
    sections: list[str] = []
    if ap_result is not None:
        sections.append(f"### {ap_result['filename']}\n```\n{ap_result['tar_extraction']['tree']}\n```")
    if controller_result is not None:
        members = controller_result.get("archive_members", [])
        if members:
            sections.append("### Controller archive members\n```\n" + "\n".join(members[:TREE_ENTRY_LIMIT]) + "\n```")
        for embedded in controller_result.get("embedded_ap_images", []):
            sections.append(f"### {embedded['label']}\n```\n{embedded['tar_extraction']['tree']}\n```")
    return "\n\n".join(sections) if sections else "(no extracted contents)"


def aggregate_string_hits(ap_result: Optional[dict[str, Any]], controller_result: Optional[dict[str, Any]]) -> list[dict[str, str]]:
    hits: list[dict[str, str]] = []
    if ap_result is not None:
        hits.extend(ap_result.get("string_hits", []))
    if controller_result is not None:
        for embedded in controller_result.get("embedded_ap_images", []):
            hits.extend(embedded.get("string_hits", []))
    return hits[:STRING_HIT_LIMIT]


def aggregate_signature_evidence(ap_result: Optional[dict[str, Any]], controller_result: Optional[dict[str, Any]]) -> list[str]:
    evidence: list[str] = []
    if ap_result is not None:
        evidence.extend(ap_result.get("signature_evidence", []))
    if controller_result is not None:
        for embedded in controller_result.get("embedded_ap_images", []):
            evidence.extend(embedded.get("signature_evidence", []))
    return evidence


def format_uimage_table(uimage: Optional[dict[str, Any]]) -> str:
    if uimage is None:
        return "No uImage legacy header located."
    rows = [
        ("Magic", uimage["magic"]),
        ("Header CRC", uimage["header_crc"]),
        ("Header CRC Computed", str(uimage["header_crc_computed"])),
        ("Header CRC Matches", str(uimage["header_crc_matches"])),
        ("Data CRC", uimage["data_crc"]),
        ("Data CRC Computed", str(uimage["data_crc_computed"])),
        ("Data CRC Matches", str(uimage["data_crc_matches"])),
        ("Timestamp", str(uimage["timestamp"])),
        ("Size", str(uimage["size"])),
        ("Load Address", uimage["load_address"]),
        ("Entry Address", uimage["entry_address"]),
        ("OS", uimage["os"]),
        ("Arch", uimage["arch"]),
        ("Type", uimage["type"]),
        ("Compression", uimage["compression"]),
        ("Image Name", uimage["image_name"]),
        ("Path", uimage["path"]),
    ]
    lines = ["| Field | Value |", "|-------|-------|"]
    for field, value in rows:
        safe_value = str(value).replace("|", "\\|")
        lines.append(f"| {field} | {safe_value} |")
    return "\n".join(lines)


def render_string_analysis(hits: list[dict[str, str]]) -> str:
    if not hits:
        return "No matching validation-related strings found."
    lines = []
    for hit in hits:
        text = hit["text"].replace("`", "'")
        lines.append(f"- `{hit['path']}` [{hit['terms']}] — `{text}`")
    return "\n".join(lines)


def render_signature_evidence(evidence: list[str], classification: str) -> str:
    lines = [f"- Classification result: {classification}"]
    if evidence:
        lines.extend(f"- {item}" for item in evidence)
    else:
        lines.append("- No direct X.509/RSA/ECDSA/signature-file evidence was found.")
    return "\n".join(lines)


def render_rationale(reasons: list[str]) -> str:
    unique: list[str] = []
    for reason in reasons:
        if reason not in unique:
            unique.append(reason)
    return "\n".join(f"- {reason}" for reason in unique)


def write_report(
    report_path: Path,
    image_name: str,
    size: int,
    sha256: str,
    classification: str,
    tree_text: str,
    uimage: Optional[dict[str, Any]],
    string_hits: list[dict[str, str]],
    signature_evidence: list[str],
    rationale: list[str],
) -> None:
    report = "\n".join(
        [
            "# Extreme AP391x Firmware Analysis Report",
            "",
            "## Summary",
            f"- Image: {image_name}",
            f"- Size: {size}",
            f"- SHA256: {sha256}",
            f"- Classification: {classification}",
            "",
            "## Image Structure",
            tree_text,
            "",
            "## uImage Header",
            format_uimage_table(uimage),
            "",
            "## String Analysis",
            render_string_analysis(string_hits),
            "",
            "## Signature Evidence",
            render_signature_evidence(signature_evidence, classification),
            "",
            "## Classification Rationale",
            render_rationale(rationale),
            "",
            "## Safety Notes",
            "- uImage CRC is integrity checking, not a vendor cryptographic signature.",
            "- A plain SHA/MD5 manifest without a signed digest is not a cryptographic trust boundary.",
            "- X.509/RSA/ECDSA verification, signature files, or upgrade binaries calling crypto verification APIs are evidence of signing.",
            "- If signing is present, conwrt must not attempt direct factory-image generation.",
            "",
        ]
    )
    report_path.write_text(report)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Extreme AP391x/AP3915i/AP3912/AP3916/AP3917/AP7662 firmware images")
    parser.add_argument("--controller-image", help="Path to controller image archive")
    parser.add_argument("--ap-image", help="Path to AP image")
    parser.add_argument("--url", help="Explicit firmware URL to download and analyze")
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR / datetime.now().strftime("%Y-%m-%d")),
        help="Output directory for manifest.json and analysis-report.md",
    )
    return parser.parse_args()


def validate_args(args: argparse.Namespace) -> Optional[str]:
    provided = [bool(args.controller_image), bool(args.ap_image), bool(args.url)]
    if sum(provided) != 1:
        return "Provide exactly one of --controller-image, --ap-image, or --url."
    return None


def main() -> int:
    args = parse_args()
    error = validate_args(args)
    if error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1

    output_dir = Path(args.output_dir).expanduser().resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "manifest.json"
    report_path = output_dir / "analysis-report.md"

    manifest: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs": {
            "controller_image": args.controller_image,
            "ap_image": args.ap_image,
            "url": args.url,
        },
        "safety": {
            "download_policy": "explicit user-provided URLs only",
            "auth_bypass": False,
            "leaked_mirrors": False,
        },
    }

    with tempfile.TemporaryDirectory(prefix="extreme-ap391x-analyze-") as temp_name:
        temp_dir = Path(temp_name)
        analysis_path: Optional[Path] = None
        source_kind = "ap-image"
        if args.controller_image:
            analysis_path = Path(args.controller_image).expanduser().resolve()
            source_kind = "controller-image"
        elif args.ap_image:
            analysis_path = Path(args.ap_image).expanduser().resolve()
            source_kind = "ap-image"
        elif args.url:
            downloaded, download_meta, download_error = download_url(args.url, temp_dir)
            manifest["download"] = download_meta
            if download_error:
                manifest["error"] = download_error
                manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
                print(download_error, file=sys.stderr)
                return 1
            analysis_path = downloaded
            source_kind = "url"
        if analysis_path is None or not analysis_path.is_file():
            print("ERROR: Input image not found.", file=sys.stderr)
            return 1

        manifest["source_kind"] = source_kind
        manifest["analyzed_path"] = str(analysis_path)

        ap_result: Optional[dict[str, Any]] = None
        controller_result: Optional[dict[str, Any]] = None

        if source_kind == "controller-image":
            controller_result = analyze_controller_image(analysis_path, temp_dir)
        elif source_kind == "ap-image":
            ap_result = analyze_ap_image(analysis_path, temp_dir / "ap-analysis", analysis_path.name)
        else:
            ap_result = analyze_ap_image(analysis_path, temp_dir / "ap-analysis", analysis_path.name)
            controller_result = analyze_controller_image(analysis_path, temp_dir / "controller-analysis")
            if not controller_result.get("embedded_ap_images"):
                controller_result = None

        classification, rationale = aggregate_classification(ap_result, controller_result)
        primary_uimage = choose_primary_uimage(ap_result, controller_result)
        string_hits = aggregate_string_hits(ap_result, controller_result)
        signature_evidence = aggregate_signature_evidence(ap_result, controller_result)
        tree_text = aggregate_tree(ap_result, controller_result)
        size = analysis_path.stat().st_size
        sha256 = sha256_file(analysis_path)

        manifest["classification"] = classification
        manifest["classification_rationale"] = rationale
        manifest["ap_image_analysis"] = ap_result
        manifest["controller_image_analysis"] = controller_result
        manifest["primary_uimage_header"] = primary_uimage
        manifest["string_hits"] = string_hits
        manifest["signature_evidence"] = signature_evidence

        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        write_report(
            report_path,
            analysis_path.name,
            size,
            sha256,
            classification,
            tree_text,
            primary_uimage,
            string_hits,
            signature_evidence,
            rationale,
        )

        if REPORT_COPY_PATH.parent.is_dir():
            try:
                shutil.copyfile(report_path, REPORT_COPY_PATH)
                manifest["report_copy_path"] = str(REPORT_COPY_PATH)
                manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
            except OSError:
                pass

    print(f"Wrote {manifest_path}")
    print(f"Wrote {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
