#!/usr/bin/env python3
"""Generate the device support matrix HTML page from model JSON files.

Usage: python3 scripts/generate_matrix.py docs/index.html
"""
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
USE_CASES_DIR = ROOT / "scripts" / "use_cases"
COMMIT_URL = "https://github.com/amperstrand/conwrt/commit/"

FLASH_METHODS = [
    "oem-playwright",
    "sysupgrade",
    "recovery-http",
    "uboot-http",
    "dlink-hnap",
    "tftp",
    "serial-tftp-openwrt",
    "mtd-write",
    "zycast",
]

CAPABILITIES = [
    ("ethernet", "Ethernet"),
    ("wifi", "WiFi"),
    ("usb", "USB"),
    ("cellular", "Cellular"),
]

STATUS_ICONS = {
    "tested": '<span class="badge tested">tested</span>',
    "works": '<span class="badge tested">works</span>',
    "o": '<span class="badge defined">defined</span>',
    "blocked": '<span class="badge blocked">blocked</span>',
    "untested": "",
}


def load_models() -> list[dict]:
    models = []
    for f in sorted(MODELS_DIR.glob("*.json")):
        d = json.loads(f.read_text())
        d["_file"] = f.name
        models.append(d)
    return models


def load_use_cases() -> list[dict]:
    sys.path.insert(0, str(USE_CASES_DIR.parent))
    from use_cases import registry
    ucs = []
    for name, uc in sorted(registry().items()):
        commands_html = ""
        try:
            script = uc.build_configure({})
            if script and script.strip():
                escaped = html.escape(script.strip())
                commands_html = (
                    '<details><summary>Show commands</summary>'
                    f'<pre><code>{escaped}</code></pre></details>'
                )
        except (ValueError, TypeError, KeyError):
            commands_html = '<em class="note">requires configuration</em>'
        except Exception:
            commands_html = '<em class="note">requires configuration</em>'

        ucs.append({
            "name": uc.name,
            "description": uc.description,
            "packages": uc.packages,
            "requires_capabilities": uc.requires_capabilities,
            "test_status": uc.test_status,
            "tested_notes": uc.tested_notes,
            "commands_html": commands_html,
            "packages_via": uc.packages_via,
            "configure_via": uc.configure_via,
        })
    return ucs


def get_flash_status(model: dict, method: str) -> str:
    methods = model.get("flash_methods", {})
    if method not in methods:
        return ""
    mdef = methods[method]
    desc = mdef.get("description", "").lower()

    tested_hw = model.get("tested_hardware", {})
    test_info = tested_hw.get(method, {})
    tested = test_info.get("tested")
    if tested:
        commit = test_info.get("commit", "")
        if commit:
            short = commit[:7]
            url = COMMIT_URL + commit
            return f'<a href="{url}" class="commit-link">{STATUS_ICONS["tested"]}<br><code>{short}</code></a>'
        return STATUS_ICONS["tested"]
    if "does not work" in desc or "no router has ever been successfully flashed" in desc:
        return STATUS_ICONS["blocked"]
    if test_info.get("tested") is False and "blocks" in test_info.get("notes", "").lower():
        return STATUS_ICONS["blocked"]
    return STATUS_ICONS["o"]


def get_wifi_status(model: dict) -> str:
    tested_hw = model.get("tested_hardware", {})
    wifi_info = tested_hw.get("wifi_sta_ap", {})
    if wifi_info.get("tested"):
        return STATUS_ICONS["tested"]
    caps = model.get("capabilities", [])
    if "wifi" in caps:
        return STATUS_ICONS["o"]
    return ""


def _render_test_entries(model: dict) -> str:
    tested_hw = model.get("tested_hardware", {})
    if not tested_hw:
        return '<span class="note">—</span>'

    parts = []
    for entry_name, info in tested_hw.items():
        tested = info.get("tested", False)
        if tested:
            cls = "tested"
        elif "notes" in info and not tested:
            cls = "defined"
        else:
            cls = "untested"

        badge = f'<span class="badge {cls}">{cls}</span>'

        meta_parts = [f'<code>{html.escape(entry_name)}</code>', badge]

        commit = info.get("commit", "")
        if commit:
            short = commit[:7]
            url = COMMIT_URL + commit
            meta_parts.append(
                f'<a href="{url}" class="commit-link">@<code>{short}</code></a>'
            )

        verified_with = info.get("verified_with", "")
        if verified_with:
            meta_parts.append(
                f'<span class="verified">{html.escape(verified_with)}</span>'
            )

        date = info.get("date", "")
        if date:
            meta_parts.append(f'<span class="date">{date}</span>')

        parts.append(f'<div class="test-entry {cls}">{" ".join(meta_parts)}</div>')

    return "\n".join(parts)


def generate_html(models: list[dict], use_cases: list[dict]) -> str:
    rows = ""
    for m in models:
        vendor = m.get("vendor", "")
        desc = m.get("description", "")
        hw = m.get("hardware", {})
        soc = hw.get("soc", "")
        ram = hw.get("ram", "")
        flash = hw.get("flash", "")

        method_cells = ""
        for method in FLASH_METHODS:
            method_cells += f"<td>{get_flash_status(m, method)}</td>\n"

        wifi_cell = f"<td>{get_wifi_status(m)}</td>"

        cap_cell = ""
        for cap_id, _ in CAPABILITIES:
            if cap_id in m.get("capabilities", []):
                cap_cell += f'<span class="cap">{cap_id}</span> '

        tested = m.get("_tested_flash_methods", [])
        tested_note = ", ".join(tested) if tested else ""

        rows += f"""        <tr>
          <td class="vendor">{vendor}</td>
          <td class="model">{desc}<br><small class="id">{m['id']}</small></td>
          <td class="soc">{soc}</td>
          <td>{ram}</td>
          <td>{flash}</td>
{method_cells}          {wifi_cell}
          <td class="caps">{cap_cell}</td>
        </tr>
"""

    log_rows = ""
    for m in models:
        tested_hw = m.get("tested_hardware", {})
        if not tested_hw:
            continue
        vendor = m.get("vendor", "")
        desc = m.get("description", "")
        entries_html = _render_test_entries(m)
        log_rows += f"""        <tr>
          <td class="vendor">{vendor}</td>
          <td class="model">{desc}<br><small class="id">{m['id']}</small></td>
          <td class="test-entries">{entries_html}</td>
        </tr>
"""

    uc_rows = ""
    for uc in use_cases:
        pkgs = ", ".join(uc["packages"][:5])
        if len(uc["packages"]) > 5:
            pkgs += f" +{len(uc['packages']) - 5} more"
        reqs = ", ".join(uc["requires_capabilities"]) or "none"

        status_badge = ""
        ts = uc.get("test_status", "")
        if ts == "tested":
            status_badge = '<span class="badge tested">tested</span>'
        elif ts == "experimental":
            status_badge = '<span class="badge defined">experimental</span>'
        else:
            status_badge = '<span class="badge untested">untested</span>'

        tested_notes = uc.get("tested_notes", "")
        notes_html = f'<br><small>{html.escape(tested_notes)}</small>' if tested_notes else ""

        uc_rows += f"""        <tr>
          <td><code>{uc['name']}</code></td>
          <td>{uc['description']}</td>
          <td>{status_badge}{notes_html}</td>
          <td>{reqs}</td>
          <td><small>{pkgs}</small></td>
          <td>{uc['commands_html']}</td>
        </tr>
"""

    method_headers = ""
    for method in FLASH_METHODS:
        label = method.replace("-", "<br>")
        method_headers += f"          <th>{label}</th>\n"

    testing_log_section = ""
    if log_rows:
        testing_log_section = f"""
<h2>Device Testing Log</h2>
<p class="subtitle">Per-device tested capabilities with commit links.</p>
<table class="testing-log">
  <thead>
    <tr>
      <th>Vendor</th>
      <th>Device</th>
      <th>Tested Capabilities</th>
    </tr>
  </thead>
  <tbody>
{log_rows}  </tbody>
</table>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>conwrt — Device Support Matrix</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: #1a1a1a; background: #fafafa; padding: 2rem; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.5rem; }}
  h2 {{ font-size: 1.3rem; margin: 2rem 0 1rem; color: #555; }}
  .subtitle {{ color: #666; margin-bottom: 2rem; }}
  .gen-time {{ color: #999; font-size: 0.85rem; margin-bottom: 2rem; }}
  table {{ border-collapse: collapse; width: 100%; overflow-x: auto; display: block; margin-bottom: 2rem; }}
  th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.6rem; text-align: center; font-size: 0.85rem; }}
  th {{ background: #f5f5f5; font-weight: 600; position: sticky; top: 0; white-space: nowrap; }}
  td.vendor {{ font-weight: 600; white-space: nowrap; }}
  td.model {{ text-align: left; min-width: 180px; }}
  td.soc {{ text-align: left; font-size: 0.8rem; }}
  td.caps {{ text-align: left; }}
  .id {{ color: #999; }}
  .cap {{ display: inline-block; background: #e8e8e8; border-radius: 3px; padding: 1px 5px; font-size: 0.75rem; margin: 1px; }}
  .badge {{ display: inline-block; border-radius: 3px; padding: 1px 6px; font-size: 0.7rem; font-weight: 600; }}
  .badge.tested {{ background: #d4edda; color: #155724; }}
  .badge.defined {{ background: #fff3cd; color: #856404; }}
  .badge.blocked {{ background: #f8d7da; color: #721c24; }}
  .badge.untested {{ background: #e9ecef; color: #6c757d; }}
  .legend {{ margin: 1rem 0 2rem; display: flex; gap: 1.5rem; flex-wrap: wrap; }}
  .legend-item {{ display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }}
  footer {{ margin-top: 3rem; color: #999; font-size: 0.8rem; }}
  a {{ color: #0366d6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  /* Commit links */
  .commit-link {{ color: #0366d6; text-decoration: none; font-size: 0.75rem; }}
  .commit-link:hover {{ text-decoration: underline; }}
  .commit-link code {{ font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; font-size: 0.7rem; background: #f0f0f0; padding: 1px 4px; border-radius: 2px; }}

  /* Device Testing Log */
  table.testing-log td.test-entries {{ text-align: left; min-width: 320px; }}
  .test-entry {{ display: inline-block; margin: 2px 4px 2px 0; padding: 4px 8px; border-left: 3px solid #ccc; background: #fff; font-size: 0.8rem; vertical-align: top; border-radius: 0 3px 3px 0; }}
  .test-entry.tested {{ border-left-color: #28a745; background: #f0faf3; }}
  .test-entry.defined {{ border-left-color: #ffc107; background: #fffdf3; }}
  .test-entry.untested {{ border-left-color: #adb5bd; background: #f8f9fa; }}
  .test-entry code {{ font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; font-size: 0.75rem; }}
  .test-entry .badge {{ margin: 0 3px; }}
  .test-entry .verified {{ display: block; color: #666; font-style: italic; font-size: 0.75rem; margin-top: 2px; }}
  .test-entry .date {{ color: #999; font-size: 0.7rem; margin-left: 4px; }}

  /* Use case command details */
  details {{ margin-top: 4px; }}
  details summary {{ cursor: pointer; color: #0366d6; font-size: 0.8rem; }}
  details summary:hover {{ text-decoration: underline; }}
  details pre {{ margin-top: 6px; padding: 8px; background: #f5f5f5; border: 1px solid #e0e0e0; border-radius: 4px; overflow-x: auto; font-size: 0.75rem; line-height: 1.4; }}
  details code {{ font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; }}
  .note {{ color: #999; font-size: 0.8rem; font-style: italic; }}
</style>
</head>
<body>

<h1>conwrt Device Support Matrix</h1>
<p class="subtitle">Auto-generated from <code>models/*.json</code> — the authoritative single source of truth.</p>

<div class="legend">
  <div class="legend-item"><span class="badge tested">tested</span> Verified on real hardware</div>
  <div class="legend-item"><span class="badge defined">defined</span> Model defined, not yet tested</div>
  <div class="legend-item"><span class="badge blocked">blocked</span> Known to not work</div>
</div>

<h2>Flash Methods</h2>
<table>
  <thead>
    <tr>
      <th>Vendor</th>
      <th>Device</th>
      <th>SoC</th>
      <th>RAM</th>
      <th>Flash</th>
{method_headers}      <th>WiFi<br>STA/AP</th>
      <th>Caps</th>
    </tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>
{testing_log_section}
<h2>Use Case Presets</h2>
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Description</th>
      <th>Status</th>
      <th>Requires</th>
      <th>Packages</th>
      <th>Commands</th>
    </tr>
  </thead>
  <tbody>
{uc_rows}  </tbody>
</table>

<footer>
  Generated from <a href="https://github.com/amperstrand/conwrt/tree/master/models">models/*.json</a>.
  Last update: __TIMESTAMP__
</footer>

</body>
</html>"""


def main():
    import datetime
    models = load_models()
    use_cases = load_use_cases()
    html = generate_html(models, use_cases)
    html = html.replace("__TIMESTAMP__", datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    print(f"Generated {out} ({len(models)} models, {len(use_cases)} use cases)")


if __name__ == "__main__":
    main()
