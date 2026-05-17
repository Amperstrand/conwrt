#!/usr/bin/env python3
"""Generate the device support matrix HTML page from model JSON files.

Usage: python3 scripts/generate_matrix.py docs/index.html
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS_DIR = ROOT / "models"
USE_CASES_DIR = ROOT / "scripts" / "use_cases"

FLASH_METHODS = [
    "sysupgrade",
    "recovery-http",
    "uboot-http",
    "dlink-hnap",
    "tftp",
    "serial-tftp-openwrt",
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
        ucs.append({
            "name": uc.name,
            "description": uc.description,
            "packages": uc.packages,
            "requires_capabilities": uc.requires_capabilities,
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
    if test_info.get("tested"):
        return STATUS_ICONS["tested"]
    if test_info.get("notes", "").lower().find("block") >= 0 or "does not work" in desc:
        return STATUS_ICONS["blocked"]
    if not test_info.get("tested", True) and "notes" in test_info:
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

    uc_rows = ""
    for uc in use_cases:
        pkgs = ", ".join(uc["packages"][:5])
        if len(uc["packages"]) > 5:
            pkgs += f" +{len(uc['packages']) - 5} more"
        reqs = ", ".join(uc["requires_capabilities"]) or "none"
        uc_rows += f"""        <tr>
          <td><code>{uc['name']}</code></td>
          <td>{uc['description']}</td>
          <td>{reqs}</td>
          <td><small>{pkgs}</small></td>
        </tr>
"""

    method_headers = ""
    for method in FLASH_METHODS:
        label = method.replace("-", "<br>")
        method_headers += f"          <th>{label}</th>\n"

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
  table {{ border-collapse: collapse; width: 100%; overflow-x: auto; display: block; }}
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
  .legend {{ margin: 1rem 0 2rem; display: flex; gap: 1.5rem; flex-wrap: wrap; }}
  .legend-item {{ display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; }}
  footer {{ margin-top: 3rem; color: #999; font-size: 0.8rem; }}
  a {{ color: #0366d6; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
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

<h2>Use Case Presets</h2>
<table>
  <thead>
    <tr>
      <th>Name</th>
      <th>Description</th>
      <th>Requires</th>
      <th>Packages</th>
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
    html = html.replace("__TIMESTAMP__", datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%d %H:%M UTC"))

    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "docs" / "index.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(html)
    print(f"Generated {out} ({len(models)} models, {len(use_cases)} use cases)")


if __name__ == "__main__":
    main()
