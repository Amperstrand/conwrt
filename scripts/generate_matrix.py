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
    "oem-http",
    "sysupgrade",
    "recovery-http",
    "uboot-http",
    "dlink-hnap",
    "edgeos-kernel-swap",
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
    for idx, (_name, uc) in enumerate(sorted(registry().items())):
        cmd_id = f"cmd-{idx}"
        commands_html = ""
        raw_script = ""
        try:
            script = uc.build_configure({})
            if script and script.strip():
                raw_script = script.strip()
                commands_html = (
                    f'<button class="cmd-toggle" data-cmd-id="{cmd_id}">Show commands</button>'
                )
        except (ValueError, TypeError, KeyError, AttributeError, RuntimeError, ImportError):
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
            "cmd_id": cmd_id,
            "raw_script": raw_script,
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

        cap_cell = ""
        for cap_id, _ in CAPABILITIES:
            if cap_id in m.get("capabilities", []):
                cap_cell += f'<span class="cap">{cap_id}</span> '

        rows += f"""        <tr>
          <td class="vendor">{vendor}</td>
          <td class="model">{desc}<br><small class="id">{m['id']}</small></td>
          <td class="soc">{soc}</td>
          <td>{ram}</td>
          <td>{flash}</td>
{method_cells}          <td class="caps">{cap_cell}</td>
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

    cmd_source_divs = ""
    for uc in use_cases:
        raw = uc.get("raw_script", "")
        if raw:
            escaped = html.escape(raw)
            cmd_source_divs += f'<div class="cmd-source" id="{uc["cmd_id"]}">{escaped}</div>\n'

    method_headers = ""
    for method in FLASH_METHODS:
        label = method.replace("-", "<br>")
        method_headers += f"          <th>{label}</th>\n"

    testing_log_section = ""
    if log_rows:
        testing_log_section = f"""
<h2 id="testing-log">Device Testing Log</h2>
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

  /* Use case command modal */
  .note {{ color: #999; font-size: 0.8rem; font-style: italic; }}
  .cmd-toggle {{ background: none; border: none; color: #0366d6; cursor: pointer; font-size: 0.8rem; padding: 0; text-decoration: underline; }}
  .cmd-toggle:hover {{ color: #0257a5; }}
  .cmd-source {{ display: none; }}
  .modal-overlay {{ display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.5); z-index: 1000; justify-content: center; align-items: center; }}
  .modal-overlay.active {{ display: flex; }}
  .modal-content {{ background: #fff; border-radius: 8px; max-width: 720px; width: 90%; max-height: 80vh; display: flex; flex-direction: column; box-shadow: 0 8px 32px rgba(0,0,0,0.2); }}
  .modal-header {{ display: flex; justify-content: space-between; align-items: center; padding: 12px 16px; border-bottom: 1px solid #e0e0e0; }}
  .modal-title {{ font-weight: 600; font-size: 0.9rem; }}
  .modal-close {{ background: none; border: none; font-size: 1.5rem; cursor: pointer; color: #666; padding: 0 4px; line-height: 1; }}
  .modal-close:hover {{ color: #333; }}
  .modal-code {{ margin: 0; padding: 16px; overflow: auto; flex: 1; font-family: 'SF Mono', 'Menlo', 'Consolas', monospace; font-size: 0.8rem; line-height: 1.5; text-align: left; white-space: pre; background: #f8f9fa; }}
  .modal-copy {{ margin: 12px 16px; padding: 6px 16px; background: #0366d6; color: #fff; border: none; border-radius: 4px; cursor: pointer; font-size: 0.85rem; align-self: flex-end; }}
  .modal-copy:hover {{ background: #0257a5; }}

  /* Sticky nav */
  .sticky-nav {{ position: fixed; top: 0; left: 0; right: 0; z-index: 100; background: #fff; border-bottom: 1px solid #e0e0e0; padding: 8px 2rem; display: flex; gap: 1.5rem; align-items: center; }}
  .sticky-nav .nav-brand {{ font-weight: 700; font-size: 0.95rem; color: #1a1a1a; text-decoration: none; }}
  .sticky-nav .nav-brand:hover {{ text-decoration: none; }}
  .sticky-nav a {{ color: #555; font-size: 0.85rem; text-decoration: none; padding: 4px 0; border-bottom: 2px solid transparent; transition: border-color 0.15s; }}
  .sticky-nav a:hover {{ color: #0366d6; border-bottom-color: #0366d6; text-decoration: none; }}
  .sticky-nav a.active {{ color: #0366d6; border-bottom-color: #0366d6; }}
  body {{ padding-top: 48px; }}

  /* Landing page sections */
  .section {{ margin-bottom: 3rem; }}
  .hero {{ text-align: center; padding: 3.5rem 1rem 3rem; margin-bottom: 3rem; border-radius: 8px; background: linear-gradient(135deg, #f0f6ff 0%, #fafafa 70%); border: 1px solid #e0e0e0; }}
  .hero h1 {{ font-size: 2.6rem; line-height: 1.15; margin-bottom: 1rem; color: #1a1a1a; }}
  .hero .subtitle {{ font-size: 1.15rem; max-width: 640px; margin: 0 auto 2rem; line-height: 1.6; }}
  .hero-ctas {{ display: flex; gap: 0.8rem; justify-content: center; flex-wrap: wrap; }}
  .btn {{ display: inline-block; padding: 0.7rem 1.4rem; border-radius: 6px; font-size: 0.95rem; font-weight: 600; text-decoration: none; transition: background 0.15s, border-color 0.15s; border: 1px solid transparent; }}
  .btn:hover {{ text-decoration: none; }}
  .btn-primary {{ background: #0366d6; color: #fff; border-color: #0366d6; }}
  .btn-primary:hover {{ background: #0257a5; }}
  .btn-secondary {{ background: #fff; color: #0366d6; border-color: #0366d6; }}
  .btn-secondary:hover {{ background: #eef4fb; }}
  .btn-ghost {{ background: transparent; color: #555; border-color: #ccc; }}
  .btn-ghost:hover {{ border-color: #0366d6; color: #0366d6; }}

  .section-head {{ margin-bottom: 1.5rem; }}
  .section-head h2 {{ font-size: 1.5rem; color: #1a1a1a; margin: 0 0 0.3rem; }}
  .section-head .subtitle {{ color: #666; margin: 0; }}

  .steps-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.25rem; }}
  .step-card {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 1.25rem; }}
  .step-card .step-num {{ display: inline-flex; align-items: center; justify-content: center; width: 28px; height: 28px; border-radius: 50%; background: #0366d6; color: #fff; font-weight: 700; font-size: 0.85rem; margin-bottom: 0.6rem; }}
  .step-card h3 {{ font-size: 1.05rem; margin-bottom: 0.6rem; }}
  .step-card .code-block {{ background: #f8f9fa; border-radius: 4px; padding: 0.75rem; font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 0.8rem; overflow-x: auto; white-space: pre; border: 1px solid #ececec; }}
  .step-note {{ font-size: 0.85rem; color: #666; margin-top: 1rem; text-align: center; }}

  .cards-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }}
  .card {{ background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 1.25rem; }}
  .card h3 {{ font-size: 1.05rem; margin-bottom: 0.5rem; color: #1a1a1a; }}
  .card p {{ color: #555; font-size: 0.9rem; line-height: 1.55; margin: 0; }}
  .card .card-link {{ display: inline-block; margin-top: 0.6rem; font-size: 0.85rem; color: #0366d6; }}

  .docs-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 0.8rem; }}
  .doc-link {{ display: block; background: #fff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 0.9rem 1.1rem; text-decoration: none; transition: border-color 0.15s, background 0.15s; }}
  .doc-link:hover {{ text-decoration: none; border-color: #0366d6; background: #f0f6ff; }}
  .doc-link .doc-title {{ font-weight: 600; font-size: 0.92rem; color: #0366d6; }}
  .doc-link .doc-desc {{ font-size: 0.8rem; color: #888; margin-top: 0.2rem; }}
</style>
</head>
<body>

<nav class="sticky-nav">
  <a class="nav-brand" href="#">conwrt</a>
  <a href="#quick-start">Quick Start</a>
  <a href="#features">Features</a>
  <a href="#stories">User Stories</a>
  <a href="wizard.html">Wizard</a>
  <a href="#flash-methods">Devices</a>
  <a href="#use-cases">Use Cases</a>
  <a href="#docs">Docs</a>
  <a href="https://github.com/amperstrand/conwrt">GitHub</a>
</nav>

<section class="hero">
  <h1>Flash OpenWrt onto any router.</h1>
  <p class="subtitle">conwrt is a framework for flashing routers with OpenWrt — AI-assisted discovery for new devices, automated flashing for known ones. 21 devices supported across 7 vendors.</p>
  <div class="hero-ctas">
    <a class="btn btn-primary" href="wizard.html">Deployment Wizard &rarr;</a>
    <a class="btn btn-secondary" href="#quick-start">Quick Start &darr;</a>
    <a class="btn btn-ghost" href="https://github.com/amperstrand/conwrt">View on GitHub</a>
  </div>
</section>

<section class="section" id="quick-start">
  <div class="section-head">
    <h2>Quick Start</h2>
    <p class="subtitle">From clone to flash in three commands.</p>
  </div>
  <div class="steps-grid">
    <div class="step-card">
      <span class="step-num">1</span>
      <h3>Install</h3>
      <div class="code-block">git clone https://github.com/amperstrand/conwrt &amp;&amp; cd conwrt &amp;&amp; python3 -m venv .venv &amp;&amp; source .venv/bin/activate &amp;&amp; python -m pip install -e '.[dev]'</div>
    </div>
    <div class="step-card">
      <span class="step-num">2</span>
      <h3>Connect &amp; Detect</h3>
      <div class="code-block"># Plug ethernet to your router, then:
python3 scripts/conwrt.py probe
# Or auto-detect:
python3 scripts/conwrt.py auto</div>
    </div>
    <div class="step-card">
      <span class="step-num">3</span>
      <h3>Flash</h3>
      <div class="code-block">python3 scripts/conwrt.py flash --model-id dlink-covr-x1860-a1 --request-image --wan-ssh</div>
    </div>
  </div>
  <p class="step-note">Or use the interactive <a href="wizard.html">Wizard &rarr;</a> to pick your router and get the exact commands.</p>
</section>

<section class="section" id="features">
  <div class="section-head">
    <h2>What conwrt can do</h2>
    <p class="subtitle">Six core capabilities that make router flashing reproducible.</p>
  </div>
  <div class="cards-grid">
    <div class="card"><h3>Auto-Detect Devices</h3><p>Probe any ethernet interface to identify connected routers via SSH fingerprint, MAC OUI, or boot-state detection. No manual IP guessing.</p></div>
    <div class="card"><h3>21 Supported Devices</h3><p>D-Link, GL.iNet, Linksys, Ubiquiti, ZyXEL, ASUS, Extreme Networks. Each with tested flash methods and boot signatures.</p></div>
    <div class="card"><h3>One-Command Flash</h3><p>conwrt flash handles the full lifecycle: detect recovery mode &rarr; upload firmware &rarr; verify SHA-256 &rarr; confirm SSH &rarr; collect inventory.</p></div>
    <div class="card"><h3>21 Pre-configured Presets</h3><p>USB tethering, SQM bufferbloat fix, WireGuard VPN, AdGuard, mesh networking, travelmate captive portal — all baked into the firmware image.</p></div>
    <div class="card"><h3>Custom ASU Builds</h3><p>Request firmware from the OpenWrt ASU builder with your SSH key, password, WiFi config, and use cases baked in. Flash and forget.</p></div>
    <div class="card"><h3>Router-to-Router</h3><p>Install conwrt on an OpenWrt router to flash other routers. Multicast flash (zycast) for provisioning many devices at once.</p></div>
  </div>
</section>

<section class="section" id="stories">
  <div class="section-head">
    <h2>Who uses conwrt?</h2>
    <p class="subtitle">Real-world deployment scenarios.</p>
  </div>
  <div class="cards-grid">
    <div class="card"><h3>The Traveler</h3><p>USB tether + VPN + SQM on a pocket-sized GL.iNet Beryl AX.</p><a class="card-link" href="user-stories.html#traveler">Read full story &rarr;</a></div>
    <div class="card"><h3>The Homelab Operator</h3><p>AdGuard + guest WiFi + WireGuard remote access on a Linksys MX4200.</p><a class="card-link" href="user-stories.html#homelab">Read full story &rarr;</a></div>
    <div class="card"><h3>The Mesh Builder</h3><p>802.11s mesh network from repurposed consumer routers.</p><a class="card-link" href="user-stories.html#mesh">Read full story &rarr;</a></div>
    <div class="card"><h3>The Developer</h3><p>Python API, model definitions, CLI scripting for full infrastructure-as-code.</p><a class="card-link" href="user-stories.html#developer">Read full story &rarr;</a></div>
    <div class="card"><h3>The Device Rescuer</h3><p>Recovery-mode flashing for bricked or stock-firmware-locked routers.</p><a class="card-link" href="user-stories.html#rescuer">Read full story &rarr;</a></div>
  </div>
</section>

<div class="legend">
  <div class="legend-item"><span class="badge tested">tested</span> Verified on real hardware</div>
  <div class="legend-item"><span class="badge defined">defined</span> Model defined, not yet tested</div>
  <div class="legend-item"><span class="badge blocked">blocked</span> Known to not work</div>
</div>

<h2 id="flash-methods">Flash Methods</h2>
<table>
  <thead>
    <tr>
      <th>Vendor</th>
      <th>Device</th>
      <th>SoC</th>
      <th>RAM</th>
      <th>Flash</th>
{method_headers}      <th>Caps</th>
    </tr>
  </thead>
  <tbody>
{rows}  </tbody>
</table>
{testing_log_section}
<h2 id="use-cases">Use Case Presets</h2>
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

<section class="section" id="docs">
  <div class="section-head">
    <h2>Documentation</h2>
    <p class="subtitle">Source files and design docs on GitHub.</p>
  </div>
  <div class="docs-grid">
    <a class="doc-link" href="https://github.com/amperstrand/conwrt#readme"><span class="doc-title">README</span><span class="doc-desc">Full feature reference, CLI options, use case docs</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/blob/master/CONTRIBUTING.md"><span class="doc-title">Contributing</span><span class="doc-desc">PR-based workflow, device contribution guide</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/blob/master/docs/process.md"><span class="doc-title">AI Discovery Process</span><span class="doc-desc">Stage 1 onboarding for unknown routers</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/blob/master/docs/gotchas.md"><span class="doc-title">Device Gotchas</span><span class="doc-desc">Per-model quirks and known issues</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/blob/master/docs/testing-status.md"><span class="doc-title">Testing Status</span><span class="doc-desc">Hardware verification log and test matrix</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/blob/master/docs/design-ops-pipeline.md"><span class="doc-title">Ops Pipeline Design</span><span class="doc-desc">Transport-agnostic operation rendering</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/tree/master/recipes"><span class="doc-title">Per-Device Recipes</span><span class="doc-desc">Step-by-step procedures and field notes</span></a>
    <a class="doc-link" href="https://github.com/amperstrand/conwrt/blob/master/AGENTS.md"><span class="doc-title">Safety Rules (AGENTS.md)</span><span class="doc-desc">Hardware-safety constraints for automated agents</span></a>
  </div>
</section>

<footer>
  Generated from <a href="https://github.com/amperstrand/conwrt/tree/master/models">models/*.json</a> — the authoritative single source of truth.<br>
  Last update: __TIMESTAMP__ · <a href="wizard.html">Deployment Wizard</a> · <a href="https://github.com/amperstrand/conwrt">GitHub</a>
</footer>

{cmd_source_divs}<div id="cmd-modal" class="modal-overlay"><div class="modal-content"><div class="modal-header"><span class="modal-title">Shell Commands</span><button class="modal-close">&times;</button></div><pre class="modal-code"><code id="modal-code-content"></code></pre><button class="modal-copy">Copy</button></div></div>
<script>
const overlay = document.getElementById('cmd-modal');
const codeContent = document.getElementById('modal-code-content');
document.addEventListener('click', e => {{
  const toggle = e.target.closest('.cmd-toggle');
  if (toggle) {{
    const src = document.getElementById(toggle.dataset.cmdId);
    if (src) {{
      codeContent.textContent = src.textContent;
      overlay.classList.add('active');
    }}
    return;
  }}
  if (e.target === overlay || e.target.closest('.modal-close')) {{
    overlay.classList.remove('active');
    return;
  }}
  if (e.target.closest('.modal-copy')) {{
    navigator.clipboard.writeText(codeContent.textContent).then(() => {{
      e.target.closest('.modal-copy').textContent = 'Copied!';
      setTimeout(() => {{ e.target.closest('.modal-copy').textContent = 'Copy'; }}, 2000);
    }});
    return;
  }}
}});
document.addEventListener('keydown', e => {{
  if (e.key === 'Escape') overlay.classList.remove('active');
}});
// Sticky nav: scroll offset + active highlighting
const navLinks = document.querySelectorAll('.sticky-nav a[href^="#"]');
const sections = [...navLinks].map(a => document.getElementById(a.getAttribute('href').slice(1))).filter(Boolean);
navLinks.forEach(a => a.addEventListener('click', e => {{
  e.preventDefault();
  const target = document.getElementById(a.getAttribute('href').slice(1));
  if (target) target.scrollIntoView({{ behavior: 'smooth', block: 'start' }});
}}));
function updateActive() {{
  let current = '';
  for (const s of sections) {{
    if (s.getBoundingClientRect().top <= 80) current = s.id;
  }}
  navLinks.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + current));
}}
window.addEventListener('scroll', updateActive, {{ passive: true }});
updateActive();
</script>
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
