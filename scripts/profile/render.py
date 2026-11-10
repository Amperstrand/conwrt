"""Render ProfilePlan for display, ASU, or SSH."""
from __future__ import annotations

from profile.plan import ProfilePlan, StepKind


def opkg_install_script(packages: list[str], remove: list[str] | None = None) -> str:
    """Shell script to install packages via opkg."""
    parts = ["opkg update"]
    if remove:
        parts.append("opkg remove " + " ".join(remove) + " 2>/dev/null || true")
    if packages:
        parts.append("opkg install " + " ".join(packages))
    return " && ".join(parts)


def print_plan(plan: ProfilePlan) -> None:
    """Human-readable plan summary."""
    print(f"Profile plan (mode={plan.mode})")
    print(f"  ASU packages ({len(plan.all_packages())}): {', '.join(plan.all_packages()) or '(none)'}")
    remove = plan.all_packages_remove()
    if remove:
        print(f"  opkg remove: {', '.join(remove)}")
    script = plan.asu_defaults_script()
    print(f"  ASU defaults script: {len(script.splitlines()) if script else 0} lines")
    print()
    for i, step in enumerate(plan.steps, 1):
        line = f"  {i}. [{step.kind.value}] {step.label}"
        if step.skipped_reason:
            line += f" — SKIPPED ({step.skipped_reason})"
        print(line)
        if step.opkg_packages and step.kind != StepKind.OPKG_BATCH:
            print(f"       opkg: {', '.join(step.opkg_packages)}")
        if step.firstboot_script and step.include_in_asu:
            n = len(step.firstboot_script.splitlines())
            print(f"       firstboot: {n} lines")
        if step.configure_script and step.include_in_post_install:
            preview = step.configure_script.replace("\n", " ")[:120]
            print(f"       ssh: {preview}{'...' if len(step.configure_script) > 120 else ''}")
        if step.wifi_detect_band:
            print(f"       wifi: detect {step.wifi_detect_band} → {step.wifi_role}")


def ssh_steps_preview(plan: ProfilePlan) -> list[str]:
    """Ordered SSH command previews for dry-run."""
    lines: list[str] = []
    for step in plan.steps:
        if step.skipped_reason:
            lines.append(f"# SKIP {step.label}: {step.skipped_reason}")
            continue
        if not step.include_in_post_install:
            continue
        if step.kind == StepKind.OPKG_BATCH and step.opkg_packages:
            lines.append(opkg_install_script(step.opkg_packages, step.opkg_remove))
        elif step.opkg_packages and step.kind == StepKind.USE_CASE:
            lines.append(f"# {step.label}: opkg install " + " ".join(step.opkg_packages))
        if step.configure_script:
            lines.append(f"# {step.label}")
            for ln in step.configure_script.strip().splitlines():
                if ln.strip() and not ln.strip().startswith("#"):
                    lines.append(ln.strip())
        if step.wifi_detect_band:
            lines.append(f"# {step.label}: detect radio for {step.wifi_detect_band}")
    return lines
