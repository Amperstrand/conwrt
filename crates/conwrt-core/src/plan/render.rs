//! `render` — split out of the former plan.rs monolith (pure move).
use super::*;
use alloc::format;
use alloc::string::{String, ToString};
pub(super) fn device_var(network: &str) -> String {
    let sanitized: String = network
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    format!("_conwrt_dev_{sanitized}")
}

/// UCI identifier keys render bare (1.x convention); non-identifier
/// characters are rejected-by-sanitization rather than quoted.
pub(super) fn uci_key(key: &str) -> String {
    key.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Section references may also be anonymous (`@dnsmasq[0]`) — still bare
/// in renders, still shell-word-safe by construction.
pub(super) fn uci_section_ref(section: &str) -> String {
    section
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '[' | ']') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// UCI identifier tokens (section names, section types, service names)
/// render bare when they match the safe charset — the 1.x convention
/// (`uci set network.wg0=interface`, `/etc/init.d/network restart`), so
/// golden output is byte-identical to the Python builders. Anything
/// outside the charset is single-quoted instead: a hostile name can
/// splice shell syntax neither bare nor quoted.
pub(super) fn uci_token(token: &str) -> String {
    let safe = !token.is_empty()
        && token
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '@'));
    if safe {
        token.to_string()
    } else {
        shell_quote(token)
    }
}

/// Render a plan to a POSIX shell script (BusyBox `ash`-compatible — the
/// OpenWrt shell transport, matching 1.x's `render_shell` conventions:
/// single-quoted uci values, `/etc/init.d/<name> <action>`).
///
/// The whole plan renders as **one script** so device-resolution state
/// (`ResolveNetworkDevice` → `UciValue::ResolvedDevice`) survives within a
/// single remote shell. Run it with `set -e`; verification is separate and
/// read-only (see `Plan::verification`).
#[must_use]
pub fn render_shell(plan: &Plan) -> String {
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str(&format!(
        "# conwrt plan: {} -> model {}\n",
        plan.profile_id, plan.model_id
    ));
    script.push_str("set -e\n\n");
    // advisories render as comments only — never commands (golden
    // comparator filters comments, so parity is unaffected)
    for warning in &plan.warnings {
        script.push_str(&format!("# WARNING: {warning}\n"));
    }
    if !plan.warnings.is_empty() {
        script.push('\n');
    }

    for op in &plan.ops {
        match op {
            PlanOp::EnsurePackage { name } => {
                script.push_str(&format!("# install package {name}\n"));
                // 1.x apk-aware shape (a11bfd6) + index self-heal: a fresh
                // 25.x boot may lack the apk adb index until `apk update`.
                // The opkg branch first checks `opkg list-installed`: a
                // device that already has the package must stay usable
                // offline — `opkg update` aborts under `set -e` when the
                // feed is unreachable (AGENTS.md package rules).
                script.push_str(&format!(
                    "if command -v apk >/dev/null 2>&1; then apk add {q} || {{ apk update \\
&& apk add {q}; }}; else [ -n \"$(opkg list-installed {q} 2>/dev/null)\" ] || {{ opkg update && opkg install {q}; }}; fi\n\n",
                    q = shell_quote(name)
                ));
            }
            PlanOp::RevertUci { config } => {
                script.push_str(&format!("# revert staged {config} baseline\n"));
                // `|| true`: on a fresh install the config file may not
                // exist yet; reverting nothing must not abort the script.
                script.push_str(&format!("uci -q revert {config} 2>/dev/null || true\n\n"));
            }
            PlanOp::ClearUciSections {
                config,
                section_type,
            } => {
                script.push_str(&format!("# clear {config}.{section_type} sections\n"));
                script.push_str(&format!(
                    "for _s in $(uci -q show {config} 2>/dev/null | grep '={section_type}' \
                     | cut -d. -f2 | cut -d= -f1); do uci -q delete {config}.$_s; done\ntrue\n\n"
                ));
            }
            PlanOp::ResolveNetworkDevice { network } => {
                let var = device_var(network);
                script.push_str(&format!("# resolve device for network {network}\n"));
                script.push_str(&format!(
                    // `|| true`: under `set -e`, a failed command
                    // substitution in an assignment aborts the script —
                    // and `uci get` exits 1 when the option is absent
                    // (which is this branch's whole purpose).
                    "{var}=$(uci get network.{network}.device 2>/dev/null || true)\n\
                     if [ -z \"${var}\" ] || ! ip addr show \"${var}\" 2>/dev/null \
                     | grep -q \"inet \"; then\n\
                     \x20 {var}=$(ip route show default 0.0.0.0/0 2>/dev/null \
                     | awk '{{print $5}}' | head -1)\n\
                     fi\n\
                     if [ -z \"${var}\" ]; then {var}={network}; fi\n\n"
                ));
            }
            PlanOp::SetUciSection {
                config,
                section,
                section_type,
                options,
            } => {
                script.push_str(&format!("# uci {config}.{section}={section_type}\n"));
                script.push_str(&format!(
                    "uci set {config}.{}={}\n",
                    uci_token(section),
                    uci_token(section_type)
                ));
                for (option, value) in options {
                    match value {
                        UciValue::Literal(v) => script.push_str(&format!(
                            "uci set {config}.{section}.{}={}\n",
                            uci_key(option),
                            shell_quote(v)
                        )),
                        UciValue::ResolvedDevice { network } => {
                            let var = device_var(network);
                            script.push_str(&format!(
                                "uci set {config}.{section}.{}=\"${var}\"\n",
                                uci_key(option)
                            ));
                        }
                    }
                }
                script.push('\n');
            }
            PlanOp::SetUciOptions {
                config,
                section,
                options,
            } => {
                let section = uci_section_ref(section);
                script.push_str(&format!("# uci {config}.{section} options\n"));
                for (option, value) in options {
                    match value {
                        UciValue::Literal(v) => script.push_str(&format!(
                            "uci set {config}.{section}.{}={}\n",
                            uci_key(option),
                            shell_quote(v)
                        )),
                        UciValue::ResolvedDevice { network } => {
                            let var = device_var(network);
                            script.push_str(&format!(
                                "uci set {config}.{section}.{}=\"${var}\"\n",
                                uci_key(option)
                            ));
                        }
                    }
                }
                script.push('\n');
            }
            PlanOp::UciDeleteOption {
                config,
                section,
                option,
            } => {
                let section = uci_section_ref(section);
                script.push_str(&format!(
                    "# uci delete {config}.{section}.{}\nuci -q delete {config}.{section}.{} \
|| true\n\n",
                    uci_key(option),
                    uci_key(option)
                ));
            }
            PlanOp::UciAddList {
                config,
                section,
                option,
                value,
            } => {
                let section = uci_section_ref(section);
                script.push_str(&format!(
                    "# uci add_list {config}.{section}.{}\nuci add_list {config}.{section}.{}={}\n\n",
                    uci_key(option),
                    uci_key(option),
                    shell_quote(value)
                ));
            }
            PlanOp::ResetUciConfig { config } => {
                script.push_str(&format!(
                    "# reset uci {config}\nuci -q delete {config} >/dev/null 2>&1 || true\n\n"
                ));
            }
            PlanOp::CleanupUciSections { config, pattern } => {
                // Byte-exact port of 1.x `uci_cleanup_sections_sh`
                // (scripts/profile/uci_helpers.py) — golden-compared in
                // tests/use_case_goldens.rs.
                script.push_str(&format!(
                    "# cleanup uci {config} sections matching {pattern}\n"
                ));
                script.push_str(&format!(
                    "while uci show {config} 2>/dev/null | grep -q \"{pattern}\"; do \
                     _s=$(uci show {config} 2>/dev/null | grep \"{pattern}\" \
                     | head -1 | cut -d. -f2 | cut -d= -f1); \
                     uci delete \"{config}.$_s\" 2>/dev/null; done; true\n\n"
                ));
            }
            PlanOp::Shell { command } => {
                // No trailing blank line: heredoc payloads (tether's ADB
                // hotplug hook) require exact line adjacency — a blank line
                // between `cat << EOF` and the body would corrupt the file.
                script.push_str(&format!("{command}\n"));
            }
            PlanOp::CommitUci { config } => {
                script.push_str(&format!("# uci commit {config}\nuci commit {config}\n\n"));
            }
            PlanOp::Service { name, action } => {
                let action = match action {
                    ServiceAction::Enable => "enable",
                    ServiceAction::Restart => "restart",
                    ServiceAction::Start => "start",
                };
                script.push_str(&format!(
                    "# service {name} {action}\n/etc/init.d/{} {}\n\n",
                    uci_token(name),
                    action
                ));
            }
        }
    }
    script
}
