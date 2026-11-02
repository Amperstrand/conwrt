//! `planners` — split out of the former plan.rs monolith (pure move).
use super::*;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use conwrt_types::DeviceModel;
/// Named DoH resolver endpoints (1.x parity).
pub const DOH_PROVIDERS: &[(&str, &str)] = &[
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("google", "https://dns.google/dns-query"),
    ("quad9", "https://dns.quad9.net/dns-query"),
    ("mullvad", "https://dns.mullvad.net/dns-query"),
    ("adguard", "https://dns.adguard-dns.com/dns-query"),
];

/// Bech32 payload charset (BIP-173) — the only characters allowed
/// after the `npub1`/`nsec1` human-readable prefixes.
pub(super) const BECH32_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

pub(super) fn plan_configuration_wizzard(
    model: &DeviceModel,
    _cw: &ConfigurationWizzardProfile,
) -> Result<Plan, Unsupported> {
    let ops = vec![PlanOp::Shell {
        command: "# --- configurationwizzard: deployed via deploy_configurationwizzard() ---\n\
                  # Admin: http://router/ (uhttpd port 80)\n\
                  # Portal: served by NDS on port 2050\n\
                  # rpcd plugin bridges ubus → tollgate CLI"
            .into(),
    }];
    let verification = vec![VerificationCheck {
        description: "admin panel deployed (host-side deploy_configurationwizzard)".into(),
        command: "test -d /www/net4sats && echo yes || echo missing".into(),
        expect_contains: "yes".into(),
    }];
    Ok(Plan {
        profile_id: "configurationwizzard".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// 1.x `_echo_write`: single-quote-escaped echo lines for BusyBox.
pub(super) fn echo_write_ops(path: &str, content: &str) -> Vec<PlanOp> {
    let mut lines: Vec<&str> = content.split('\n').collect();
    if lines.last() == Some(&"") {
        lines.pop();
    }
    let mut ops = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let op = if i == 0 { ">" } else { ">>" };
        let escaped = line.replace('\'', "'\\\''");
        ops.push(PlanOp::Shell {
            command: format!("echo '{escaped}' {op} {path}"),
        });
    }
    ops
}

pub(super) fn plan_fips_bluetooth_rfcomm(
    model: &DeviceModel,
    fips: &FipsBluetoothRfcommProfile,
) -> Result<Plan, Unsupported> {
    fips.validate()?;
    let yaml = fips.yaml_config();
    let mut ops: Vec<PlanOp> = ["bluez-libs", "bluez-utils", "bluez-utils-extra", "kmod-tun"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell {
        command: "mkdir -p /etc/fips".into(),
    });
    ops.extend(echo_write_ops("/etc/fips/fips.yaml", &yaml));
    ops.push(PlanOp::Shell {
        command: format!("echo '{}' > /etc/fips/bt-pin", fips.bt_pin),
    });
    let peers_allow = fips.peers_allow();
    if !peers_allow.is_empty() {
        ops.extend(echo_write_ops("/etc/fips/peers.allow", &peers_allow));
    }
    // bt-agent init script (static)
    let bt_agent_init = [
        "#!/bin/sh /etc/rc.common",
        "START=98",
        "STOP=10",
        "start() {",
        "    hciconfig hci0 up",
        "    command -v bt-agent >/dev/null 2>&1 && bt-agent -c NoInputNoOutput -p /etc/fips/bt-pin &",
        "}",
        "stop() {",
        "    killall bt-agent 2>/dev/null",
        "}",
    ].join("\n");
    ops.extend(echo_write_ops("/etc/init.d/bt-agent", &bt_agent_init));
    ops.push(PlanOp::Shell {
        command: "chmod +x /etc/init.d/bt-agent".into(),
    });
    ops.push(PlanOp::Service {
        name: "bt-agent".into(),
        action: ServiceAction::Enable,
    });
    // fips init script (static)
    let fips_init = [
        "#!/bin/sh /etc/rc.common",
        "START=99",
        "STOP=10",
        "start() {",
        "    fips -c /etc/fips/fips.yaml &",
        "}",
        "stop() {",
        "    killall fips 2>/dev/null",
        "}",
    ]
    .join("\n");
    ops.extend(echo_write_ops("/etc/init.d/fips", &fips_init));
    ops.push(PlanOp::Shell {
        command: "chmod +x /etc/init.d/fips".into(),
    });
    ops.push(PlanOp::Service {
        name: "fips".into(),
        action: ServiceAction::Enable,
    });
    ops.push(PlanOp::Shell {
        command: format!(
            "echo 'FIPS Bluetooth RFCOMM configured ({}, channel {}, {} peer(s))'",
            fips.role,
            fips.channel,
            fips.peers.len()
        ),
    });
    let verification = vec![
        VerificationCheck {
            description: "fips.yaml written".into(),
            command: "test -f /etc/fips/fips.yaml && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "fips service enabled".into(),
            command: "/etc/init.d/fips enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "fips-bluetooth-rfcomm".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// The surfshark runtime-API script body AFTER the shared JSON helper
/// (1.x `surfshark_script` minus `JSON_HELPER_SH`), byte-verbatim with
/// sentinel tokens for the gated interpolations.
/// The wg0 interface + peer stanza (1.x wg0_uci_sh output, verbatim)
/// shared by the runtime-API VPN presets — variables stay shell-side
/// (quoted fragments like `"$IVPN_PRIV"` are per-provider names).
pub(super) const WG_STANZA_SH: &str = concat!(
    "uci set network.wg0=interface\n",
    "uci set network.wg0.proto='wireguard'\n",
    "uci set network.wg0.private_key=\"__WG_PRIV__\"\n",
    "uci set network.wg0.listen_port='51820'\n",
    "uci add_list network.wg0.addresses=\"${PEER_IP}/32\"\n",
    "uci set network.wg0.mtu='1280'\n",
    "uci set network.wg0.auto='1'\n",
    "\n",
    "uci add network wireguard_wg0\n",
    "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_IP\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_port=\"$SERVER_PORT\"\n",
    "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
    "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
    "uci set network.@wireguard_wg0[0].persistent_keepalive='25'\n",
);

/// The endpoint /32 static-route block with sentinels — each preset
/// substitutes its section name into the marker BEFORE token splice
/// (route sections are named per-provider in 1.x).
pub(super) fn route_block(section: &str) -> String {
    format!(
        "# Static route: prevent circular routing through VPN tunnel\n\
         uci -q delete network.{section}\n\
         uci set network.{section}=route\n\
         uci set network.{section}.interface='__IFACE__'\n\
         uci set network.{section}.target=\"${{SERVER_IP}}\"\n\
         uci set network.{section}.netmask='255.255.255.255'\n\
         uci set network.{section}.gateway='__GATEWAY__'\n"
    )
}

/// The pre-commit address readback tail (AGENTS.md).
pub(super) fn readback_block(provider: &str) -> String {
    let mut lines: Vec<String> = vec![
        "# Pre-commit IP readback (AGENTS.md): refuse to reach commit with a".into(),
        "# tunnel address that is not a sane /32 (the surfshark #604-P1 class)".into(),
        "WG_ADDR=$(uci -q get network.wg0.addresses)".into(),
        "case \"$WG_ADDR\" in".into(),
        "    */32) ;;".into(),
        "esac".into(),
    ];
    lines.insert(
        5,
        format!(
            "    *) echo \"{provider}: wg0 address '$WG_ADDR' not a sane /32 — \
             aborting before commit\"; exit 1 ;;"
        ),
    );
    lines.join("\n")
}

/// The IVPN runtime-API script body AFTER the shared JSON helper —
/// byte-verbatim vs the FIXED 1.x builder, sentinel tokens for the
/// gated interpolations.
pub(super) const IVPN_WG_BODY_SH: &str = concat!(
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Register WG public key with IVPN API\n",
    "KEY_RESP=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.ivpn.net/v4/account/wireguard/key?account_id=__ACCOUNT__\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"public_key\":\"'\"${WG_PUB}\"'\"}')\n",
    "PEER_IP=$(echo \"$KEY_RESP\" | json_get ip_address)\n",
    "# Strip CIDR if present\n",
    "PEER_IP=${PEER_IP%%/*}\n",
    "\n",
    "# Fetch server list and pick first (.json variant — the extensionless path 404s)\n",
    "SERVERS=$(curl -s -m 15 \"https://api.ivpn.net/v4/servers.json\")\n",
    "SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '[.wireguard[].hosts[] | select(has(\"public_key\"))] | .[0]')\n",
    "SERVER_IP=$(echo \"$SERVER_ENTRY\" | json_get host)\n",
    "SERVER_KEY=$(echo \"$SERVER_ENTRY\" | json_get public_key)\n",
    "SERVER_PORT=$(echo \"$SERVER_ENTRY\" | json_get wg_port)\n",
    "[ -z \"$SERVER_PORT\" ] && SERVER_PORT=51820\n",
    "\n",
    "# Abort BEFORE the destructive wg0 cleanup unless the response is complete\n",
    "# (the surfshark #604-P2 class: a failed key registration leaves PEER_IP\n",
    "# empty — without this guard the script below deletes a working tunnel)\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_IP\" ] \\\n",
    "    || { echo 'IVPN: server list incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    "if [ -z \"$PEER_IP\" ]; then echo 'IVPN: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "IVPN_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
);

/// The Mullvad runtime-API script body AFTER the shared JSON helper.
pub(super) const MULLVAD_WG_BODY_SH: &str = concat!(
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Register WG public key with Mullvad API\n",
    "RESPONSE=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.mullvad.net/www/accounts/me/wg-peers/\" \\\n",
    "    -H \"Authorization: Token __TOKEN__\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"public_key\":\"'\"${WG_PUB}\"'\"}')\n",
    "PEER_IP=$(echo \"$RESPONSE\" | json_get ipv4_address)\n",
    "# Strip CIDR if present (Mullvad returns 10.xx.xx.xx/32)\n",
    "PEER_IP=${PEER_IP%%/*}\n",
    "\n",
    "# Fetch server list and pick best server\n",
    "SERVERS=$(curl -s -m 15 -H \"Accept: application/json\" \"https://api.mullvad.net/www/relays/wireguard/\")\n",
    "if [ -n \"__COUNTRY_FILTER__\" ]; then\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '[.[] | select(.country_code==\"__COUNTRY__\")] | .[0]')\n",
    "else\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '.[0]')\n",
    "fi\n",
    "SERVER_IP=$(echo \"$SERVER_ENTRY\" | json_get ipv4_addr_in)\n",
    "SERVER_KEY=$(echo \"$SERVER_ENTRY\" | json_get pubkey)\n",
    "SERVER_HOST=$(echo \"$SERVER_ENTRY\" | json_get hostname)\n",
    "SERVER_PORT=51820\n",
    "\n",
    "# Abort BEFORE the destructive wg0 cleanup unless the response is\n",
    "# complete (surfshark #604-P2 class)\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_IP\" ] \\\n",
    "    || { echo 'Mullvad: server list incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    "if [ -z \"$PEER_IP\" ]; then echo 'Mullvad: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "MULLVAD_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
);

pub(super) const SURFSHARK_WG_BODY_SH: &str = concat!(
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Authenticate with Surfshark — get auth token\n",
    "AUTH_RESP=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.surfshark.com/v1/auth/login\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"username\":\"__USERNAME__\",\"password\":\"__PASSWORD__\"}')\n",
    "AUTH_TOKEN=$(echo \"$AUTH_RESP\" | json_get token)\n",
    "\n",
    "# Generate WireGuard configuration\n",
    "WG_RESP=$(curl -s -m 15 -X POST \\\n",
    "    \"https://api.surfshark.com/v1/account/wireguard/new\" \\\n",
    "    -H \"Authorization: Bearer ${AUTH_TOKEN}\" \\\n",
    "    -H \"Content-Type: application/json\" \\\n",
    "    -d '{\"publicKey\":\"'\"${WG_PUB}\"'\"}')\n",
    "PEER_IP=$(echo \"$WG_RESP\" | json_get ipAddress)\n",
    "# Strip CIDR if present\n",
    "PEER_IP=${PEER_IP%%/*}\n",
    "\n",
    "# Fetch server list and pick best (v4 clusters: public endpoint, hostname-only\n",
    "# entries — connectionName/pubKey; no IP field, so the endpoint is a DNS name)\n",
    "SERVERS=$(curl -s -m 15 \\\n",
    "    \"https://api.surfshark.com/v4/server/clusters/generic?countryCode=\" \\\n",
    "    -H \"Content-Type: application/json\")\n",
    "if [ -n \"__COUNTRY_FILTER__\" ]; then\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '[.[] | select(.country | test(\"__COUNTRY__\";\"i\"))] | .[0]')\n",
    "else\n",
    "    SERVER_ENTRY=$(echo \"$SERVERS\" | jq -r '.[0]')\n",
    "fi\n",
    "SERVER_HOST=$(echo \"$SERVER_ENTRY\" | json_get connectionName)\n",
    "SERVER_KEY=$(echo \"$SERVER_ENTRY\" | json_get pubKey)\n",
    "SERVER_PORT=51820\n",
    "# Resolve the endpoint hostname for the static /32 route; skip the route\n",
    "# (netifd's wireguard proto installs its own endpoint route) when DNS fails.\n",
    "# BusyBox nslookup (OpenWrt 25.12.5, verified live 2026-10-14) prints the\n",
    "# resolver as \"Address: <ip>:53\" and each answer as \"Address: <ip>\".\n",
    "SERVER_IP=$(nslookup \"$SERVER_HOST\" 2>/dev/null | awk '$1==\"Address:\" && $2 ~ /^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$/ {print $2}' | tail -1)\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_HOST\" ] \\\n",
    "    || { echo 'Surfshark: server list incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    // a failed key registration (error JSON) leaves PEER_IP empty —
    // without this guard the script below would DELETE the working
    // wg0 and write addresses=/32 (Codex #604 P2 round 2)
    "if [ -z \"$PEER_IP\" ]; then echo 'Surfshark: key registration failed (no peer IP) — aborting before wg0 cleanup'; exit 1; fi\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "SS_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
    "# Configure WireGuard interface\n",
    "uci set network.wg0=interface\n",
    "uci set network.wg0.proto='wireguard'\n",
    "uci set network.wg0.private_key=\"$SS_PRIV\"\n",
    "uci set network.wg0.listen_port='51820'\n",
    "uci add_list network.wg0.addresses=\"${PEER_IP}/32\"\n",
    "uci set network.wg0.mtu='1280'\n",
    "uci set network.wg0.auto='1'\n",
    "\n",
    "uci add network wireguard_wg0\n",
    "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_HOST\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_port=\"$SERVER_PORT\"\n",
    "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
    "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
    "uci set network.@wireguard_wg0[0].persistent_keepalive='25'\n",
    "\n",
    "\n",
    "if [ -n \"$SERVER_IP\" ]; then\n",
    "# Static route: prevent circular routing through VPN tunnel\n",
    "uci -q delete network.surfshark_server_route\n",
    "uci set network.surfshark_server_route=route\n",
    "uci set network.surfshark_server_route.interface='__IFACE__'\n",
    "uci set network.surfshark_server_route.target=\"${SERVER_IP}\"\n",
    "uci set network.surfshark_server_route.netmask='255.255.255.255'\n",
    "uci set network.surfshark_server_route.gateway='__GATEWAY__'\n",
    "else\n",
    "    echo \"Surfshark: endpoint DNS unresolved — skipping static route (netifd installs its own)\"\n",
    "fi\n",
    "\n",
    "# Pre-commit IP readback (AGENTS.md): the shared ops below commit\n",
    "# and restart networking — refuse to reach commit with a tunnel\n",
    "# address that is not a sane /32 (Codex #604 P1 round 3).\n",
    "WG_ADDR=$(uci -q get network.wg0.addresses)\n",
    "case \"$WG_ADDR\" in\n",
    "    */32) ;;\n",
    "    *) echo \"Surfshark: wg0 address '$WG_ADDR' not a sane /32 — aborting before commit\"; exit 1 ;;\n",
    "esac\n",
);

/// Single left-to-right pass over `__TOKEN__` placeholders: inserted
/// values are never re-scanned, so a credential that itself contains
/// token-shaped text (`abc__IFACE__def`) survives verbatim — chained
/// `.replace()` calls would rewrite it (Codex #604 P2 round 5).
pub(super) fn substitute_tokens(template: &str, pairs: &[(&str, &str)]) -> String {
    // generic single-pass: at each step splice the EARLIEST token
    // occurrence and continue after the inserted value — inserted
    // values are never re-scanned, whatever their shape (token styles
    // vary: `__TOK__`, `{iface}` …). Non-token text passes through.
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    loop {
        let mut best: Option<(usize, &str, &str)> = None;
        for (tok, val) in pairs {
            if let Some(pos) = rest.find(tok) {
                if best.is_none_or(|(p, _, _)| pos < p) {
                    best = Some((pos, tok, val));
                }
            }
        }
        match best {
            Some((pos, tok, val)) => {
                out.push_str(&rest[..pos]);
                out.push_str(val);
                rest = &rest[pos + tok.len()..];
            }
            None => {
                out.push_str(rest);
                return out;
            }
        }
    }
}

/// Shared tail assembly for the runtime-API VPN presets: wg0 stanza
/// (per-provider shell var name), per-provider static-route section,
/// and the pre-commit address readback — spliced with the planner's
/// tokens in ONE substitution pass.
/// The vpn-node first-boot publisher script, byte-verbatim vs the
/// FIXED 1.x builder — sentinel tokens for the gated interpolations
/// (nak path, d_tag, region, price, listing JSON, relays, nsec).
/// NOTE: unlike the runtime-API VPN presets there is no transport
/// heredoc wrapper — the 1.x op IS this script directly.
pub(super) const VPN_NODE_FIRST_BOOT_SH: &str = concat!(
    "cat > /etc/vpn-listing.sh << 'SCRIPT'\n",
    "#!/bin/sh\n",
    "# Publish Europa listing on first boot\n",
    "NSEC_FILE=\"/etc/vpn-node/nsec\"\n",
    "WG_PUBKEY=$(wg show wg0 public-key 2>/dev/null)\n",
    "if [ -z \"$WG_PUBKEY\" ] || [ ! -f \"$NSEC_FILE\" ]; then\n",
    "    echo \"vpn-listing: missing wg0 pubkey or nsec, skipping\" >&2\n",
    "    exit 0\n",
    "fi\n",
    "NSEC=$(cat \"$NSEC_FILE\")\n",
    "__NAK__ event \\\n",
    "    -k 30402 \\\n",
    "    --sec \"$NSEC\" \\\n",
    "    -d \"__DTAG__\" \\\n",
    "    -t \"t=vpn-service\" \\\n",
    "    -t \"t=wireguard\" \\\n",
    "    -t \"protocol=wireguard\" \\\n",
    "    -t \"region=__COUNTRY__\" \\\n",
    "    -t \"price=__PRICE__\" \\\n",
    "    -c '__LISTING_JSON__' \\\n",
    "    __RELAYS__ 2>&1\n",
    "echo \"vpn-listing: published\"\n",
    "SCRIPT\n",
    "chmod +x /etc/vpn-listing.sh\n",
    "\n",
    "mkdir -p /etc/vpn-node\n",
    "echo '__NSEC__' > /etc/vpn-node/nsec\n",
    "chmod 600 /etc/vpn-node/nsec\n",
    "\n",
    "( sleep 30 && /etc/vpn-listing.sh > /tmp/vpn-listing.log 2>&1 ) &\n",
);

pub(super) fn plan_vpn_node(model: &DeviceModel, vn: &VpnNodeProfile) -> Result<Plan, Unsupported> {
    vn.validate()?;
    // single-pass: the nsec/relays/listing JSON are values, never
    // re-scanned (token-shaped payloads survive verbatim)
    let body = substitute_tokens(
        VPN_NODE_FIRST_BOOT_SH,
        &[
            ("__NAK__", vn.nak_path.as_str()),
            ("__DTAG__", vn.d_tag.as_str()),
            ("__COUNTRY__", vn.country.as_str()),
            (
                "__PRICE__",
                format!("{}sat/{}", vn.price_amount, vn.price_unit).as_str(),
            ),
            ("__LISTING_JSON__", vn.listing_json().as_str()),
            (
                "__RELAYS__",
                vn.relays.split(',').collect::<Vec<_>>().join(" ").as_str(),
            ),
            ("__NSEC__", vn.nsec.as_str()),
        ],
    );
    let mut ops: Vec<PlanOp> = ["wireguard-tools", "luci-proto-wireguard"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell { command: body });
    let verification = vec![
        VerificationCheck {
            description: "listing publisher installed and executable".into(),
            command: "test -x /etc/vpn-listing.sh && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "operator nsec file written".into(),
            command: "test -f /etc/vpn-node/nsec && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-node".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) const NORDVPN_IKE2_CA_PEM: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ\n",
    "MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2\n",
    "MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV\n",
    "BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI\n",
    "hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF\n",
    "kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr\n",
    "XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU\n",
    "eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV\n",
    "skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu\n",
    "MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA\n",
    "37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR\n",
    "hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s\n",
    "Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy\n",
    "WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6\n",
    "MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST\n",
    "LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG\n",
    "SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g\n",
    "nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/\n",
    "k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S\n",
    "DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/\n",
    "pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo\n",
    "k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp\n",
    "+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd\n",
    "NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa\n",
    "wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC\n",
    "VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S\n",
    "PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==\n",
    "-----END CERTIFICATE-----\n",
);

/// The IKEv2 swanctl connection config (byte-verbatim vs 1.x, with
/// sentinel tokens for the gated interpolations). Written to
/// /etc/swanctl/conf.d/nordvpn-ikev2.conf inside a quoted heredoc.
pub(super) const NORDVPN_IKE2_SWANCTL_SH: &str = concat!(
    "connections {\n",
    "  nordvpn {\n",
    "    version = 2\n",
    "    send_cert = never\n",
    "    local_addrs = %defaultroute\n",
    "    remote_addrs = __STATION__\n",
    "    proposals = aes256-sha256-modp2048, aes256-sha1-modp2048, aes128-sha256-modp2048\n",
    "    reauth_time = 0s\n",
    "    fragmentation = yes\n",
    "    mobike = yes\n",
    "    local {\n",
    "      auth = eap\n",
    "      eap_id = \"__USERNAME__\"\n",
    "    }\n",
    "    remote {\n",
    "      auth = pubkey\n",
    "      id = %any\n",
    "    }\n",
    "    vips = 0.0.0.0\n",
    "    dpd_delay = 60s\n",
    "    children {\n",
    "      nord {\n",
    "        remote_ts = 0.0.0.0/0\n",
    "        local_ts = dynamic\n",
    "        start_action = start\n",
    "        close_action = restart\n",
    "        esp_proposals = aes256-sha256, aes256-sha1, aes128-sha256\n",
    "        rekey_time = 3600s\n",
    "      }\n",
    "    }\n",
    "  }\n",
    "}\n",
    "secrets {\n",
    "  eap-nord {\n",
    "    secret = \"__PASSWORD__\"\n",
    "  }\n",
    "}",
);

pub(super) fn plan_vpn_nordvpn_ike2(
    model: &DeviceModel,
    i2: &VpnNordvpnIke2Profile,
) -> Result<Plan, Unsupported> {
    i2.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops: Vec<PlanOp> = [
        "strongswan",
        "strongswan-charon",
        "strongswan-swanctl",
        "strongswan-mod-aes",
        "strongswan-mod-sha1",
        "strongswan-mod-sha2",
        "strongswan-mod-gmp",
        "strongswan-mod-hmac",
        "strongswan-mod-pubkey",
        "strongswan-mod-x509",
        "strongswan-mod-pem",
        "strongswan-mod-random",
        "strongswan-mod-nonce",
        "strongswan-mod-eap-identity",
        "strongswan-mod-eap-mschapv2",
        "strongswan-mod-md4",
        "strongswan-mod-kernel-netlink",
        "strongswan-mod-updown",
        "strongswan-mod-attr",
        "strongswan-mod-openssl",
        "strongswan-mod-socket-default",
        "kmod-ipsec4",
        "kmod-xfrm-interface",
        "kmod-nft-xfrm",
    ]
    .iter()
    .map(|name| PlanOp::EnsurePackage {
        name: (*name).into(),
    })
    .collect();
    // hw_accel branch: true = modprobe the EIP-93; false = rmmod +
    // blacklist before any SA exists (with live references it wedges
    // the kernel — AGENTS.md; the 1.x hardware lessons)
    let hw_block = if i2.hw_accel {
        "modprobe crypto_hw_eip93 2>/dev/null || true\n".to_string()
    } else {
        concat!(
            "rmmod crypto_hw_eip93 2>/dev/null || true\n",
            "mkdir -p /etc/modprobe.d\n",
            "echo 'blacklist crypto_hw_eip93' > /etc/modprobe.d/no-eip93.conf\n",
        )
        .to_string()
    };
    let hw_echo = if i2.hw_accel { "on" } else { "off" };
    let swanctl = substitute_tokens(
        NORDVPN_IKE2_SWANCTL_SH,
        &[
            ("__STATION__", i2.station.as_str()),
            ("__USERNAME__", i2.username.as_str()),
            ("__PASSWORD__", i2.password.as_str()),
        ],
    );
    let bringup = "( sleep 8; /usr/lib/ipsec/charon >/dev/null 2>&1; ) &\n\
                   ( sleep 20; swanctl --load-all >/dev/null 2>&1; \
                    swanctl --initiate --child nord >/dev/null 2>&1; ) &";
    // transport script body, line-by-line for byte fidelity with the
    // FIXED 1.x builder (golden: tests/goldens/vpn-nordvpn-ikev2.sh)
    let mut body = String::new();
    body.push_str("# --- NordVPN IKEv2 (strongSwan, EAP-MSCHAPv2) ---\n");
    body.push_str(&hw_block);
    body.push('\n');
    body.push_str("mkdir -p /var/ipsec /etc/swanctl/conf.d /etc/swanctl/x509ca\n\n");
    // printf with shell-escaped \n sequences (literal backslash-n, not
    // actual newlines — the golden bytes)
    body.push_str(
        "printf 'charon {\\n  install_routes = yes\\n}\\n' > /var/ipsec/strongswan.conf\n\n",
    );
    body.push_str("cat > /etc/swanctl/x509ca/nordvpn.pem << 'NORD_CA_EOF'\n");
    body.push_str(NORDVPN_IKE2_CA_PEM);
    body.push_str("NORD_CA_EOF\n\n");
    body.push_str("cat > /etc/swanctl/conf.d/nordvpn-ikev2.conf << 'NORD_SWAN_EOF'\n");
    body.push_str(&swanctl);
    body.push('\n');
    body.push_str("NORD_SWAN_EOF\n\n");
    body.push_str("chmod 600 /etc/swanctl/conf.d/nordvpn-ikev2.conf\n\n");
    body.push_str("# charon is not under procd here: start it from rc.local after the network\n");
    body.push_str(
        "grep -q 'nordvpn-ikev2-charon' /etc/rc.local 2>/dev/null || \
         cat >> /etc/rc.local << 'NORD_RC_EOF'\n",
    );
    body.push_str("# nordvpn-ikev2-charon\n");
    body.push_str(bringup);
    body.push('\n');
    body.push_str("NORD_RC_EOF\n\n");
    body.push_str("# also bring it up right now (first boot)\n");
    body.push_str(bringup);
    body.push('\n');
    body.push_str(&format!(
        "echo \"NordVPN IKEv2 staged: server {} ({}), hw_accel={}\"",
        i2.hostname, i2.station, hw_echo
    ));
    let payload = format!(
        "cat > /tmp/nordvpn_ikev2_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/nordvpn_ikev2_setup.sh",
        body.trim_end()
    );
    ops.push(PlanOp::Shell { command: payload });
    // firewall block inline (ikev2 does NOT use the shared verify
    // tail — charon bring-up is rc.local-based; the zone rides the
    // ipsec0 logical interface)
    for pattern in [
        "name='vpn'",
        "dest='vpn'",
        "name='KillSwitch-Reject-NonVPN'",
        "name='Allow-VPN-Management'",
    ] {
        ops.push(PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: pattern.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_zone".into(),
        section_type: "zone".into(),
        options: vec![
            ("name".into(), literal("vpn".into())),
            ("input".into(), literal("REJECT".into())),
            ("output".into(), literal("ACCEPT".into())),
            ("forward".into(), literal("REJECT".into())),
            ("masq".into(), literal("1".into())),
            ("mtu_fix".into(), literal("1".into())),
            ("network".into(), literal("ipsec0".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_fwd".into(),
        section_type: "forwarding".into(),
        options: vec![
            ("src".into(), literal("lan".into())),
            ("dest".into(), literal("vpn".into())),
        ],
    });
    if i2.allow_management {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_mgmt".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("Allow-VPN-Management".into())),
                ("src".into(), literal("vpn".into())),
                ("proto".into(), literal("tcp".into())),
                ("dest_port".into(), literal("22 80 443".into())),
                ("target".into(), literal("ACCEPT".into())),
            ],
        });
    }
    if i2.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_killswitch".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("KillSwitch-Reject-NonVPN".into())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("proto".into(), literal("all".into())),
                ("target".into(), literal("REJECT".into())),
            ],
        });
    }
    ops.push(PlanOp::Shell {
        command: "nft add rule inet fw4 input_wan udp dport { 500, 4500 } accept comment 'IKE/NAT-T' 2>/dev/null; \
                  nft add rule inet fw4 input_wan meta l4proto esp accept comment 'ESP' 2>/dev/null; true"
            .into(),
    });
    for dns in ["103.86.96.100", "103.86.99.100"] {
        ops.push(PlanOp::Shell {
            command: format!("uci del_list dhcp.@dnsmasq[0].server='{dns}' 2>/dev/null; true"),
        });
        ops.push(PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: dns.into(),
        });
    }
    ops.push(PlanOp::Shell {
        command: "uci set dhcp.@dnsmasq[0].noresolv='1'".into(),
    });
    let verification = vec![
        VerificationCheck {
            description: "swanctl config present".into(),
            command: "test -f /etc/swanctl/conf.d/nordvpn-ikev2.conf && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "NordVPN CA certificate installed".into(),
            command: "test -f /etc/swanctl/x509ca/nordvpn.pem && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-nordvpn-ikev2".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// The openperf-client STA autostart procd init script (static — no
/// interpolations; the SSID lands only in the uci loops below).
pub(super) const OPENPERF_CLIENT_INITD_SH: &str = concat!(
    "cat > /etc/init.d/openperf-autostart << 'OPENPERF_EOF'\n",
    "#!/bin/sh /etc/rc.common\n",
    "USE_PROCD=1\n",
    "START=98\n",
    "STOP=1\n",
    "\n",
    "start_service() {\n",
    "    procd_open_instance\n",
    "    procd_set_param respawn 3600 5 0\n",
    "    procd_set_param env AP_IP=\n",
    "    procd_set_param command /usr/bin/python3 /root/openperf/sta_autostart.py\n",
    "    procd_set_param stdout 1\n",
    "    procd_set_param stderr 1\n",
    "    procd_close_instance\n",
    "}\n",
    "OPENPERF_EOF\n",
    "chmod +x /etc/init.d/openperf-autostart",
);

/// The openperf-server procd init script (PORT token).
pub(super) const OPENPERF_SERVER_INITD_SH: &str = concat!(
    "cat > /etc/init.d/openperf-server << 'OPENPERF_EOF'\n",
    "#!/bin/sh /etc/rc.common\n",
    "USE_PROCD=1\n",
    "START=99\n",
    "STOP=1\n",
    "\n",
    "start_service() {\n",
    "    procd_open_instance\n",
    "    procd_set_param respawn 3600 5 0\n",
    "    procd_set_param command /usr/bin/python3 /root/openperf/server.py\n",
    "    procd_set_param stdout 1\n",
    "    procd_set_param stderr 1\n",
    "    procd_set_param env PORT=__PORT__\n",
    "    procd_close_instance\n",
    "}\n",
    "OPENPERF_EOF\n",
    "chmod +x /etc/init.d/openperf-server",
);

pub(super) fn plan_openperf_client(
    model: &DeviceModel,
    oc: &OpenPerfClientProfile,
) -> Result<Plan, Unsupported> {
    oc.validate()?;
    let mut ops: Vec<PlanOp> = ["python3", "iperf3"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell {
        command: "mkdir -p /root/openperf/init.d".into(),
    });
    ops.push(PlanOp::Shell {
        command: OPENPERF_CLIENT_INITD_SH.into(),
    });
    // STA config loop — SSID lands in single-quoted uci values
    ops.push(PlanOp::Shell {
        command: [
            "for iface in sta_radio0 phy0_sta; do".to_string(),
            "    if uci -q get wireless.$iface >/dev/null 2>&1; then".to_string(),
            format!("        uci set wireless.$iface.ssid='{}'", oc.mgmt_ssid),
            "        uci set wireless.$iface.encryption='none'".to_string(),
            "        uci set wireless.$iface.network='wan'".to_string(),
            "        break".to_string(),
            "    fi".to_string(),
            "done".to_string(),
        ]
        .join("\n"),
    });
    // HaHalow STA loop — the -halow SSID variant
    ops.push(PlanOp::Shell {
        command: [
            "for iface in default_radio1; do".to_string(),
            "    if uci -q get wireless.$iface >/dev/null 2>&1; then".to_string(),
            format!(
                "        uci set wireless.$iface.ssid='{}-halow'",
                oc.mgmt_ssid
            ),
            "        uci set wireless.$iface.encryption='sae'".to_string(),
            "        uci set wireless.$iface.key='openperf-test'".to_string(),
            "        break".to_string(),
            "    fi".to_string(),
            "done".to_string(),
        ]
        .join("\n"),
    });
    ops.push(PlanOp::CommitUci {
        config: "wireless".into(),
    });
    ops.push(PlanOp::Service {
        name: "openperf-autostart".into(),
        action: ServiceAction::Enable,
    });
    let verification = vec![VerificationCheck {
        description: "STA autostart service enabled".into(),
        command: "/etc/init.d/openperf-autostart enabled && echo yes".into(),
        expect_contains: "yes".into(),
    }];
    Ok(Plan {
        profile_id: "openperf_client".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_openperf_server(
    model: &DeviceModel,
    os: &OpenPerfServerProfile,
) -> Result<Plan, Unsupported> {
    os.validate()?;
    let mut ops: Vec<PlanOp> = ["python3", "iperf3"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell {
        command: "mkdir -p /root/openperf/init.d".into(),
    });
    ops.push(PlanOp::Shell {
        command: substitute_tokens(
            OPENPERF_SERVER_INITD_SH,
            &[("__PORT__", os.port.to_string().as_str())],
        ),
    });
    // AP config loop — SSID lands in single-quoted uci values
    ops.push(PlanOp::Shell {
        command: [
            "for iface in phy0-ap0 default_radio0; do".to_string(),
            "    if uci -q get wireless.$iface >/dev/null 2>&1; then".to_string(),
            format!("        uci set wireless.$iface.ssid='{}'", os.mgmt_ssid),
            "        uci set wireless.$iface.encryption='none'".to_string(),
            "        break".to_string(),
            "    fi".to_string(),
            "done".to_string(),
        ]
        .join("\n"),
    });
    // HaHalow AP loop
    ops.push(PlanOp::Shell {
        command: [
            "for iface in default_radio1; do".to_string(),
            "    if uci -q get wireless.$iface >/dev/null 2>&1; then".to_string(),
            format!(
                "        uci set wireless.$iface.ssid='{}-halow'",
                os.mgmt_ssid
            ),
            "        uci set wireless.$iface.encryption='sae'".to_string(),
            "        uci set wireless.$iface.key='openperf-test'".to_string(),
            "        break".to_string(),
            "    fi".to_string(),
            "done".to_string(),
        ]
        .join("\n"),
    });
    ops.push(PlanOp::CommitUci {
        config: "wireless".into(),
    });
    ops.push(PlanOp::Service {
        name: "openperf-server".into(),
        action: ServiceAction::Enable,
    });
    let verification = vec![VerificationCheck {
        description: "server service enabled".into(),
        command: "/etc/init.d/openperf-server enabled && echo yes".into(),
        expect_contains: "yes".into(),
    }];
    Ok(Plan {
        profile_id: "openperf_server".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// The shared 30s wg-handshake fail-open verify tail (base.py parity).
pub(super) const VERIFY_WG_30S: &str = "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart";

pub(super) fn runtime_api_vpn_body(
    body_const: &str,
    wg_priv_var: &str,
    route_section: &str,
    readback_provider: &str,
    iface: &str,
    gateway: &str,
    extra_tokens: &[(&str, &str)],
) -> String {
    let mut pairs: Vec<(String, String)> = extra_tokens
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    pairs.push(("__WG_PRIV__".into(), wg_priv_var.to_string()));
    pairs.push(("__IFACE__".into(), iface.to_string()));
    pairs.push(("__GATEWAY__".into(), gateway.to_string()));
    let route = route_block(route_section);
    let readback = readback_block(readback_provider);
    // assemble then single-pass substitute everything at once — the
    // shared JSON helper always leads the script (1.x composition)
    let mut template = VPN_JSON_HELPER_SH.to_string();
    template.push_str(body_const);
    template.push_str(WG_STANZA_SH);
    template.push('\n');
    template.push_str(&route);
    template.push_str("\n\n");
    template.push_str(&readback);
    let refs: Vec<(&str, &str)> = pairs
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    substitute_tokens(&template, &refs)
}

pub(super) fn plan_vpn_ivpn(model: &DeviceModel, iv: &VpnIvpnProfile) -> Result<Plan, Unsupported> {
    iv.validate()?;
    let body = runtime_api_vpn_body(
        IVPN_WG_BODY_SH,
        "$IVPN_PRIV",
        "ivpn_server_route",
        "IVPN",
        &iv.upstream_iface,
        &iv.upstream_gateway,
        &[("__ACCOUNT__", iv.account_id.as_str())],
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::RevertUci {
            config: "network".into(),
        },
        PlanOp::RevertUci {
            config: "firewall".into(),
        },
        PlanOp::RevertUci {
            config: "dhcp".into(),
        },
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["10.0.0.53"],
        iv.kill_switch,
        true,
        VERIFY_WG_30S,
    );
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface configured".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "wg0 handshake observed (tunnel actually up)".into(),
            command: "wg show wg0 2>/dev/null | grep -q 'latest handshake' && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-ivpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_vpn_mullvad(
    model: &DeviceModel,
    mu: &VpnMullvadProfile,
) -> Result<Plan, Unsupported> {
    mu.validate()?;
    let country_filter = if mu.country.is_empty() {
        String::new()
    } else {
        format!("\"country_code\":\"{}\"", mu.country)
    };
    let body = runtime_api_vpn_body(
        MULLVAD_WG_BODY_SH,
        "$MULLVAD_PRIV",
        "mullvad_server_route",
        "Mullvad",
        &mu.upstream_iface,
        &mu.upstream_gateway,
        &[
            ("__TOKEN__", mu.account_token.as_str()),
            ("__COUNTRY_FILTER__", country_filter.as_str()),
            ("__COUNTRY__", mu.country.as_str()),
        ],
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::RevertUci {
            config: "network".into(),
        },
        PlanOp::RevertUci {
            config: "firewall".into(),
        },
        PlanOp::RevertUci {
            config: "dhcp".into(),
        },
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["10.64.0.1"],
        mu.kill_switch,
        true,
        VERIFY_WG_30S,
    );
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface configured".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "wg0 handshake observed (tunnel actually up)".into(),
            command: "wg show wg0 2>/dev/null | grep -q 'latest handshake' && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-mullvad".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_vpn_surfshark(
    model: &DeviceModel,
    ss: &VpnSurfsharkProfile,
) -> Result<Plan, Unsupported> {
    ss.validate()?;
    // creds/country/gateway ride the script text verbatim — the
    // validate() charset gates are what make every interpolation a
    // safe payload (no quoting needed, 1.x bytes preserved)
    let country_filter = if ss.country.is_empty() {
        String::new()
    } else {
        format!("country/{}/", ss.country)
    };
    let body = format!(
        "{}{}",
        VPN_JSON_HELPER_SH,
        substitute_tokens(
            SURFSHARK_WG_BODY_SH,
            &[
                ("__USERNAME__", ss.username.as_str()),
                ("__PASSWORD__", ss.password.as_str()),
                ("__COUNTRY_FILTER__", country_filter.as_str()),
                ("__COUNTRY__", ss.country.as_str()),
                ("__IFACE__", ss.upstream_iface.as_str()),
                ("__GATEWAY__", ss.upstream_gateway.as_str()),
            ],
        ),
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    // Clean baseline (AGENTS.md, Codex #604 P1 round 4): aborted runs
    // leave /tmp/.uci staging debris — revert before staging so the
    // later commits cannot make unrelated changes permanent.
    let mut ops = vec![
        PlanOp::RevertUci {
            config: "network".into(),
        },
        PlanOp::RevertUci {
            config: "firewall".into(),
        },
        PlanOp::RevertUci {
            config: "dhcp".into(),
        },
        // runtime-API script needs wg tooling + kmod on vanilla images
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        // the script authenticates via curl (Codex #604 P2) — not in
        // every base image
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared composition (zone on wg0, management on) + Surfshark DNS
    // pair in the 1.x order + the 30s wg handshake verify tail
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["162.252.172.57", "149.154.159.92"],
        ss.kill_switch,
        true,
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface configured".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "wg0 handshake observed (tunnel actually up)".into(),
            command: "wg show wg0 2>/dev/null | grep -q 'latest handshake' && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-surfshark".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) const PIA_WG_BODY_SH: &str = concat!(
    "\n",
    "# Generate WireGuard keypair\n",
    "wg genkey > /tmp/vpn_private.key\n",
    "wg pubkey < /tmp/vpn_private.key > /tmp/vpn_public.key\n",
    "chmod 600 /tmp/vpn_private.key\n",
    "\n",
    "\n",
    "# Authenticate with PIA — get auth token\n",
    "curl -fs -m 15 -u __CREDS__ \\\n",
    "    \"https://www.privateinternetaccess.com/gtoken/generateToken\" \\\n",
    "    -o /tmp/vpn_token.json\n",
    "PIA_TOKEN=$(cat /tmp/vpn_token.json | json_get token)\n",
    "[ -n \"$PIA_TOKEN\" ] || { echo 'PIA: auth failed — no token in API response'; exit 1; }\n",
    "\n",
    "# URL-encode token: PIA tokens contain +, /, = that break curl\n",
    "ENC_TOKEN=$(echo \"$PIA_TOKEN\" | sed 's/+/%2B/g; s/=/%3D/g; s|/|%2F|g')\n",
    "\n",
    "WG_PUB=$(cat /tmp/vpn_public.key)\n",
    "\n",
    "# Register WG key with regional server\n",
    "curl -fs -m 15 -k \\\n",
    "    \"https://__REGION__.privacy.network:1337/addKey?pt=${ENC_TOKEN}&pubkey=${WG_PUB}\" \\\n",
    "    -o /tmp/vpn_addkey.json\n",
    "\n",
    "# Parse server response\n",
    "SERVER_KEY=$(cat /tmp/vpn_addkey.json | json_get server_key)\n",
    "SERVER_IP=$(cat /tmp/vpn_addkey.json | json_get server_ip)\n",
    "SERVER_PORT=$(cat /tmp/vpn_addkey.json | json_get server_port)\n",
    "PEER_IP=$(cat /tmp/vpn_addkey.json | json_get peer_ip)\n",
    "# Abort BEFORE the destructive wg0 cleanup unless the response is complete\n",
    "[ -n \"$SERVER_KEY\" ] && [ -n \"$SERVER_IP\" ] && [ -n \"$SERVER_PORT\" ] && [ -n \"$PEER_IP\" ] \\\n",
    "    || { echo 'PIA: addKey response incomplete — aborting before wg0 cleanup'; exit 1; }\n",
    "\n",
    "# Clean up old WireGuard interface + peers\n",
    "uci -q delete network.wg0\n",
    "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
    "    uci delete network.@wireguard_wg0[0]\n",
    "done\n",
    "\n",
    "\n",
    "PIA_PRIV=$(cat /tmp/vpn_private.key)\n",
    "\n",
    "uci set network.wg0=interface\n",
    "uci set network.wg0.proto='wireguard'\n",
    "uci set network.wg0.private_key=\"$PIA_PRIV\"\n",
    "uci set network.wg0.listen_port='51820'\n",
    "uci add_list network.wg0.addresses=\"${PEER_IP}/32\"\n",
    "uci set network.wg0.mtu='1280'\n",
    "uci set network.wg0.auto='1'\n",
    "\n",
    "uci add network wireguard_wg0\n",
    "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_IP\"\n",
    "uci set network.@wireguard_wg0[0].endpoint_port=\"$SERVER_PORT\"\n",
    "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
    "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
    "uci set network.@wireguard_wg0[0].persistent_keepalive='25'\n",
    "\n",
    "# Static route: prevent circular routing through VPN tunnel\n",
    "uci -q delete network.pia_server_route\n",
    "uci set network.pia_server_route=route\n",
    "uci set network.pia_server_route.interface='__IFACE__'\n",
    "uci set network.pia_server_route.target=\"${SERVER_IP}\"\n",
    "uci set network.pia_server_route.netmask='255.255.255.255'\n",
    "uci set network.pia_server_route.gateway='__GATEWAY__'\n",
);

pub(super) fn plan_vpn_pia(model: &DeviceModel, pia: &VpnPiaProfile) -> Result<Plan, Unsupported> {
    pia.validate()?;
    // creds ride sh-quoted into `curl -u` (1.x sh_quote parity — the
    // same escaping render_shell uses for uci literals); the body is
    // the verbatim 1.x script with sentinel tokens for the four
    // interpolations (validate()'s gates make them payload-safe).
    // Single-pass substitution: chained `.replace()` would rewrite
    // token-shaped payloads inside the quoted creds (the surfshark
    // #604-P2 class, applied here by the hardening audit).
    let creds = shell_quote(&format!("{}:{}", pia.username, pia.password));
    let body = format!(
        "{}{}",
        VPN_JSON_HELPER_SH,
        substitute_tokens(
            PIA_WG_BODY_SH,
            &[
                ("__CREDS__", creds.as_str()),
                ("__REGION__", pia.region.as_str()),
                ("__IFACE__", pia.upstream_iface.as_str()),
                ("__GATEWAY__", pia.upstream_gateway.as_str()),
            ],
        ),
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        // runtime-API script needs wg tooling + kmod on vanilla images
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        // the script's first act is `curl -u` auth (hardening audit:
        // the surfshark #604-P2 gap, same class here) — not in every
        // base image
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared composition + the 30s wg handshake verify TAIL; PIA DNS
    // pair in the 1.x order (243 first)
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["10.0.0.243", "10.0.0.242"],
        pia.kill_switch,
        pia.allow_management,
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface configured".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "wg0 handshake observed (tunnel actually up)".into(),
            command: "wg show wg0 2>/dev/null | grep -q 'latest handshake' && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-pia".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// 1.x `shell_safe::WIFI_ENCRYPTIONS`.
pub const WIFI_ENCRYPTIONS: &[&str] = &[
    "none",
    "psk",
    "psk2",
    "psk3",
    "sae",
    "sae-mixed",
    "owe",
    "mixed-psk",
    "psk-mixed",
];

/// 1.x `shell_safe::WIFI_BANDS`.
pub const WIFI_BANDS: &[&str] = &["2.4ghz", "5ghz", "5ghz-low", "5ghz-high", "6ghz"];

pub(super) fn plan_doh(model: &DeviceModel, doh: &DohProfile) -> Result<Plan, Unsupported> {
    doh.validate()?;
    let url = doh.resolver_url().to_string();
    let port = doh.listen_port;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "https-dns-proxy".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-https-dns-proxy".into(),
        },
        PlanOp::ResetUciConfig {
            config: "https-dns-proxy".into(),
        },
        PlanOp::SetUciSection {
            config: "https-dns-proxy".into(),
            section: "main".into(),
            section_type: "https_dns_proxy".into(),
            options: vec![
                ("bootstrap_dns".into(), literal("1.1.1.1,8.8.8.8".into())),
                ("listen_addr".into(), literal("127.0.0.1".into())),
                ("listen_port".into(), literal(port.to_string())),
                ("resolver_url".into(), literal(url.clone())),
            ],
        },
        PlanOp::CommitUci {
            config: "https-dns-proxy".into(),
        },
        PlanOp::Service {
            name: "https-dns-proxy".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "https-dns-proxy".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::SetUciOptions {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            options: vec![("noresolv".into(), literal("1".into()))],
        },
        PlanOp::UciDeleteOption {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
        },
        PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: format!("127.0.0.1#{port}"),
        },
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        PlanOp::Service {
            name: "dnsmasq".into(),
            action: ServiceAction::Restart,
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "resolver URL persisted exactly".into(),
            command: format!(
                "test \"$(uci -q get https-dns-proxy.main.resolver_url)\" = {url_q} && echo ok",
                url_q = shell_quote(&url)
            ),
            expect_contains: "ok".into(),
        },
        VerificationCheck {
            description: "dnsmasq forwards to the local proxy".into(),
            command: format!(
                "uci -q get dhcp.@dnsmasq[0].server | grep -qx {entry} && echo ok",
                entry = shell_quote(&format!("127.0.0.1#{port}"))
            ),
            expect_contains: "ok".into(),
        },
        VerificationCheck {
            description: "proxy enabled at boot".into(),
            command: "/etc/init.d/https-dns-proxy enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    // 1.x parity: trailing informational line (doh.py final status echo).
    ops.push(PlanOp::Shell {
        command: format!("echo \"DoH configured: {} on port {port}\"", doh.provider),
    });
    Ok(Plan {
        profile_id: "doh".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// Single-quote a literal for POSIX shells (`'` → `'\''`).
pub(super) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\''"))
}

// ---- tether (1.x `scripts/use_cases/usb_tether.py`, verbatim ports) ----

/// 1.x `uci_add_to_wan_zone_sh` (scripts/profile/uci_helpers.py):
/// idempotent `wan`-zone membership by zone NAME (not index) — del_list
/// then add_list on the zone named `wan`, del_list everywhere else. The
/// body is guarded by an explicit `if` because the earlier
/// `[ ... = 'wan' ] && ...; break` form ran `add_list` on the FIRST
/// zone regardless of name (1.x comment, kept true here).
pub(super) fn uci_add_to_wan_zone_sh(iface: &str) -> String {
    format!(
        "for _z in $(uci show firewall 2>/dev/null | grep '=zone' \
         | cut -d. -f2 | cut -d= -f1 || true); do \
         if [ \"$(uci -q get firewall.\"$_z\".name)\" = 'wan' ]; then \
         uci -q del_list firewall.\"$_z\".network='{iface}' 2>/dev/null; \
         uci add_list firewall.\"$_z\".network='{iface}'; \
         else \
         uci -q del_list firewall.\"$_z\".network='{iface}' 2>/dev/null; \
         fi; \
         done; true"
    )
}

/// 1.x `_detect_usb_net_device`: walk `/sys/class/net` until a device
/// bound to one of the tethering drivers appears (BRE `\|` alternation),
/// falling back to `usb0`/`usb1` existence.
pub(super) fn tether_detect_script(match_android: bool, match_ios: bool, timeout: u32) -> String {
    let mut drivers: Vec<&str> = Vec::new();
    if match_android {
        drivers.extend(["rndis", "cdc_ether", "cdc_ncm", "usbnet"]);
    }
    if match_ios {
        drivers.push("ipheth");
    }
    let driver_pattern = drivers.join("\\|");
    let mut s = String::new();
    s.push_str("USB_DEV=\"\"\n");
    s.push_str(&format!("for _ in $(seq 1 {timeout}); do\n"));
    s.push_str("for dev in /sys/class/net/*; do\n");
    s.push_str("name=$(basename \"$dev\")\n");
    s.push_str("case \"$name\" in\n");
    s.push_str("lo|br-lan|eth0|wlan*) continue ;;\n");
    s.push_str("esac\n");
    s.push_str("driver=$(readlink \"$dev/device/driver\" 2>/dev/null || true)\n");
    s.push_str(&format!(
        "if echo \"$driver\" | grep -qi \"{driver_pattern}\"; then\n"
    ));
    s.push_str("USB_DEV=\"$name\"\n");
    s.push_str("break 2\n");
    s.push_str("fi\n");
    if match_ios {
        s.push_str("iface_desc=\"\"\n");
        s.push_str(
            "[ -e \"$dev/device/interface\" ] && \
             iface_desc=$(cat \"$dev/device/interface\" 2>/dev/null || true)\n",
        );
        s.push_str("if echo \"$iface_desc\" | grep -qi \"apple\\|iphone\"; then\n");
        s.push_str("USB_DEV=\"$name\"\n");
        s.push_str("break 2\n");
        s.push_str("fi\n");
    }
    s.push_str("done\n");
    s.push_str("sleep 1\n");
    s.push_str("done\n");
    s.push_str("if [ -z \"$USB_DEV\" ]; then\n");
    s.push_str("for cand in usb0 usb1; do\n");
    s.push_str("[ -e \"/sys/class/net/$cand\" ] && USB_DEV=\"$cand\" && break\n");
    s.push_str("done\n");
    s.push_str("fi\n");
    s
}

/// 1.x `_setup_interface`: create the DHCP interface on the discovered
/// `$USB_DEV`, join it to the `wan` zone, commit, and bring it up. Runs
/// only when a USB network device was found.
pub(super) fn tether_setup_interface(iface: &str) -> String {
    let mut s = String::new();
    s.push_str("if [ -n \"$USB_DEV\" ]; then\n");
    s.push_str(&format!("uci set network.{iface}=interface\n"));
    s.push_str(&format!("uci set network.{iface}.proto='dhcp'\n"));
    s.push_str(&format!("uci set network.{iface}.device=\"$USB_DEV\"\n"));
    s.push_str(&format!("uci set network.{iface}.metric='20'\n"));
    s.push_str(&uci_add_to_wan_zone_sh(iface));
    s.push('\n');
    s.push_str("uci commit network\n");
    s.push_str("uci commit firewall\n");
    s.push_str(&format!("ifup {iface} 2>/dev/null || true\n"));
    s.push_str(&format!(
        "echo \"USB tethering enabled on $USB_DEV -> {iface}\"\n"
    ));
    s.push_str("else\n");
    s.push_str("echo \"USB tethering: no USB network device found, skipping\" >&2\n");
    s.push_str("fi\n");
    s
}

pub(super) fn tether_start_usbmuxd() -> &'static str {
    "/usr/sbin/usbmuxd -v -U -f >/dev/null 2>&1 &\n"
}

/// 1.x `_adb_hotplug_script` (raw string, byte-for-byte). Two enablement
/// methods per USB bind with exponential backoff: `svc usb setFunctions
/// rndis` (Android ≤ 12) and UI automation — Android 14+ rejects
/// privileged tethering APIs from plain adb shell, but uiautomator dump +
/// `input tap` simulate a user toggling the switch (Pixel 10 / Android
/// 15, field-verified 2026-10-01). Installed as a hotplug hook; the
/// heredoc body reassembles because consecutive `Shell` ops render as
/// adjacent lines.
pub(super) fn tether_adb_hotplug_script() -> &'static str {
    // The 1.x source is a Python RAW string whose first line is a lone
    // `\` — 1.x renders it as its own script line (a shell line
    // continuation, harmless), and byte parity keeps it.
    "\\\n\
mkdir -p /etc/hotplug.d/usb
cat > /etc/hotplug.d/usb/99-usb-tether-adb << 'HOTPLUG_EOF'
[ \"$ACTION\" = \"bind\" ] || exit 0
[ \"$PRODUCT\" ] || exit 0
(
HOME=/root
export HOME
command -v adb >/dev/null 2>&1 || exit 0
DELAY=1
attempt=0
while [ $attempt -lt 7 ]; do
    attempt=$((attempt + 1))
    sleep $DELAY
    if ip addr show usb0 2>/dev/null | grep -q \"inet \"; then
        exit 0
    fi
    STATE=$(adb get-state 2>/dev/null)
    if [ \"$STATE\" = \"device\" ]; then
        adb shell svc usb setFunctions rndis 2>/dev/null
        sleep 3
        if ip addr show usb0 2>/dev/null | grep -q \"inet \"; then
            logger -t usb-tether \"ADB svc enabled tethering (attempt $attempt)\"
            exit 0
        fi
        adb shell input keyevent KEYCODE_WAKEUP 2>/dev/null
        sleep 1
        adb shell am start -a android.settings.TETHER_SETTINGS 2>/dev/null
        sleep 3
        adb shell uiautomator dump /sdcard/ui.xml 2>/dev/null
        UI=$(adb shell cat /sdcard/ui.xml 2>/dev/null)
        USB_ROW=$(echo \"$UI\" | grep -oE 'USB.tethering[^>]*bounds=\"\\[[0-9]+,[0-9]+' | grep -oE '[0-9]+,[0-9]+' | head -1)
        USB_Y=$(echo \"$USB_ROW\" | cut -d, -f2)
        if [ -n \"$USB_Y\" ]; then
            USB_Y_CENTER=$((USB_Y + 28))
            SWITCH=$(echo \"$UI\" | grep -oE \"Switch[^>]*bounds=\\\"\\[[0-9]+,${USB_Y_CENTER}\" | grep -oE '\\[[0-9]+,' | grep -oE '[0-9]+' | head -1)
            if [ -n \"$SWITCH\" ]; then
                SWITCH_CENTER=$((SWITCH + 65))
                adb shell input tap $SWITCH_CENTER $USB_Y_CENTER 2>/dev/null
                sleep 3
                if ip addr show usb0 2>/dev/null | grep -q \"inet \"; then
                    logger -t usb-tether \"ADB UI toggle enabled tethering (attempt $attempt)\"
                    exit 0
                fi
            fi
        fi
    fi
    DELAY=$((DELAY * 2))
done
logger -t usb-tether \"ADB tethering gave up after $attempt attempts\"
) &
HOTPLUG_EOF
"
}

/// 1.x `_shell_lines_to_ops` shape: strip each line, drop empties
/// (BlankLine ops are cosmetic and filtered by the golden comparator).
pub(super) fn shell_lines(ops: &mut Vec<PlanOp>, text: &str) {
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            ops.push(PlanOp::Shell {
                command: line.into(),
            });
        }
    }
}

/// 1.x kill-switch tunnel verification (tail of the wireguard script):
/// if no WireGuard handshake appears within 30 s, the kill switch rule
/// is deleted so the site regains WAN (fail-open by design — 1.x
/// behavior).
pub(super) const WIREGUARD_KILLSWITCH_VERIFY: &str = "i=0; while [ $i -lt 30 ]; do \
if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then \
echo 'WG kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; \
echo 'WG kill-switch: tunnel failed \u{2014} removing kill switch to restore WAN'; \
uci delete firewall.wg_client_killswitch; uci commit firewall; fw4 restart";

/// Cashu VPN kill-switch guard — 1.x `cashu_vpn_client.py` post-apply
/// loop: wait up to 30 s for a handshake, else remove the kill switch so
/// the site regains WAN (fail-open by design, like the wireguard-client
/// guard above).
pub(super) const CASHU_VPN_KILLSWITCH_VERIFY: &str = "i=0; while [ $i -lt 30 ]; do \
if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then \
echo 'Cashu VPN kill-switch: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; \
echo 'Cashu VPN kill-switch: tunnel failed \u{2014} removing kill switch to restore WAN'; \
uci delete firewall.cashu_vpn_killswitch; uci commit firewall; fw4 restart";

pub(super) fn plan_tether(
    model: &DeviceModel,
    tether: &TetherProfile,
) -> Result<Plan, Unsupported> {
    tether.validate()?;
    let iface = &tether.interface;
    let mut ops: Vec<PlanOp> = tether
        .variant
        .packages()
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    let script = match tether.variant {
        TetherVariant::Auto => {
            format!(
                "{}{}\n{}\n{}",
                tether_start_usbmuxd(),
                tether_detect_script(true, true, tether.detect_timeout_secs),
                tether_setup_interface(iface),
                tether_adb_hotplug_script()
            )
        }
        TetherVariant::Android => format!(
            "{}\n{}\n",
            tether_detect_script(true, false, tether.detect_timeout_secs),
            tether_setup_interface(iface)
        ),
        TetherVariant::AndroidAdb => format!(
            "{}\n{}\n{}",
            tether_detect_script(true, false, tether.detect_timeout_secs),
            tether_setup_interface(iface),
            tether_adb_hotplug_script()
        ),
        TetherVariant::Ios => format!(
            "{}{}\n{}\n",
            tether_start_usbmuxd(),
            tether_detect_script(false, true, tether.detect_timeout_secs),
            tether_setup_interface(iface)
        ),
    };
    shell_lines(&mut ops, &script);

    // Verification is split by what is provable without USB hardware:
    // ADB-carrying variants install a hotplug hook (filesystem proof,
    // VM-checkable); the network.<iface> section only exists once a real
    // USB network device answers (hardware-gated).
    let verification = if matches!(
        tether.variant,
        TetherVariant::Auto | TetherVariant::AndroidAdb
    ) {
        vec![VerificationCheck {
            description: "ADB hotplug hook installed".into(),
            command: "test -f /etc/hotplug.d/usb/99-usb-tether-adb && echo yes".into(),
            expect_contains: "yes".into(),
        }]
    } else {
        vec![VerificationCheck {
            description: "USB WAN interface configured (hardware-gated)".into(),
            command: format!("uci -q get network.{iface}.proto"),
            expect_contains: "dhcp".into(),
        }]
    };
    Ok(Plan {
        profile_id: tether.variant.id().into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_wireguard_client(
    model: &DeviceModel,
    wg: &WireguardClientProfile,
) -> Result<Plan, Unsupported> {
    wg.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("wireguard".into())),
                ("private_key".into(), literal(wg.private_key.clone())),
                ("addresses".into(), literal(wg.address.clone())),
            ],
        },
    ];
    if !wg.dns.is_empty() {
        ops.push(PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "dns".into(),
            value: wg.dns.clone(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "network".into(),
        section: "wg0_peer".into(),
        section_type: "wireguard_wg0".into(),
        options: vec![
            ("public_key".into(), literal(wg.peer_public_key.clone())),
            ("endpoint_host".into(), literal(wg.endpoint_host.clone())),
            (
                "endpoint_port".into(),
                literal(wg.endpoint_port.to_string()),
            ),
            ("allowed_ips".into(), literal(wg.allowed_ips.clone())),
            ("route_allowed_ips".into(), literal("1".into())),
            ("persistent_keepalive".into(), literal("25".into())),
        ],
    });
    if !wg.peer_psk.is_empty() {
        ops.push(PlanOp::SetUciOptions {
            config: "network".into(),
            section: "wg0_peer".into(),
            options: vec![("preshared_key".into(), literal(wg.peer_psk.clone()))],
        });
    }
    // Named firewall sections + while-loop cleanup of stale anonymous
    // sections to prevent accumulation across reconfigure runs.
    ops.extend([
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "dest='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='KillSwitch-Reject-NonVPN'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_vpn".into(),
            section_type: "zone".into(),
            options: vec![
                ("name".into(), literal("vpn".into())),
                ("input".into(), literal("REJECT".into())),
                ("output".into(), literal("ACCEPT".into())),
                ("forward".into(), literal("REJECT".into())),
                ("masq".into(), literal("1".into())),
                ("mtu_fix".into(), literal("1".into())),
                ("network".into(), literal("wg0".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_fwd".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("vpn".into())),
            ],
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_client_killswitch".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("KillSwitch-Reject-NonVPN".into())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("proto".into(), literal("all".into())),
                ("target".into(), literal("REJECT".into())),
            ],
        });
    }
    ops.extend([
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo 'WireGuard client configured: {}:{}'",
                wg.endpoint_host, wg.endpoint_port
            ),
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::Shell {
            command: WIREGUARD_KILLSWITCH_VERIFY.into(),
        });
    }
    // The kill-switch rule is intentionally NOT verified post-apply: the
    // verify loop removes it when no handshake appears (fail-open).
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface persisted".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "peer endpoint persisted".into(),
            command: "uci -q get network.wg0_peer.endpoint_host".into(),
            expect_contains: wg.endpoint_host.clone(),
        },
        VerificationCheck {
            description: "peer public key persisted".into(),
            command: "uci -q get network.wg0_peer.public_key".into(),
            expect_contains: wg.peer_public_key.clone(),
        },
        // Same read-back class as the #524 P1 (caught in cashu-vpn,
        // fixed here too): the committed address must be read back.
        // green with an unnumbered interface.
        VerificationCheck {
            description: "tunnel address persisted".into(),
            command: "uci -q get network.wg0.addresses".into(),
            expect_contains: wg.address.clone(),
        },
    ];
    Ok(Plan {
        profile_id: "wireguard-client".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_wireguard_server(
    model: &DeviceModel,
    wg: &WireguardServerProfile,
) -> Result<Plan, Unsupported> {
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "qrencode".into(),
        },
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("wireguard".into())),
                ("private_key".into(), literal(wg.private_key.clone())),
                ("listen_port".into(), literal(wg.listen_port.to_string())),
            ],
        },
        PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "addresses".into(),
            value: wg.subnet.clone(),
        },
        PlanOp::Shell {
            command: "mkdir -p /etc/wireguard && \
                      wg show wg0 public-key > /etc/wireguard/server_public_key \
                      2>/dev/null || true"
                .into(),
        },
    ];
    if !wg.peer1_public_key.is_empty() {
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0_peer1".into(),
            section_type: "wireguard_wg0".into(),
            options: vec![
                ("public_key".into(), literal(wg.peer1_public_key.clone())),
                ("allowed_ips".into(), literal(wg.peer1_allowed_ips.clone())),
                ("route_allowed_ips".into(), literal("1".into())),
            ],
        });
        if !wg.peer1_psk.is_empty() {
            ops.push(PlanOp::SetUciOptions {
                config: "network".into(),
                section: "wg0_peer1".into(),
                options: vec![("preshared_key".into(), literal(wg.peer1_psk.clone()))],
            });
        }
    }
    // Named firewall sections + while-loop cleanup of stale anonymous
    // sections to prevent accumulation across reconfigure runs.
    ops.extend([
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='Allow-WireGuard'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_vpn".into(),
            section_type: "zone".into(),
            options: vec![
                ("name".into(), literal("vpn".into())),
                ("input".into(), literal("ACCEPT".into())),
                ("output".into(), literal("ACCEPT".into())),
                ("forward".into(), literal("REJECT".into())),
                ("masq".into(), literal("1".into())),
                ("mtu_fix".into(), literal("1".into())),
                ("network".into(), literal("wg0".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_fwd_lan".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("vpn".into())),
                ("dest".into(), literal("lan".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_fwd_wan".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("vpn".into())),
                ("dest".into(), literal("wan".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "wg_server_allow".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("Allow-WireGuard".into())),
                ("src".into(), literal("wan".into())),
                ("dest_port".into(), literal(wg.listen_port.to_string())),
                ("proto".into(), literal("udp".into())),
                ("target".into(), literal("ACCEPT".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"WireGuard server configured: port {}, subnet {}\"",
                wg.listen_port, wg.subnet
            ),
        },
    ]);
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface persisted".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "listen port persisted".into(),
            command: "uci -q get network.wg0.listen_port".into(),
            expect_contains: wg.listen_port.to_string(),
        },
        VerificationCheck {
            description: "wan allow rule persisted".into(),
            command: "uci -q get firewall.wg_server_allow.name".into(),
            expect_contains: "Allow-WireGuard".into(),
        },
    ];
    Ok(Plan {
        profile_id: "wireguard-server".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_cashu_vpn_client(
    model: &DeviceModel,
    wg: &CashuVpnClientProfile,
) -> Result<Plan, Unsupported> {
    wg.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::SetUciSection {
            config: "network".into(),
            section: "wg0".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("wireguard".into())),
                ("private_key".into(), literal(wg.private_key.clone())),
                ("addresses".into(), literal(wg.peer_ip.clone())),
            ],
        },
    ];
    for token in wg.dns.split(',').map(str::trim).filter(|t| !t.is_empty()) {
        ops.push(PlanOp::UciAddList {
            config: "network".into(),
            section: "wg0".into(),
            option: "dns".into(),
            value: token.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "network".into(),
        section: "wg0_peer".into(),
        section_type: "wireguard_wg0".into(),
        options: vec![
            ("public_key".into(), literal(wg.peer_public_key.clone())),
            ("endpoint_host".into(), literal(wg.server_host.clone())),
            ("endpoint_port".into(), literal(wg.server_port.to_string())),
            ("allowed_ips".into(), literal(wg.allowed_ips.clone())),
            ("route_allowed_ips".into(), literal("1".into())),
            ("persistent_keepalive".into(), literal("25".into())),
        ],
    });
    ops.extend([
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "dest='vpn'".into(),
        },
        PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: "name='KillSwitch-Reject-NonVPN'".into(),
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "cashu_vpn_zone".into(),
            section_type: "zone".into(),
            options: vec![
                ("name".into(), literal("vpn".into())),
                ("input".into(), literal("REJECT".into())),
                ("output".into(), literal("ACCEPT".into())),
                ("forward".into(), literal("REJECT".into())),
                ("masq".into(), literal("1".into())),
                ("mtu_fix".into(), literal("1".into())),
                ("network".into(), literal("wg0".into())),
            ],
        },
        PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "cashu_vpn_fwd".into(),
            section_type: "forwarding".into(),
            options: vec![
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("vpn".into())),
            ],
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "cashu_vpn_killswitch".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("KillSwitch-Reject-NonVPN".into())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("proto".into(), literal("all".into())),
                ("target".into(), literal("REJECT".into())),
            ],
        });
    }
    ops.extend([
        PlanOp::CommitUci {
            config: "network".into(),
        },
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo 'Cashu VPN client configured: {}:{} (peer_ip={})'",
                wg.server_host, wg.server_port, wg.peer_ip
            ),
        },
    ]);
    if wg.kill_switch {
        ops.push(PlanOp::Shell {
            command: CASHU_VPN_KILLSWITCH_VERIFY.into(),
        });
    }
    // The kill-switch rule is intentionally NOT verified post-apply: the
    // guard loop removes it when no handshake appears (fail-open).
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface persisted".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "peer endpoint persisted".into(),
            command: "uci -q get network.wg0_peer.endpoint_host".into(),
            expect_contains: wg.server_host.clone(),
        },
        VerificationCheck {
            description: "peer public key persisted".into(),
            command: "uci -q get network.wg0_peer.public_key".into(),
            expect_contains: wg.peer_public_key.clone(),
        },
        // Codex P1 (#524): the tunnel address was committed but never
        // read back — a failed/typo'd addresses value left the plan
        // green with an unnumbered interface.
        VerificationCheck {
            description: "tunnel address persisted".into(),
            command: "uci -q get network.wg0.addresses".into(),
            expect_contains: wg.peer_ip.clone(),
        },
    ];
    Ok(Plan {
        profile_id: "cashu-vpn-client".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_ssh_hardening(
    model: &DeviceModel,
    sh: &SshHardeningProfile,
) -> Result<Plan, Unsupported> {
    let pw_auth = if sh.disable_password_auth {
        "off"
    } else {
        "on"
    };
    let gateway_ports = if sh.restrict_gateway_ports {
        "no"
    } else {
        "yes"
    };
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::SetUciOptions {
            config: "dropbear".into(),
            section: "@dropbear[0]".into(),
            options: vec![
                ("PasswordAuth".into(), literal(pw_auth.into())),
                ("RootPasswordAuth".into(), literal(pw_auth.into())),
                ("Port".into(), literal(sh.port.to_string())),
                ("IdleTimeout".into(), literal(sh.idle_timeout.to_string())),
                (
                    "MaxAuthTries".into(),
                    literal(sh.max_auth_tries.to_string()),
                ),
                ("GatewayPorts".into(), literal(gateway_ports.into())),
            ],
        },
        PlanOp::CommitUci {
            config: "dropbear".into(),
        },
        PlanOp::Service {
            name: "dropbear".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"SSH hardened: password_auth={pw_auth} idle={}s \
                 max_tries={} port={}\"",
                sh.idle_timeout, sh.max_auth_tries, sh.port
            ),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "password auth mode persisted".into(),
            command: "uci -q get dropbear.@dropbear[0].PasswordAuth".into(),
            expect_contains: pw_auth.into(),
        },
        VerificationCheck {
            description: "listen port persisted".into(),
            command: "uci -q get dropbear.@dropbear[0].Port".into(),
            expect_contains: sh.port.to_string(),
        },
    ];
    Ok(Plan {
        profile_id: "ssh-hardening".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_travelmate(
    model: &DeviceModel,
    tm: &TravelmateProfile,
) -> Result<Plan, Unsupported> {
    let captive_flag = if tm.captive { "1" } else { "0" };
    let literal = |v: String| UciValue::Literal(v);
    let mut global_options = vec![
        ("trm_enabled".into(), literal("1".into())),
        ("trm_automatic".into(), literal("1".into())),
        ("trm_captive".into(), literal(captive_flag.into())),
        ("trm_timeout".into(), literal(tm.timeout.to_string())),
        ("trm_retry".into(), literal(tm.retry.to_string())),
        ("trm_radio".into(), literal(tm.radio.clone())),
    ];
    if !tm.uplinks.is_empty() {
        global_options.push(("trm_iface".into(), literal("trm_wwan".into())));
        global_options.push(("trm_uplink".into(), literal("trm_wwan".into())));
    }
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "travelmate".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-travelmate".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-bundle".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-certificates".into(),
        },
        PlanOp::SetUciOptions {
            config: "travelmate".into(),
            section: "global".into(),
            options: global_options,
        },
    ];
    if !tm.uplinks.is_empty() {
        // Mirror of travelmate's own `setup` command shape (2.4.x): the
        // trm_iface gate in travelmate-functions.sh exits "not
        // configured" without it; the uplink pair is trm_wwan (dhcp,
        // metric 100) + trm_wwan6 (dhcpv6 via @trm_wwan), both joined
        // to the wan zone by NAME via the 1.x helper.
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "trm_wwan".into(),
            section_type: "interface".into(),
            options: vec![
                ("proto".into(), literal("dhcp".into())),
                ("metric".into(), literal("100".into())),
            ],
        });
        ops.push(PlanOp::SetUciSection {
            config: "network".into(),
            section: "trm_wwan6".into(),
            section_type: "interface".into(),
            options: vec![
                ("device".into(), literal("@trm_wwan".into())),
                ("proto".into(), literal("dhcpv6".into())),
            ],
        });
        ops.push(PlanOp::Shell {
            command: uci_add_to_wan_zone_sh("trm_wwan"),
        });
        ops.push(PlanOp::Shell {
            command: uci_add_to_wan_zone_sh("trm_wwan6"),
        });
        for uplink in &tm.uplinks {
            let mut options = vec![
                ("device".into(), literal(uplink.radio.clone())),
                ("mode".into(), literal("sta".into())),
                ("network".into(), literal("trm_wwan".into())),
                ("ssid".into(), literal(uplink.ssid.clone())),
                ("encryption".into(), literal(uplink.encryption.clone())),
            ];
            if uplink.encryption != "none" {
                options.push(("key".into(), literal(uplink.psk.clone())));
            }
            ops.push(PlanOp::SetUciSection {
                config: "wireless".into(),
                section: uplink.iface.clone(),
                section_type: "wifi-iface".into(),
                options,
            });
            // travelmate 2.4.x recognition: each sta wifi-iface needs a
            // paired `uplink` section in /etc/config/travelmate (matched
            // by device+ssid in f_getcfg) carrying enabled=1 — without
            // it f_setif force-disables the iface and the sta_list stays
            // empty (found live on x1860-1, 2026-10-22).
            ops.push(PlanOp::SetUciSection {
                config: "travelmate".into(),
                section: uplink.iface.clone(),
                section_type: "uplink".into(),
                options: vec![
                    ("device".into(), literal(uplink.radio.clone())),
                    ("ssid".into(), literal(uplink.ssid.clone())),
                    ("enabled".into(), literal("1".into())),
                ],
            });
        }
        ops.push(PlanOp::CommitUci {
            config: "network".into(),
        });
        ops.push(PlanOp::CommitUci {
            config: "wireless".into(),
        });
        ops.push(PlanOp::Shell {
            command: "wifi reload; ubus call network.interface.trm_wwan up 2>/dev/null; true"
                .into(),
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "travelmate".into(),
    });
    ops.push(PlanOp::Service {
        name: "travelmate".into(),
        action: ServiceAction::Enable,
    });
    ops.push(PlanOp::Service {
        name: "travelmate".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Shell {
        command: if tm.uplinks.is_empty() {
            format!(
                "echo \"Travelmate configured: auto-connect on {}\"",
                tm.radio
            )
        } else {
            format!(
                "echo \"Travelmate configured: auto-connect on {} ({} uplinks)\"",
                tm.radio,
                tm.uplinks.len()
            )
        },
    });
    let verification = vec![
        VerificationCheck {
            description: "travelmate enabled".into(),
            command: "uci -q get travelmate.global.trm_enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "scan radio persisted".into(),
            command: "uci -q get travelmate.global.trm_radio".into(),
            expect_contains: tm.radio.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/travelmate enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "travelmate".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_adguard(model: &DeviceModel, ag: &AdguardProfile) -> Result<Plan, Unsupported> {
    let literal = |v: String| UciValue::Literal(v);
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "adguardhome".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-adguardhome".into(),
        },
        PlanOp::SetUciSection {
            config: "adguardhome".into(),
            section: "adguardhome".into(),
            section_type: "adguardhome".into(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                (
                    "http_address".into(),
                    literal(format!("{}:{}", ag.listen_ip, ag.web_port)),
                ),
                ("dns_port".into(), literal(ag.dns_port.to_string())),
            ],
        },
        PlanOp::CommitUci {
            config: "adguardhome".into(),
        },
        PlanOp::Service {
            name: "adguardhome".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "adguardhome".into(),
            action: ServiceAction::Start,
        },
        PlanOp::SetUciOptions {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            options: vec![("noresolv".into(), literal("1".into()))],
        },
        PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: format!("127.0.0.1#{}", ag.dns_port),
        },
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        PlanOp::Service {
            name: "dnsmasq".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"AdGuard Home configured: DNS on port {}, web UI at {}:{}\"",
                ag.dns_port, ag.listen_ip, ag.web_port
            ),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "adguardhome enabled in uci".into(),
            command: "uci -q get adguardhome.adguardhome.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "dnsmasq forwards to adguard".into(),
            command: "uci -q get dhcp.@dnsmasq[0].server".into(),
            expect_contains: format!("127.0.0.1#{}", ag.dns_port),
        },
    ];
    Ok(Plan {
        profile_id: "adguard".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_mesh11sd(
    model: &DeviceModel,
    mesh: &Mesh11sdProfile,
) -> Result<Plan, Unsupported> {
    mesh.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut setup_options = vec![
        ("auto_mesh_id".into(), literal(mesh.mesh_id.clone())),
        ("mesh_gate_base_ssid".into(), literal(mesh.ssid.clone())),
        (
            "mesh_gate_encryption".into(),
            literal(mesh.encryption.clone()),
        ),
    ];
    if !mesh.key.is_empty() {
        setup_options.push(("mesh_gate_key".into(), literal(mesh.key.clone())));
    }
    setup_options.push(("auto_config".into(), literal(mesh.auto_config.clone())));
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "mesh11sd".into(),
        },
        PlanOp::EnsurePackage {
            name: "ip-full".into(),
        },
        PlanOp::EnsurePackage {
            name: "kmod-nft-bridge".into(),
        },
        PlanOp::EnsurePackage {
            name: "vxlan".into(),
        },
        PlanOp::Shell {
            command: "opkg remove wpad-basic-mbedtls wpad-basic-wolfssl wpad-basic-openssl \
                      wpad-basic 2>/dev/null || true"
                .into(),
        },
        PlanOp::Shell {
            command: "opkg install wpad-mbedtls 2>/dev/null || true".into(),
        },
        PlanOp::Shell {
            command: "service wpad restart 2>/dev/null || true".into(),
        },
        PlanOp::SetUciOptions {
            config: "mesh11sd".into(),
            section: "setup".into(),
            options: setup_options,
        },
        PlanOp::CommitUci {
            config: "mesh11sd".into(),
        },
        PlanOp::Shell {
            command: "service mesh11sd restart 2>/dev/null || true".into(),
        },
        PlanOp::Shell {
            command: format!(
                "echo \"Mesh11sd configured: mesh_id={} ssid={}\"",
                mesh.mesh_id, mesh.ssid
            ),
        },
    ];
    let verification = vec![VerificationCheck {
        description: "mesh id persisted".into(),
        command: "uci -q get mesh11sd.setup.auto_mesh_id".into(),
        expect_contains: mesh.mesh_id.clone(),
    }];
    Ok(Plan {
        profile_id: "mesh11sd".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

/// The 1.x watchdog payload, verbatim (`WATCHDOG_INIT` in
/// `scripts/use_cases/rescue_watchdog.py`): procd init heredoc +
/// watchdog loop heredoc, `__TARGET__` substituted at plan time.
pub(super) const RESCUE_WATCHDOG_INIT: &str = r#"cat > /etc/init.d/rescue-watchdog << 'WD_EOF'
#!/bin/sh /etc/rc.common

START=99
USE_PROCD=1

start_service() {
    procd_open_instance
    procd_set_param command /bin/sh /usr/bin/rescue-watchdog-loop
    procd_set_param respawn 3600 5 0
    procd_set_param stdout 1
    procd_set_param stderr 1
    procd_close_instance
}
WD_EOF
chmod +x /etc/init.d/rescue-watchdog

/usr/bin/rescue-watchdog-loop << 'WDL_EOF'
#!/bin/sh
TARGET="${WATCHDOG_TARGET:-__TARGET__}"
GRACE=600
FAILS=0
while :; do
    UPTIME=$(cut -d. -f1 /proc/uptime)
    if [ "$UPTIME" -lt "$GRACE" ]; then
        FAILS=0
    elif ping -c1 -W3 "$TARGET" >/dev/null 2>&1; then
        FAILS=0
    else
        FAILS=$((FAILS+1))
        logger -t rescue-watchdog "target $TARGET unreachable ($FAILS/3)"
        if [ "$FAILS" -ge 3 ]; then
            logger -t rescue-watchdog "networking wedged - rebooting"
            sync
            reboot
        fi
    fi
    sleep 60
done
WDL_EOF
chmod +x /usr/bin/rescue-watchdog-loop

/etc/init.d/rescue-watchdog enable
/etc/init.d/rescue-watchdog restart
"#;

pub(super) const NODNS_INITD_SCRIPT: &str = r####"#!/bin/sh /etc/rc.common
START=99
USE_PROCD=1

start_service() {
	procd_open_instance
	procd_set_param command /usr/bin/nodns-poll.sh
	procd_set_param respawn
	procd_set_param stdout 1
	procd_set_param stderr 1
	procd_close_instance
}
"####;

pub(super) const NODNS_POLL_SCRIPT_TEMPLATE: &str = r####"#!/bin/sh
# nodns DNS bridge -- polls zone export API, updates dnsmasq addn-hosts cache.
# Auto-generated by conwrt use_cases/nodns.
ZONE="__ZONE__"
API_URL="__URL__"
POLL_INTERVAL=__POLL_INTERVAL__
HOSTS_FILE="/etc/dnsmasq.d/nodns.hosts"
TMP_FILE="/tmp/nodns-zone.txt"

mkdir -p /etc/dnsmasq.d

while true; do
	# Fetch BIND zone file from the nodns bot API.
	if curl -s --connect-timeout 10 --max-time 30 \
		"${API_URL}/api/zone/${ZONE}/export" \
		-o "$TMP_FILE" 2>/dev/null; then
		# Parse: extract A/AAAA records -> "ip<TAB>fqdn" lines for addn-hosts.
		awk -v z="$ZONE" '
		BEGIN { OFS = "\t" }
		{
			rtype = toupper($3)
			if (rtype != "A" && rtype != "AAAA") next
			name = $1
			ip = $NF
			if (name == "@") name = z
			else if (name ~ /\.$/) sub(/\.$/, "", name)
			else name = name "." z
			print ip, name
		}' "$TMP_FILE" > "$HOSTS_FILE.new"
		# Atomic swap only when we got valid data.
		if [ -s "$HOSTS_FILE.new" ]; then
			mv "$HOSTS_FILE.new" "$HOSTS_FILE"
			killall -HUP dnsmasq 2>/dev/null
		else
			rm -f "$HOSTS_FILE.new"
		fi
	fi
	sleep "$POLL_INTERVAL"
done
"####;

pub(super) const AUTO_SQM_SCRIPT: &str = r####"#!/bin/sh
# auto-sqm — measure WAN link speed and configure SQM

MODE=$(uci -q get auto_sqm.config.mode || echo "static")
INTERFACE=$(uci -q get auto_sqm.config.interface || echo "wan")
DEVICE=$(uci -q get auto_sqm.config.device || echo "eth0")
TARGET_PCT=$(uci -q get auto_sqm.config.target_percent || echo "90")
QDISC=$(uci -q get auto_sqm.config.qdisc || echo "cake")
QOS_SCRIPT=$(uci -q get auto_sqm.config.script || echo "piece_of_cake.qos")
MEAS_MODE=$(uci -q get auto_sqm.config.measurement_mode || echo "wget")
IPERF3_HOST=$(uci -q get auto_sqm.config.iperf3_host || echo "")
IPERF3_PORT=$(uci -q get auto_sqm.config.iperf3_port || echo "5201")
TEST_URL=$(uci -q get auto_sqm.config.test_url || echo "")
UPLOAD_FALLBACK=$(uci -q get auto_sqm.config.upload_fallback_kbps || echo "5000")
HYSTERESIS=$(uci -q get auto_sqm.config.hysteresis_percent || echo "10")

DL_SPEED=0
UL_SPEED=0

measure_wget() {
    [ -z "$DEVICE" ] && return 1
    [ -z "$TEST_URL" ] && return 1
    bytes_before=$(cat /sys/class/net/"$DEVICE"/statistics/rx_bytes 2>/dev/null) || return 1
    t1=$(date +%s)
    wget -O /dev/null -T 30 "$TEST_URL" 2>/dev/null || return 1
    t2=$(date +%s)
    bytes_after=$(cat /sys/class/net/"$DEVICE"/statistics/rx_bytes 2>/dev/null) || return 1
    elapsed=$((t2 - t1))
    [ "$elapsed" -eq 0 ] && elapsed=1
    speed_bps=$(( (bytes_after - bytes_before) * 8 / elapsed ))
    DL_SPEED=$((speed_bps / 1000))
    DL_SPEED=$((DL_SPEED * TARGET_PCT / 100))
}

measure_iperf3() {
    [ -z "$IPERF3_HOST" ] && return 1
    command -v iperf3 >/dev/null 2>&1 || return 1
    json_out=$(iperf3 -c "$IPERF3_HOST" -p "$IPERF3_PORT" -t 5 -J 2>/dev/null) || return 1
    speed_bps=$(echo "$json_out" | jsonfilter -e "@.end.sum_received.bits_per_second" 2>/dev/null) || return 1
    speed_bps=$(echo "$speed_bps" | cut -d. -f1)
    DL_SPEED=$((speed_bps / 1000))
    DL_SPEED=$((DL_SPEED * TARGET_PCT / 100))
}

apply_sqm() {
    dl=$1
    ul=$2
    [ "$dl" -eq 0 ] && return 1

    cur_dl=$(uci -q get sqm."$INTERFACE".download || echo "0")
    cur_ul=$(uci -q get sqm."$INTERFACE".upload || echo "0")

    if [ "$cur_dl" -gt 0 ] && [ "$cur_ul" -gt 0 ]; then
        lo=$((100 - HYSTERESIS))
        hi=$((100 + HYSTERESIS))
        pct_dl=$((cur_dl * 100 / dl))
        pct_ul=$((cur_ul * 100 / ul))
        if [ "$pct_dl" -ge "$lo" ] && [ "$pct_dl" -le "$hi" ] && [ "$pct_ul" -ge "$lo" ] && [ "$pct_ul" -le "$hi" ]; then
            echo "auto-sqm: change within hysteresis, skipping"
            return 0
        fi
    fi

    # clean baseline first: /tmp/.uci staging debris from an aborted
    # earlier run must not merge into this commit (#470, AGENTS uci rule)
    uci revert sqm 2>/dev/null || true
    touch /etc/config/sqm

    uci set sqm.$INTERFACE=queue
    # SQM must bind the actual device, not the UCI network name (#470 —
    # the wan lesson: names break on WiFi-STA/alias setups where
    # device != name). Resolve via the network section, then the
    # configured DEVICE, then fall back to the name.
    _sqm_dev=$(uci -q get network."$INTERFACE".device 2>/dev/null)
    [ -z "$_sqm_dev" ] && _sqm_dev="$DEVICE"
    [ -z "$_sqm_dev" ] && _sqm_dev="$INTERFACE"
    uci set sqm.$INTERFACE.interface="$_sqm_dev"
    uci set sqm.$INTERFACE.enabled='1'
    uci set sqm.$INTERFACE.script="$QOS_SCRIPT"
    uci set sqm.$INTERFACE.qdisc="$QDISC"
    uci set sqm.$INTERFACE.linklayer='none'
    uci set sqm.$INTERFACE.overhead='0'
    uci set sqm.$INTERFACE.linklayer_adaptation_mechanism='default'
    uci set sqm.$INTERFACE.debug_logging='0'
    uci set sqm.$INTERFACE.verbosity='5'
    uci set sqm.$INTERFACE.download="$dl"
    uci set sqm.$INTERFACE.upload="$ul"
    uci commit sqm

    /etc/init.d/sqm enable
    /etc/init.d/sqm restart 2>/dev/null || true

    echo "auto-sqm: SQM applied ${dl}/${ul} kbit/s (${QDISC})"
}

STATIC_DL=$(uci -q get auto_sqm.config.download_kbps || echo "0")
STATIC_UL=$(uci -q get auto_sqm.config.upload_kbps || echo "0")

if [ "$MODE" = "static" ] && [ "$STATIC_DL" -gt 0 ]; then
    DL_SPEED=$((STATIC_DL * TARGET_PCT / 100))
    if [ "$STATIC_UL" -gt 0 ]; then
        UL_SPEED=$((STATIC_UL * TARGET_PCT / 100))
    else
        UL_SPEED=$UPLOAD_FALLBACK
    fi
else
    if [ "$MEAS_MODE" = "iperf3" ] && [ -n "$IPERF3_HOST" ]; then
        measure_iperf3 || measure_wget
    else
        measure_wget || measure_iperf3
    fi

    if [ "$DL_SPEED" -eq 0 ]; then
        echo "auto-sqm: measurement failed, will retry on next trigger" >&2
        exit 1
    fi

    if [ "$STATIC_UL" -gt 0 ]; then
        UL_SPEED=$((STATIC_UL * TARGET_PCT / 100))
    else
        UL_SPEED=$UPLOAD_FALLBACK
    fi
fi

apply_sqm "$DL_SPEED" "$UL_SPEED"
"####;

pub(super) fn plan_rescue_watchdog(
    model: &DeviceModel,
    wd: &RescueWatchdogProfile,
) -> Result<Plan, Unsupported> {
    let ops = vec![PlanOp::Shell {
        command: RESCUE_WATCHDOG_INIT.replace("__TARGET__", &wd.target),
    }];
    let verification = vec![VerificationCheck {
        description: "watchdog service enabled".into(),
        command: "/etc/init.d/rescue-watchdog enabled && echo yes".into(),
        expect_contains: "yes".into(),
    }];
    Ok(Plan {
        profile_id: "rescue-watchdog".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_mwan3(model: &DeviceModel, mw: &Mwan3Profile) -> Result<Plan, Unsupported> {
    mw.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let (primary_metric, primary_weight, secondary_metric, secondary_weight) =
        if mw.policy == "balanced" {
            ("1", "2", "1", "1")
        } else {
            ("1", "1", "2", "1")
        };
    let pm = format!("{}_m{primary_metric}_w{primary_weight}", mw.primary);
    let sm = format!("{}_m{secondary_metric}_w{secondary_weight}", mw.secondary);
    let pol_name = format!("{}_policy", mw.primary);
    let probe_options = vec![
        ("family".into(), literal("ipv4".into())),
        ("reliability".into(), literal("1".into())),
        ("count".into(), literal("1".into())),
        ("timeout".into(), literal("2".into())),
        ("interval".into(), literal("5".into())),
        ("down".into(), literal("3".into())),
        ("up".into(), literal("8".into())),
    ];
    let mut ops: Vec<PlanOp> = [
        "mwan3",
        "iptables-nft",
        "ip6tables-nft",
        "iptables-mod-conntrack-extra",
    ]
    .iter()
    .map(|name| PlanOp::EnsurePackage {
        name: (*name).into(),
    })
    .collect();
    // mwan3 convention: the tracked interface section is named after the
    // UCI network it tracks. 1.x hardcoded the section as `wan` while
    // pointing the member at `primary` — broken for any primary ≠ "wan"
    // (Codex #448 P1; default output renders identically, so golden
    // parity is unaffected).
    ops.push(PlanOp::ResetUciConfig {
        config: "mwan3".into(),
    });
    for section in [&mw.primary, &mw.secondary] {
        ops.push(PlanOp::SetUciSection {
            config: "mwan3".into(),
            section: section.clone(),
            section_type: "interface".into(),
            options: vec![("enabled".into(), literal("1".into()))],
        });
        for ip in &mw.track_ips {
            // 1.x renders bare `list track_ip '<ip>'` lines here — broken
            // shell (silently ignored without set -e, fatal with it); the
            // port emits the intended uci add_list against THIS section
            ops.push(PlanOp::UciAddList {
                config: "mwan3".into(),
                section: section.clone(),
                option: "track_ip".into(),
                value: ip.clone(),
            });
        }
        ops.push(PlanOp::SetUciOptions {
            config: "mwan3".into(),
            section: section.clone(),
            options: probe_options.clone(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: pm.clone(),
        section_type: "member".into(),
        options: vec![
            ("interface".into(), literal(mw.primary.clone())),
            ("metric".into(), literal(primary_metric.into())),
            ("weight".into(), literal(primary_weight.into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: sm.clone(),
        section_type: "member".into(),
        options: vec![
            ("interface".into(), literal(mw.secondary.clone())),
            ("metric".into(), literal(secondary_metric.into())),
            ("weight".into(), literal(secondary_weight.into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: pol_name.clone(),
        section_type: "policy".into(),
        options: vec![],
    });
    ops.push(PlanOp::UciAddList {
        config: "mwan3".into(),
        section: pol_name.clone(),
        option: "use_member".into(),
        value: pm.clone(),
    });
    ops.push(PlanOp::UciAddList {
        config: "mwan3".into(),
        section: pol_name.clone(),
        option: "use_member".into(),
        value: sm.clone(),
    });
    ops.push(PlanOp::SetUciOptions {
        config: "mwan3".into(),
        section: pol_name.clone(),
        options: vec![("last_resort".into(), literal("default".into()))],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: "default_rule_v4".into(),
        section_type: "rule".into(),
        options: vec![
            ("dest_ip".into(), literal("0.0.0.0/0".into())),
            ("use_policy".into(), literal(pol_name.clone())),
            ("family".into(), literal("ipv4".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "mwan3".into(),
        section: "https_rule".into(),
        section_type: "rule".into(),
        options: vec![
            ("dest_port".into(), literal("443".into())),
            ("proto".into(), literal("tcp".into())),
            ("sticky".into(), literal("1".into())),
            ("use_policy".into(), literal(pol_name.clone())),
        ],
    });
    ops.push(PlanOp::CommitUci {
        config: "mwan3".into(),
    });
    ops.push(PlanOp::Service {
        name: "mwan3".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Shell {
        command: format!(
            "echo \"mwan3 configured: {} (primary) + {} ({})\"",
            mw.primary, mw.secondary, mw.policy
        ),
    });
    let verification = vec![
        VerificationCheck {
            description: "primary interface section exists".into(),
            command: "uci -q get mwan3.wan.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "policy wired to both members".into(),
            command: format!("uci -q get mwan3.{pol_name}.use_member"),
            expect_contains: pm,
        },
    ];
    Ok(Plan {
        profile_id: "mwan3".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_pbr(model: &DeviceModel, pbr: &PbrProfile) -> Result<Plan, Unsupported> {
    pbr.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let strict = if pbr.strict_enforcement { "1" } else { "0" };
    let ops = vec![
        PlanOp::EnsurePackage { name: "pbr".into() },
        PlanOp::EnsurePackage {
            name: "luci-app-pbr".into(),
        },
        PlanOp::Shell {
            command: "uci set pbr.config=pbr".into(),
        },
        PlanOp::SetUciOptions {
            config: "pbr".into(),
            section: "config".into(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                ("verbosity".into(), literal("2".into())),
                ("strict_enforcement".into(), literal(strict.into())),
                ("resolver_set".into(), literal("none".into())),
                ("nft_file_helper".into(), literal("1".into())),
            ],
        },
        // 1.x renders these two UNQUOTED (bare interface names); the
        // validate() charset gate is what makes the verbatim render safe.
        PlanOp::Shell {
            command: format!(
                "uci set pbr.config.netifd_interface_default={}",
                pbr.wan_interface
            ),
        },
        PlanOp::Shell {
            command: format!(
                "uci add_list pbr.config.netifd_interface_local={}",
                pbr.lan_interface
            ),
        },
        PlanOp::CommitUci {
            config: "pbr".into(),
        },
        PlanOp::Service {
            name: "pbr".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "pbr".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: "echo \"pbr configured. Verify with: nft list table inet pbr 2>/dev/null\""
                .into(),
        },
        PlanOp::Shell {
            command: "echo \"Check status: /etc/init.d/pbr status\"".into(),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "pbr enabled in uci".into(),
            command: "uci -q get pbr.config.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "default WAN interface persisted".into(),
            command: "uci -q get pbr.config.netifd_interface_default".into(),
            expect_contains: pbr.wan_interface.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/pbr enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "pbr".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_openclash(
    model: &DeviceModel,
    oc: &OpenClashProfile,
) -> Result<Plan, Unsupported> {
    oc.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    // Package order and swap safety are load-bearing at apply time
    // (Codex #486 rounds 1+4+6): dnsmasq and dnsmasq-full conflict
    // (both provide dnsmasq), luci-app-openclash DEPENDS on
    // dnsmasq-full, and the removal must never run before the
    // replacement is provably installable — a dead feed after a bare
    // removal would leave the router with NO dnsmasq (DNS+DHCP outage
    // class). The swap therefore: runs only when dnsmasq is installed
    // AND dnsmasq-full is not; downloads the dnsmasq-full ipk to /tmp
    // FIRST (proving feed + package availability); and only then
    // removes and installs from the local file (offline-safe). 1.x
    // carries the swap as an image-build `packages_remove` directive
    // where none of this applies. No-op on apk systems (opkg absent;
    // apk replaces the provider without a conflict) and where
    // dnsmasq-full is already installed.
    let mut ops: Vec<PlanOp> = vec![
        PlanOp::Shell {
            command: concat!(
                "if [ -n \"$(opkg list-installed dnsmasq 2>/dev/null)\" ] ",
                "&& [ -z \"$(opkg list-installed dnsmasq-full 2>/dev/null)\" ]; then ",
                "(cd /tmp && opkg update && opkg download dnsmasq-full) ",
                "&& opkg remove dnsmasq && opkg install /tmp/dnsmasq-full_*.ipk; fi",
            )
            .into(),
        },
        PlanOp::EnsurePackage {
            name: "dnsmasq-full".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-openclash".into(),
        },
        PlanOp::EnsurePackage {
            name: "coreutils-nohup".into(),
        },
        PlanOp::EnsurePackage {
            name: "bash".into(),
        },
        PlanOp::EnsurePackage {
            name: "iptables".into(),
        },
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-certificates".into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-bundle".into(),
        },
        PlanOp::EnsurePackage {
            name: "logd".into(),
        },
    ];
    ops.extend([
        PlanOp::Shell {
            command: "mkdir -p /etc/openclash/config".into(),
        },
        // AGENTS.md staging-debris rule: an aborted earlier session may
        // have left uncommitted /tmp/.uci changes for openclash — the
        // later `uci commit openclash` would make them permanent.
        // Start every apply from the persisted baseline.
        PlanOp::RevertUci {
            config: "openclash".into(),
        },
        PlanOp::SetUciOptions {
            config: "openclash".into(),
            section: "config".into(),
            options: vec![
                ("enable".into(), literal("1".into())),
                (
                    "config_path".into(),
                    literal("/etc/openclash/config/config.yaml".into()),
                ),
                ("proxy_type".into(), literal(oc.proxy_type.clone())),
                ("core_type".into(), literal(oc.core_type.clone())),
                ("dashboard_type".into(), literal("Official".into())),
                ("dns_mode".into(), literal(oc.dns_mode.clone())),
                ("operation_mode".into(), literal(oc.dns_mode.clone())),
            ],
        },
        PlanOp::CommitUci {
            config: "openclash".into(),
        },
        PlanOp::Service {
            name: "openclash".into(),
            action: ServiceAction::Enable,
        },
        // core_type/proxy_type interpolate into a DOUBLE-quoted echo;
        // validate()'s token gate is what makes the verbatim render safe
        PlanOp::Shell {
            command: format!(
                "echo \"OpenClash configured: {} core, {} proxy\"",
                oc.core_type, oc.proxy_type
            ),
        },
        // post-flash boundary, byte-identical to 1.x: the subscription
        // config is imported via the LuCI web UI AFTER flash — this
        // plan stops here
        PlanOp::Shell {
            command: "echo \"Post-flash: import your subscription config via the LuCI web UI\""
                .into(),
        },
    ]);
    let verification = vec![
        VerificationCheck {
            description: "openclash enabled in uci".into(),
            command: "uci -q get openclash.config.enable".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "clash core persisted".into(),
            command: "uci -q get openclash.config.core_type".into(),
            expect_contains: oc.core_type.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/openclash enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "openclash".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) const PIA_OPENVPN_CA: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIHqzCCBZOgAwIBAgIJAJ0u+vODZJntMA0GCSqGSIb3DQEBDQUAMIHoMQswCQYD\n",
    "VQQGEwJVUzELMAkGA1UECBMCQ0ExEzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNV\n",
    "BAoTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIElu\n",
    "dGVybmV0IEFjY2VzczEgMB4GA1UEAxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3Mx\n",
    "IDAeBgNVBCkTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkB\n",
    "FiBzZWN1cmVAcHJpdmF0ZWludGVybmV0YWNjZXNzLmNvbTAeFw0xNDA0MTcxNzQw\n",
    "MzNaFw0zNDA0MTIxNzQwMzNaMIHoMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0Ex\n",
    "EzARBgNVBAcTCkxvc0FuZ2VsZXMxIDAeBgNVBAoTF1ByaXZhdGUgSW50ZXJuZXQg\n",
    "QWNjZXNzMSAwHgYDVQQLExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UE\n",
    "AxMXUHJpdmF0ZSBJbnRlcm5ldCBBY2Nlc3MxIDAeBgNVBCkTF1ByaXZhdGUgSW50\n",
    "ZXJuZXQgQWNjZXNzMS8wLQYJKoZIhvcNAQkBFiBzZWN1cmVAcHJpdmF0ZWludGVy\n",
    "bmV0YWNjZXNzLmNvbTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALVk\n",
    "hjumaqBbL8aSgj6xbX1QPTfTd1qHsAZd2B97m8Vw31c/2yQgZNf5qZY0+jOIHULN\n",
    "De4R9TIvyBEbvnAg/OkPw8n/+ScgYOeH876VUXzjLDBnDb8DLr/+w9oVsuDeFJ9K\n",
    "V2UFM1OYX0SnkHnrYAN2QLF98ESK4NCSU01h5zkcgmQ+qKSfA9Ny0/UpsKPBFqsQ\n",
    "25NvjDWFhCpeqCHKUJ4Be27CDbSl7lAkBuHMPHJs8f8xPgAbHRXZOxVCpayZ2SND\n",
    "fCwsnGWpWFoMGvdMbygngCn6jA/W1VSFOlRlfLuuGe7QFfDwA0jaLCxuWt/BgZyl\n",
    "p7tAzYKR8lnWmtUCPm4+BtjyVDYtDCiGBD9Z4P13RFWvJHw5aapx/5W/CuvVyI7p\n",
    "Kwvc2IT+KPxCUhH1XI8ca5RN3C9NoPJJf6qpg4g0rJH3aaWkoMRrYvQ+5PXXYUzj\n",
    "tRHImghRGd/ydERYoAZXuGSbPkm9Y/p2X8unLcW+F0xpJD98+ZI+tzSsI99Zs5wi\n",
    "jSUGYr9/j18KHFTMQ8n+1jauc5bCCegN27dPeKXNSZ5riXFL2XX6BkY68y58UaNz\n",
    "meGMiUL9BOV1iV+PMb7B7PYs7oFLjAhh0EdyvfHkrh/ZV9BEhtFa7yXp8XR0J6vz\n",
    "1YV9R6DYJmLjOEbhU8N0gc3tZm4Qz39lIIG6w3FDAgMBAAGjggFUMIIBUDAdBgNV\n",
    "HQ4EFgQUrsRtyWJftjpdRM0+925Y6Cl08SUwggEfBgNVHSMEggEWMIIBEoAUrsRt\n",
    "yWJftjpdRM0+925Y6Cl08SWhge6kgeswgegxCzAJBgNVBAYTAlVTMQswCQYDVQQI\n",
    "EwJDQTETMBEGA1UEBxMKTG9zQW5nZWxlczEgMB4GA1UEChMXUHJpdmF0ZSBJbnRl\n",
    "cm5ldCBBY2Nlc3MxIDAeBgNVBAsTF1ByaXZhdGUgSW50ZXJuZXQgQWNjZXNzMSAw\n",
    "HgYDVQQDExdQcml2YXRlIEludGVybmV0IEFjY2VzczEgMB4GA1UEKRMXUHJpdmF0\n",
    "ZSBJbnRlcm5ldCBBY2Nlc3MxLzAtBgkqhkiG9w0BCQEWIHNlY3VyZUBwcml2YXRl\n",
    "aW50ZXJuZXRhY2Nlc3MuY29tggkAnS7684Nkme0wDAYDVR0TBAUwAwEB/zANBgkq\n",
    "hkiG9w0BAQ0FAAOCAgEAJsfhsPk3r8kLXLxY+v+vHzbr4ufNtqnL9/1Uuf8NrsCt\n",
    "pXAoyZ0YqfbkWx3NHTZ7OE9ZRhdMP/RqHQE1p4N4Sa1nZKhTKasV6KhHDqSCt/dv\n",
    "Em89xWm2MVA7nyzQxVlHa9AkcBaemcXEiyT19XdpiXOP4Vhs+J1R5m8zQOxZlV1G\n",
    "tF9vsXmJqWZpOVPmZ8f35BCsYPvv4yMewnrtAC8PFEK/bOPeYcKN50bol22QYaZu\n",
    "LfpkHfNiFTnfMh8sl/ablPyNY7DUNiP5DRcMdIwmfGQxR5WEQoHL3yPJ42LkB5zs\n",
    "6jIm26DGNXfwura/mi105+ENH1CaROtRYwkiHb08U6qLXXJz80mWJkT90nr8Asj3\n",
    "5xN2cUppg74nG3YVav/38P48T56hG1NHbYF5uOCske19F6wi9maUoto/3vEr0rnX\n",
    "JUp2KODmKdvBI7co245lHBABWikk8VfejQSlCtDBXn644ZMtAdoxKNfR2WTFVEwJ\n",
    "iyd1Fzx0yujuiXDROLhISLQDRjVVAvawrAtLZWYK31bY7KlezPlQnl/D9Asxe85l\n",
    "8jO5+0LdJ6VyOs/Hd4w52alDW/MFySDZSfQHMTIc30hLBJ8OnCEIvluVQQ2UQvoW\n",
    "+no177N9L2Y+M9TcTA62ZyMXShHQGeh20rb4kK8f+iFX8NxtdHVSkxMEFSfDDyQ=\n",
    "-----END CERTIFICATE-----\n",
);

/// The vpn-provider family's shared firewall-zone/DNS/verify tail —
/// 1.x `vpn_providers/base.py::build_{firewall,dns,verify}_ops`, byte
/// parity. Named sections + `CleanupUciSections` keep re-runs and
/// technology switches (wg → openvpn) idempotent: the family zone name
/// (`name='vpn'`) lets one technology's setup retire another's rules.
/// `verify_line` is the kind-specific failure TAIL (wg handshake vs
/// tun-address probe) that removes the kill switch when the tunnel
/// never comes up.
#[allow(clippy::too_many_arguments)]
pub(super) fn push_vpn_shared_ops(
    ops: &mut Vec<PlanOp>,
    iface: &str,
    dns_servers: &[&str],
    kill_switch: bool,
    allow_management: bool,
    verify_line: &str,
) {
    let literal = |v: String| UciValue::Literal(v);
    for (config, pattern) in [
        ("firewall", "name='vpn'"),
        ("firewall", "dest='vpn'"),
        ("firewall", "name='KillSwitch-Reject-NonVPN'"),
        ("firewall", "name='Allow-VPN-Management'"),
    ] {
        ops.push(PlanOp::CleanupUciSections {
            config: config.into(),
            pattern: pattern.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_zone".into(),
        section_type: "zone".into(),
        options: vec![
            ("name".into(), literal("vpn".into())),
            ("input".into(), literal("REJECT".into())),
            ("output".into(), literal("ACCEPT".into())),
            ("forward".into(), literal("REJECT".into())),
            ("masq".into(), literal("1".into())),
            ("mtu_fix".into(), literal("1".into())),
            ("network".into(), literal(iface.into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_fwd".into(),
        section_type: "forwarding".into(),
        options: vec![
            ("src".into(), literal("lan".into())),
            ("dest".into(), literal("vpn".into())),
        ],
    });
    if allow_management {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_mgmt".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("Allow-VPN-Management".into())),
                ("src".into(), literal("vpn".into())),
                ("proto".into(), literal("tcp".into())),
                ("dest_port".into(), literal("22 80 443".into())),
                ("target".into(), literal("ACCEPT".into())),
            ],
        });
    }
    if kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_killswitch".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("KillSwitch-Reject-NonVPN".into())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("proto".into(), literal("all".into())),
                ("target".into(), literal("REJECT".into())),
            ],
        });
    }
    for dns in dns_servers {
        ops.push(PlanOp::Shell {
            command: format!("uci del_list dhcp.@dnsmasq[0].server='{dns}' 2>/dev/null; true"),
        });
        ops.push(PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "server".into(),
            value: (*dns).into(),
        });
    }
    ops.push(PlanOp::SetUciOptions {
        config: "dhcp".into(),
        section: "@dnsmasq[0]".into(),
        options: vec![("noresolv".into(), literal("1".into()))],
    });
    ops.push(PlanOp::CommitUci {
        config: "network".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "dhcp".into(),
    });
    ops.push(PlanOp::Service {
        name: "network".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Service {
        name: "dnsmasq".into(),
        action: ServiceAction::Restart,
    });
    if kill_switch {
        ops.push(PlanOp::Shell {
            command: verify_line.into(),
        });
    }
}

pub(super) fn plan_vpn_pia_openvpn(
    model: &DeviceModel,
    pia: &VpnPiaOpenvpnProfile,
) -> Result<Plan, Unsupported> {
    pia.validate()?;
    let remote_lines = pia
        .remotes
        .iter()
        .map(|host| {
            format!(
                "uci add_list openvpn.pia.remote='{host} {port}'",
                port = pia.port
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let route_block = if pia.upstream_gateway.is_empty() {
        String::new()
    } else {
        format!(
            "# pin the endpoint pool's route to the upstream (no v4 route via tun)\nfor _pia_ep in {}; do\n    ip route replace $_pia_ep/32 via {} dev {} 2>/dev/null || true\ndone\n",
            pia.remotes.join(" "),
            pia.upstream_gateway,
            pia.upstream_iface
        )
    };
    // the whole setup rides ONE heredoc payload (1.x transport_sh):
    // single-quoted delimiter keeps variables literal at write time and
    // the body runs verbatim via sh. username/password land as literal
    // auth lines — validate()'s control-character gate makes that safe.
    let body = format!(
        concat!(
            "# Clean up old WireGuard interface + peers\n",
            "uci -q delete network.wg0\n",
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
            "    uci delete network.@wireguard_wg0[0]\n",
            "done\n",
            "\n\n",
            "# Tear down any previous OpenVPN instance\n",
            "uci -q delete openvpn.pia\n",
            "\n",
            "mkdir -p /etc/openvpn\n",
            "cat > /etc/openvpn/pia-ca.rsa.4096.crt << 'PIA_CA_EOF'\n",
            "{CA}\n",
            "PIA_CA_EOF\n",
            "cat > /etc/openvpn/pia.auth << 'PIA_AUTH_EOF'\n",
            "{USERNAME}\n",
            "{PASSWORD}\n",
            "PIA_AUTH_EOF\n",
            "chmod 600 /etc/openvpn/pia.auth\n",
            "\n",
            "uci set openvpn.pia=openvpn\n",
            "uci set openvpn.pia.enabled='1'\n",
            "uci set openvpn.pia.client='1'\n",
            "uci set openvpn.pia.dev='tun'\n",
            "uci set openvpn.pia.proto='udp'\n",
            "{REMOTE_LINES}\n",
            "uci set openvpn.pia.remote_random='1'\n",
            "uci set openvpn.pia.resolv_retry='infinite'\n",
            "uci set openvpn.pia.nobind='1'\n",
            "uci set openvpn.pia.persist_key='1'\n",
            "# NO persist_tun (validated lesson): a dead tunnel must tear its routes\n",
            "# down, not blackhole the LAN behind stale routes.\n",
            "uci set openvpn.pia.ca='/etc/openvpn/pia-ca.rsa.4096.crt'\n",
            "uci set openvpn.pia.auth_user_pass='/etc/openvpn/pia.auth'\n",
            "uci set openvpn.pia.auth_nocache='1'\n",
            "uci set openvpn.pia.remote_cert_tls='server'\n",
            "uci set openvpn.pia.data_ciphers='AES-256-GCM:AES-128-GCM:AES-256-CBC'\n",
            "uci set openvpn.pia.data_ciphers_fallback='AES-256-CBC'\n",
            "uci set openvpn.pia.auth='sha256'\n",
            "uci set openvpn.pia.reneg_sec='0'\n",
            "uci set openvpn.pia.disable_occ='1'\n",
            "uci set openvpn.pia.mssfix='1420'\n",
            "uci set openvpn.pia.verb='3'\n",
            "uci set openvpn.pia.pull='1'\n",
            "# PIA has no IPv6: it pushes route-ipv6/ifconfig-ipv6 anyway, which\n",
            "# blackholes v6 on the v4-only tun0 (broke Signal on the validated box).\n",
            "uci add_list openvpn.pia.pull_filter='ignore \"route-ipv6\"'\n",
            "uci add_list openvpn.pia.pull_filter='ignore \"ifconfig-ipv6\"'\n",
            "uci commit openvpn\n",
            "\n",
            "{ROUTE_BLOCK}",
            "# tun0 joins the vpn zone (wg0 was removed by the cleanup above)\n",
            "uci -q del_list firewall.vpn_zone.network='wg0'\n",
            "uci -q add_list firewall.vpn_zone.network='tun0'\n",
            "/etc/init.d/openvpn restart || /etc/init.d/openvpn start\n",
        ),
        CA = PIA_OPENVPN_CA,
        USERNAME = pia.username,
        PASSWORD = pia.password,
        REMOTE_LINES = remote_lines,
        ROUTE_BLOCK = route_block,
    );
    let payload = format!(
        "cat > /tmp/pia_openvpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/pia_openvpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "openvpn-openssl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared vpn composition (byte-identical tail: cleanup, zone,
    // forwarding, management/kill-switch, tunnel DNS, restarts, and
    // the 45s tun-address verify TAIL that removes the kill switch
    // when the tunnel never comes up)
    push_vpn_shared_ops(
        &mut ops,
        "tun0",
        &["10.0.0.241", "10.0.0.242", "10.0.0.243"],
        pia.kill_switch,
        pia.allow_management,
        "i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
    // the 45s tail restores WAN on failure and exits 0 by design —
    // this check is what makes the apply HONEST about the outcome:
    // verified requires tun0 to actually hold an address (Codex #514
    // P2: auth failure / dead endpoints must not read as success)
    let verification = vec![
        VerificationCheck {
            description: "openvpn instance enabled".into(),
            command: "uci -q get openvpn.pia.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "tun0 has an address (tunnel actually up)".into(),
            command: "ip -4 addr show dev tun0 2>/dev/null | grep -q inet && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-pia-openvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) const VPN_JSON_HELPER_SH: &str = concat!(
    "# JSON parsing: try jq, install via apk (OpenWrt >=25.x) or opkg (<=24.x)\n",
    "if ! command -v jq >/dev/null 2>&1; then\n",
    "    apk add jq >/dev/null 2>&1 || { opkg update >/dev/null 2>&1 && opkg install jq >/dev/null 2>&1; }\n",
    "fi\n",
    "json_get() {\n",
    "    # $1 = key name; reads JSON from stdin; returns first string value\n",
    "    if command -v jq >/dev/null 2>&1; then\n",
    "        jq -r \".$1 // empty\"\n",
    "    else\n",
    "        tr -d '\\n' | sed \"s/.*\\\"$1\\\"[[:space:]]*:[[:space:]]*//\" | sed 's/[,\"].*//' | tr -d '\"'\n",
    "    fi\n",
    "}\n",
    "\n",
);

pub(super) const NORD_GATEWAY_DISCOVER_SH: &str = concat!(
    "\n",
    "VPN_GW=\"\"\n",
    "_i=0\n",
    "# netifd's wireguard proto normally installs the endpoint /32 route itself on\n",
    "# ifup; this is a fallback for paths where it does not. Capped short because\n",
    "# uci-defaults block the boot sequence (dropbear starts only after).\n",
    "while [ $_i -lt 20 ]; do\n",
    "    VPN_GW=$(ip -4 route show default dev {iface} 2>/dev/null | head -n1 | sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p')\n",
    "    [ -z \"$VPN_GW\" ] && VPN_GW=$(ip -4 route show default 2>/dev/null | head -n1 | sed -n 's/.*via \\([0-9.]\\+\\).*/\\1/p')\n",
    "    [ -n \"$VPN_GW\" ] && break\n",
    "    sleep 2; _i=$((_i+2))\n",
    "done\n",
    "if [ -n \"$VPN_GW\" ]; then\n",
    "    uci -q delete network.nordvpn_server_route\n",
    "    uci set network.nordvpn_server_route=route\n",
    "    uci set network.nordvpn_server_route.interface='{iface}'\n",
    "    uci set network.nordvpn_server_route.target='{route_ip}'\n",
    "    uci set network.nordvpn_server_route.netmask='255.255.255.255'\n",
    "    uci set network.nordvpn_server_route.gateway=\"$VPN_GW\"\n",
    "    uci commit network\n",
    "    /etc/init.d/network reload >/dev/null 2>&1 || true\n",
    "    echo \"VPN: endpoint route {route_ip}/32 via $VPN_GW on {iface}\"\n",
    "else\n",
    "    echo \"VPN: WARNING no upstream gateway found — endpoint route skipped\"\n",
    "fi\n",
    "\n",
);

pub(super) fn plan_vpn_nordvpn(
    model: &DeviceModel,
    nv: &VpnNordvpnProfile,
) -> Result<Plan, Unsupported> {
    nv.validate()?;
    let route_ip = nv.route_target.clone();
    // gateway set → static /32 route; empty → the bounded discovery
    // block (1.x _GATEWAY_DISCOVER_SH) that finds the default-route
    // gateway at apply time
    let route_block = if nv.upstream_gateway.is_empty() {
        // single-pass substitution (hardening audit: the #604-P2
        // token-collision class — validated values, defense in depth)
        substitute_tokens(
            NORD_GATEWAY_DISCOVER_SH,
            &[
                ("{iface}", nv.upstream_iface.as_str()),
                ("{route_ip}", route_ip.as_str()),
            ],
        )
    } else {
        format!(
            "uci set network.nordvpn_server_route=route\n\
             uci set network.nordvpn_server_route.interface='{iface}'\n\
             uci set network.nordvpn_server_route.target='{target}'\n\
             uci set network.nordvpn_server_route.netmask='255.255.255.255'\n\
             uci set network.nordvpn_server_route.gateway='{gateway}'\n",
            iface = nv.upstream_iface,
            target = route_ip,
            gateway = nv.upstream_gateway,
        )
    };
    // the payload rides ONE heredoc (1.x transport_sh): assignments are
    // double-quoted — validate()'s charsets are what make the verbatim
    // render safe
    let body = format!(
        concat!(
            "{JSON_HELPER}\n",
            "WG_PRIV=\"{PRIV}\"\n",
            "SERVER_KEY=\"{PUB}\"\n",
            "SERVER_IP=\"{HOST}\"\n",
            "\n",
            "# Clean up old WireGuard interface + peers\n",
            "uci -q delete network.wg0\n",
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
            "    uci delete network.@wireguard_wg0[0]\n",
            "done\n",
            "\n",
            "\n",
            "uci -q delete openvpn.nordvpn\n",
            "/etc/init.d/openvpn stop >/dev/null 2>&1 || true\n",
            "\n",
            "# WireGuard tunnel (NordLynx)\n",
            "uci set network.wg0=interface\n",
            "uci set network.wg0.proto='wireguard'\n",
            "uci set network.wg0.private_key=\"$WG_PRIV\"\n",
            "uci add_list network.wg0.addresses='{ADDR}'\n",
            "uci set network.wg0.mtu='{MTU}'\n",
            "uci set network.wg0.auto='1'\n",
            "\n",
            "uci add network wireguard_wg0\n",
            "uci set network.@wireguard_wg0[0].public_key=\"$SERVER_KEY\"\n",
            "uci set network.@wireguard_wg0[0].endpoint_host=\"$SERVER_IP\"\n",
            "uci set network.@wireguard_wg0[0].endpoint_port='{PORT}'\n",
            "uci add_list network.@wireguard_wg0[0].allowed_ips='0.0.0.0/0'\n",
            "uci set network.@wireguard_wg0[0].route_allowed_ips='1'\n",
            "uci set network.@wireguard_wg0[0].persistent_keepalive='{KEEP}'\n",
            "\n",
            "\n",
            "uci -q delete network.nordvpn_server_route\n",
            "{ROUTE}",
        ),
        JSON_HELPER = VPN_JSON_HELPER_SH,
        PRIV = nv.private_key,
        PUB = nv.server_public_key,
        HOST = nv.endpoint_host,
        ADDR = nv.address,
        MTU = nv.mtu,
        PORT = nv.endpoint_port,
        KEEP = nv.keepalive,
        ROUTE = route_block,
    );
    let payload = format!(
        "cat > /tmp/vpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/vpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "kmod-wireguard".into(),
        },
        PlanOp::EnsurePackage {
            name: "wireguard-tools".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-proto-wireguard".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared vpn composition (byte-identical tail) + the 30s wg
    // handshake verify TAIL that removes the kill switch on failure
    push_vpn_shared_ops(
        &mut ops,
        "wg0",
        &["103.86.96.100", "103.86.99.100"],
        nv.kill_switch,
        nv.allow_management,
        "i=0; while [ $i -lt 30 ]; do if wg show wg0 2>/dev/null | grep -q 'latest handshake'; then echo 'VPN: tunnel verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tunnel failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
    // honest outcome (the #514/#520 pattern): verified requires the
    // tunnel to actually hold a handshake — config-applied-but-dead
    // reports incomplete
    let verification = vec![
        VerificationCheck {
            description: "wg0 interface configured".into(),
            command: "uci -q get network.wg0.proto".into(),
            expect_contains: "wireguard".into(),
        },
        VerificationCheck {
            description: "wg0 handshake observed (tunnel actually up)".into(),
            command: "wg show wg0 2>/dev/null | grep -q 'latest handshake' && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-nordvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) const NORDVPN_OPENVPN_CA: &str = concat!(
    "-----BEGIN CERTIFICATE-----\n",
    "MIIFCjCCAvKgAwIBAgIBATANBgkqhkiG9w0BAQ0FADA5MQswCQYDVQQGEwJQQTEQ\n",
    "MA4GA1UEChMHTm9yZFZQTjEYMBYGA1UEAxMPTm9yZFZQTiBSb290IENBMB4XDTE2\n",
    "MDEwMTAwMDAwMFoXDTM1MTIzMTIzNTk1OVowOTELMAkGA1UEBhMCUEExEDAOBgNV\n",
    "BAoTB05vcmRWUE4xGDAWBgNVBAMTD05vcmRWUE4gUm9vdCBDQTCCAiIwDQYJKoZI\n",
    "hvcNAQEBBQADggIPADCCAgoCggIBAMkr/BYhyo0F2upsIMXwC6QvkZps3NN2/eQF\n",
    "kfQIS1gql0aejsKsEnmY0Kaon8uZCTXPsRH1gQNgg5D2gixdd1mJUvV3dE3y9FJr\n",
    "XMoDkXdCGBodvKJyU6lcfEVF6/UxHcbBguZK9UtRHS9eJYm3rpL/5huQMCppX7kU\n",
    "eQ8dpCwd3iKITqwd1ZudDqsWaU0vqzC2H55IyaZ/5/TnCk31Q1UP6BksbbuRcwOV\n",
    "skEDsm6YoWDnn/IIzGOYnFJRzQH5jTz3j1QBvRIuQuBuvUkfhx1FEwhwZigrcxXu\n",
    "MP+QgM54kezgziJUaZcOM2zF3lvrwMvXDMfNeIoJABv9ljw969xQ8czQCU5lMVmA\n",
    "37ltv5Ec9U5hZuwk/9QO1Z+d/r6Jx0mlurS8gnCAKJgwa3kyZw6e4FZ8mYL4vpRR\n",
    "hPdvRTWCMJkeB4yBHyhxUmTRgJHm6YR3D6hcFAc9cQcTEl/I60tMdz33G6m0O42s\n",
    "Qt/+AR3YCY/RusWVBJB/qNS94EtNtj8iaebCQW1jHAhvGmFILVR9lzD0EzWKHkvy\n",
    "WEjmUVRgCDd6Ne3eFRNS73gdv/C3l5boYySeu4exkEYVxVRn8DhCxs0MnkMHWFK6\n",
    "MyzXCCn+JnWFDYPfDKHvpff/kLDobtPBf+Lbch5wQy9quY27xaj0XwLyjOltpiST\n",
    "LWae/Q4vAgMBAAGjHTAbMAwGA1UdEwQFMAMBAf8wCwYDVR0PBAQDAgEGMA0GCSqG\n",
    "SIb3DQEBDQUAA4ICAQC9fUL2sZPxIN2mD32VeNySTgZlCEdVmlq471o/bDMP4B8g\n",
    "nQesFRtXY2ZCjs50Jm73B2LViL9qlREmI6vE5IC8IsRBJSV4ce1WYxyXro5rmVg/\n",
    "k6a10rlsbK/eg//GHoJxDdXDOokLUSnxt7gk3QKpX6eCdh67p0PuWm/7WUJQxH2S\n",
    "DxsT9vB/iZriTIEe/ILoOQF0Aqp7AgNCcLcLAmbxXQkXYCCSB35Vp06u+eTWjG0/\n",
    "pyS5V14stGtw+fA0DJp5ZJV4eqJ5LqxMlYvEZ/qKTEdoCeaXv2QEmN6dVqjDoTAo\n",
    "k0t5u4YRXzEVCfXAC3ocplNdtCA72wjFJcSbfif4BSC8bDACTXtnPC7nD0VndZLp\n",
    "+RiNLeiENhk0oTC+UVdSc+n2nJOzkCK0vYu0Ads4JGIB7g8IB3z2t9ICmsWrgnhd\n",
    "NdcOe15BincrGA8avQ1cWXsfIKEjbrnEuEk9b5jel6NfHtPKoHc9mDpRdNPISeVa\n",
    "wDBM1mJChneHt59Nh8Gah74+TM1jBsw4fhJPvoc7Atcg740JErb904mZfkIEmojC\n",
    "VPhBHVQ9LHBAdM8qFI2kRK0IynOmAZhexlP/aT/kpEsEPyaZQlnBn3An1CRz8h0S\n",
    "PApL8PytggYKeQmRhl499+6jLxcZ2IegLfqq41dzIjwHwTMplg+1pKIOVojpWA==\n",
    "-----END CERTIFICATE-----\n",
);

pub(super) const NORDVPN_OPENVPN_TLS_AUTH: &str = concat!(
    "#\n",
    "# 2048 bit OpenVPN static key\n",
    "#\n",
    "-----BEGIN OpenVPN Static key V1-----\n",
    "e685bdaf659a25a200e2b9e39e51ff03\n",
    "0fc72cf1ce07232bd8b2be5e6c670143\n",
    "f51e937e670eee09d4f2ea5a6e4e6996\n",
    "5db852c275351b86fc4ca892d78ae002\n",
    "d6f70d029bd79c4d1c26cf14e9588033\n",
    "cf639f8a74809f29f72b9d58f9b8f5fe\n",
    "fc7938eade40e9fed6cb92184abb2cc1\n",
    "0eb1a296df243b251df0643d53724cdb\n",
    "5a92a1d6cb817804c4a9319b57d53be5\n",
    "80815bcfcb2df55018cc83fc43bc7ff8\n",
    "2d51f9b88364776ee9d12fc85cc7ea5b\n",
    "9741c4f598c485316db066d52db4540e\n",
    "212e1518a9bd4828219e24b20d88f598\n",
    "a196c9de96012090e333519ae18d3509\n",
    "9427e7b372d348d352dc4c85e18cd4b9\n",
    "3f8a56ddb2e64eb67adfc9b337157ff4\n",
    "-----END OpenVPN Static key V1-----\n",
);

pub(super) const NORDVPN_OPENVPN_PORTS: &str = "1231 1232 1233 1234";

pub(super) fn plan_vpn_nordvpn_openvpn(
    model: &DeviceModel,
    nv: &VpnNordvpnOpenvpnProfile,
) -> Result<Plan, Unsupported> {
    nv.validate()?;
    let remotes = NORDVPN_OPENVPN_PORTS
        .split_whitespace()
        .map(|port| {
            format!(
                "uci add_list openvpn.nordvpn.remote='{} {port}'",
                nv.station
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    // whole setup rides ONE heredoc (1.x transport_sh): CA, tls-auth
    // and credentials land as static files; validate()'s gates make
    // the credential lines safe
    let body = format!(
        concat!(
            "# Clean up old WireGuard interface + peers\n",
            "uci -q delete network.wg0\n",
            "while uci -q get network.@wireguard_wg0[0] >/dev/null 2>&1; do\n",
            "    uci delete network.@wireguard_wg0[0]\n",
            "done\n",
            "\n",
            "# Tear down any previous OpenVPN instance\n",
            "uci -q delete openvpn.nordvpn\n",
            "\n",
            "mkdir -p /etc/openvpn\n",
            "cat > /etc/openvpn/nordvpn.ca << 'NORD_CA_EOF'\n",
            "{CA}NORD_CA_EOF\n",
            "cat > /etc/openvpn/nordvpn.ta << 'NORD_TA_EOF'\n",
            "{TA}NORD_TA_EOF\n",
            "cat > /etc/openvpn/nordvpn.auth << 'NORD_AUTH_EOF'\n",
            "{USERNAME}\n",
            "{PASSWORD}\n",
            "NORD_AUTH_EOF\n",
            "chmod 600 /etc/openvpn/nordvpn.auth\n",
            "\n",
            "uci -q delete openvpn.nordvpn\n",
            "uci set openvpn.nordvpn=openvpn\n",
            "uci set openvpn.nordvpn.enabled='1'\n",
            "uci set openvpn.nordvpn.client='1'\n",
            "uci set openvpn.nordvpn.dev='tun'\n",
            "uci set openvpn.nordvpn.proto='{PROTO}'\n",
            "{REMOTES}\n",
            "uci set openvpn.nordvpn.resolv_retry='infinite'\n",
            "uci set openvpn.nordvpn.nobind='1'\n",
            "uci set openvpn.nordvpn.persist_key='1'\n",
            "uci set openvpn.nordvpn.persist_tun='1'\n",
            "uci set openvpn.nordvpn.ca='/etc/openvpn/nordvpn.ca'\n",
            "uci set openvpn.nordvpn.auth_user_pass='/etc/openvpn/nordvpn.auth'\n",
            "uci set openvpn.nordvpn.tls_auth='/etc/openvpn/nordvpn.ta'\n",
            "uci set openvpn.nordvpn.key_direction='1'\n",
            "uci set openvpn.nordvpn.verify_x509_name='{HOSTNAME} name'\n",
            "uci set openvpn.nordvpn.remote_cert_tls='server'\n",
            "uci set openvpn.nordvpn.cipher='{CIPHER}'\n",
            "uci set openvpn.nordvpn.data_ciphers='AES-256-GCM:AES-256-CBC'\n",
            "uci set openvpn.nordvpn.auth='SHA512'\n",
            "uci set openvpn.nordvpn.comp_lzo='no'\n",
            "uci set openvpn.nordvpn.mssfix='1450'\n",
            "uci set openvpn.nordvpn.ping='15'\n",
            "uci set openvpn.nordvpn.ping_restart='0'\n",
            "uci set openvpn.nordvpn.verb='3'\n",
            "uci set openvpn.nordvpn.pull='1'\n",
            "uci commit openvpn\n",
            "\n",
            "# Bring tun0 up and attach the vpn zone to it\n",
            "uci -q del_list firewall.vpn_zone.network='wg0'\n",
            "uci -q add_list firewall.vpn_zone.network='tun0'\n",
            "/etc/init.d/openvpn restart || /etc/init.d/openvpn start\n",
        ),
        CA = NORDVPN_OPENVPN_CA,
        TA = NORDVPN_OPENVPN_TLS_AUTH,
        USERNAME = nv.username,
        PASSWORD = nv.password,
        PROTO = nv.proto,
        REMOTES = remotes,
        HOSTNAME = nv.hostname,
        CIPHER = nv.cipher,
    );
    let payload = format!(
        "cat > /tmp/nordvpn_openvpn_setup.sh << 'VPN_SETUP_EOF'\n{}\nVPN_SETUP_EOF\nsh /tmp/nordvpn_openvpn_setup.sh",
        body.trim_end()
    );
    let mut ops = vec![
        PlanOp::EnsurePackage {
            name: "openvpn-openssl".into(),
        },
        PlanOp::Shell { command: payload },
    ];
    // shared vpn composition + the 45s tun-address verify TAIL
    push_vpn_shared_ops(
        &mut ops,
        "tun0",
        &["103.86.96.100", "103.86.99.100"],
        nv.kill_switch,
        nv.allow_management,
        "i=0; while [ $i -lt 45 ]; do if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then echo 'VPN: tun interface verified'; exit 0; fi; sleep 1; i=$((i+1)); done; echo 'VPN: tun interface failed — removing kill switch to restore WAN'; uci delete firewall.vpn_killswitch; uci commit firewall; fw4 restart",
    );
    // honest outcome: verified requires tun0 to hold an address
    let verification = vec![
        VerificationCheck {
            description: "openvpn instance enabled".into(),
            command: "uci -q get openvpn.nordvpn.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "tun0 has an address (tunnel actually up)".into(),
            command: "ip -4 addr show dev tun0 2>/dev/null | grep -q inet && echo up || echo down"
                .into(),
            expect_contains: "up".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-nordvpn-openvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_ssl(model: &DeviceModel, ssl: &SslProfile) -> Result<Plan, Unsupported> {
    ssl.validate()?;
    // libustream-{wolfssl,mbedtls,openssl} all own libustream-ssl.so —
    // installing wolfssl next to an existing backend is a file-clash
    // abort under `set -e` (Codex #486 round 5). ANY backend serves
    // uhttpd TLS, so the plan installs wolfssl only when NO
    // libustream provider is present and preserves the installed one
    // otherwise (1.x's hardcoded wolfssl list entry stays an
    // image-build choice, where a fresh image has no clash).
    let mut ops = vec![
        PlanOp::Shell {
            command: concat!(
                "if ! (opkg list-installed 2>/dev/null || apk info 2>/dev/null) ",
                "| grep -q '^libustream-'; then ",
                // manager-scoped install with the renderer's own
                // fresh-index self-heal (apk update && apk add) — the
                // retry never crosses into the other package manager
                "if command -v apk >/dev/null 2>&1; then ",
                "apk add libustream-wolfssl || { apk update && apk add libustream-wolfssl; }; ",
                "else opkg update && opkg install libustream-wolfssl; fi; fi",
            )
            .into(),
        },
        PlanOp::EnsurePackage {
            name: "ca-bundle".into(),
        },
    ];
    // Both branches are runtime-conditional payloads kept as SINGLE
    // `;`-joined lines: the 1.x transport (apply.py::_run_step_script)
    // routes any line-start `if` through a ` && ` line-join that would
    // mangle a multi-line block into invalid shell (`then && uci …`)
    // — a one-line conditional survives the join untouched. The
    // uhttpd wiring is guarded on the post-flash certs existing:
    // pointed at missing cert files uhttpd drops the HTTPS listener
    // or exits, so a cert-less router must not take the wiring yet
    // (Codex #486 P1 round 2). Each guard reverts its config's staged
    // /tmp/.uci debris first (AGENTS.md staging rule), the
    // listen_https reset stays idempotent (round-1 fix), and the
    // nodogsplash body uses del_list-before-add_list with no trailing
    // `|| true` (rounds 2+4 fixes: failures abort instead of masking
    // as success). The skip path must NOT read as success: with the
    // uhttpd branch enabled, verification requires the certs to exist
    // AND the uci readbacks to show the wiring — a cert-less device
    // fails the apply loudly instead of reporting `applied` for a
    // no-op (Codex #486 P1 round 3). The nds-only configuration keeps
    // no post-hoc checks: its outcome is genuinely runtime-conditional
    // on nodogsplash being installed.
    if ssl.enable_uhttpd_https {
        ops.push(PlanOp::Shell {
            command: concat!(
                "if [ -f /etc/tollgate/ssl/server.crt ] && ",
                "[ -f /etc/tollgate/ssl/server.key ]; then ",
                // &&-chained fail-fast body (the 1.x transport runs
                // control-flow scripts WITHOUT set -e — a `;` chain
                // would let a failed uci set ride a trailing echo to a
                // fake success). Best-effort steps (revert, delete)
                // are isolated in groups so `|| true` cannot swallow a
                // neighboring hard failure; the post-commit readback
                // gates the success echo.
                "(uci -q revert uhttpd 2>/dev/null || true) && ",
                "uci set uhttpd.main.cert='/etc/tollgate/ssl/server.crt' && ",
                "uci set uhttpd.main.key='/etc/tollgate/ssl/server.key' && ",
                "(uci -q delete uhttpd.main.listen_https || true) && ",
                "uci add_list uhttpd.main.listen_https='0.0.0.0:443' && ",
                "uci add_list uhttpd.main.listen_https='[::]:443' && ",
                "uci commit uhttpd && ",
                "uci -q get uhttpd.main.listen_https | grep -q '0.0.0.0:443' && ",
                "/etc/init.d/uhttpd restart && ",
                "echo 'ssl: uhttpd HTTPS wired on :443'; ",
                "else ",
                "echo 'ssl: /etc/tollgate/ssl certs not present yet — skipping uhttpd HTTPS wiring (deploy certs, then re-run)' >&2; ",
                "fi",
            )
            .into(),
        });
    }
    if ssl.open_port_443_nds {
        ops.push(PlanOp::Shell {
            command: concat!(
                "if uci -q show nodogsplash >/dev/null 2>&1; then ",
                "(uci -q revert nodogsplash 2>/dev/null || true) && ",
                "(uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' || true) && ",
                "uci add_list nodogsplash.@nodogsplash[0].users_to_router='allow tcp port 443' && ",
                "uci commit nodogsplash && ",
                "uci -q get nodogsplash.@nodogsplash[0].users_to_router | grep -q 'allow tcp port 443' && ",
                "/etc/init.d/nodogsplash restart && ",
                "echo 'ssl: nodogsplash allows tcp/443 to the router'; ",
                "fi",
            )
            .into(),
        });
    }
    let mut verification = Vec::new();
    if ssl.enable_uhttpd_https {
        verification.extend([
            VerificationCheck {
                description: "certs deployed for uhttpd HTTPS (host-side post-flash step)".into(),
                command: "[ -f /etc/tollgate/ssl/server.crt ] && \
                          [ -f /etc/tollgate/ssl/server.key ] && echo present"
                    .into(),
                expect_contains: "present".into(),
            },
            VerificationCheck {
                description: "uhttpd cert path persisted".into(),
                command: "uci -q get uhttpd.main.cert".into(),
                expect_contains: "/etc/tollgate/ssl/server.crt".into(),
            },
            VerificationCheck {
                description: "uhttpd listens on 443".into(),
                command: "uci -q get uhttpd.main.listen_https".into(),
                expect_contains: "0.0.0.0:443".into(),
            },
        ]);
    }
    Ok(Plan {
        profile_id: "ssl".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_ap_nostr_id(
    model: &DeviceModel,
    ap: &ApNostrIdProfile,
) -> Result<Plan, Unsupported> {
    ap.validate()?;
    let npub24: String = ap.npub.chars().take(24).collect();
    let ops = vec![
        PlanOp::Shell {
            command: "mkdir -p /etc/tollgate".into(),
        },
        PlanOp::Shell {
            command: format!(
                "[ -f /etc/tollgate/ap-nsec ] || printf '%s\\n' '{}' > /etc/tollgate/ap-nsec",
                ap.nsec
            ),
        },
        PlanOp::Shell {
            command: "[ -f /etc/tollgate/ap-nsec ] || chmod 600 /etc/tollgate/ap-nsec".into(),
        },
        PlanOp::Shell {
            command: format!(
                "[ -f /etc/tollgate/ap-npub ] || printf '%s\\n' '{}' > /etc/tollgate/ap-npub",
                ap.npub
            ),
        },
        PlanOp::Shell {
            command: "[ -f /etc/tollgate/ap-npub ] || chmod 644 /etc/tollgate/ap-npub".into(),
        },
        PlanOp::Shell {
            command: format!(
                "for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' | cut -d. -f2 | cut -d= -f1); do uci set wireless.$_s.nas_identifier='{}'; done",
                ap.npub
            ),
        },
        PlanOp::CommitUci {
            config: "wireless".into(),
        },
        PlanOp::Shell {
            command: "wifi reload 2>/dev/null || true".into(),
        },
        PlanOp::Shell {
            command: format!("echo \"AP Nostr identity configured: npub={npub24}...\""),
        },
    ];
    let verification = vec![VerificationCheck {
        description: "ap-npub present and wireless carries nas_identifier".into(),
        command: "[ -f /etc/tollgate/ap-npub ] && uci show wireless \\
                  | grep -q nas_identifier && echo yes"
            .into(),
        expect_contains: "yes".into(),
    }];
    Ok(Plan {
        profile_id: "ap-nostr-id".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_mptcp_bonding(
    model: &DeviceModel,
    mp: &MptcpBondingProfile,
) -> Result<Plan, Unsupported> {
    mp.validate()?;
    // 1.x ships a legacy `apk add curl || opkg …` one-liner here —
    // package delivery, excluded from golden comparison; the 2.x port
    // uses the #421 apk-aware EnsurePackage instead (with the
    // offline-installed guard the raw one-liner lacks).
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "curl".into(),
        },
        PlanOp::Shell {
            command: format!(
                "curl -fsSL owrt.bondingshouldbefree.org | sh -s -- \
                 --server-ipv4 {} --server-port {} --uuid {}",
                mp.server_ipv4, mp.server_port, mp.uuid
            ),
        },
        PlanOp::Shell {
            command: "echo \"BSBF installed. Verify: bsbf-bonding --status\"".into(),
        },
        PlanOp::Shell {
            command: "echo \"Monitor: bsbf-netspeed\"".into(),
        },
        PlanOp::Shell {
            command: "echo \"Uninstall: bsbf-bonding --uninstall\"".into(),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "BSBF client installed".into(),
            command: "command -v bsbf-bonding >/dev/null 2>&1 && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            // upstream MPTCP ABI on 25.12+/SNAPSHOT is the sysctl tree,
            // not the legacy /proc/net/mptcp_net dir the 1.x docstring
            // names — which would false-fail good devices (Codex #600 P2,
            // kernel doc: docs.kernel.org/networking/mptcp-sysctl.html).
            // Reading "1" proves support AND enabled in one probe.
            description: "MPTCP kernel enabled (25.12+/SNAPSHOT prerequisite)".into(),
            command: "cat /proc/sys/net/mptcp/enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            // CVE-2026-98432 (CVSS 9.8): IPv4-TCP-handshake UAF with
            // the proven zero-click-root path against MPTCP listeners;
            // fixed at kernel 6.12.113 (6.6.159 on the 6.6 series).
            // MPTCP-bearing 25.12 kernels are 6.12.x — refuse to call
            // an apply healthy on an unpatched kernel.
            description: "kernel patched for CVE-2026-98432 (>= 6.12.113)".into(),
            command: "K=$(uname -r); awk -v k=\"$K\" 'BEGIN{split(k,a,\"[-.]\"); \
                      if (a[1]>6 || (a[1]==6 && (a[2]>12 || (a[2]==12 && a[3]>=113)))) exit 0; \
                      exit 1}' && echo patched || echo VULNERABLE"
                .into(),
            expect_contains: "patched".into(),
        },
    ];
    Ok(Plan {
        profile_id: "mptcp-bonding".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_vpn_openvpn(
    model: &DeviceModel,
    vo: &VpnOpenvpnProfile,
) -> Result<Plan, Unsupported> {
    vo.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops: Vec<PlanOp> = ["openvpn-openssl", "luci-app-openvpn"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    // 1.x setup script, byte-verbatim: the quoted heredoc makes the
    // config literal (validate() gates the OVPNEOF delimiter);
    // credentials ride UCI overrides — the init script's contract for
    // external-config instances (Codex #603 P1)
    let mut setup = String::new();
    setup.push_str("# Write OpenVPN config\n");
    setup.push_str("mkdir -p /etc/openvpn\n");
    setup.push_str("cat > /etc/openvpn/vpn-client.ovpn << 'OVPNEOF'\n");
    setup.push_str(&vo.ovpn_config);
    setup.push_str("\nOVPNEOF\n");
    ops.push(PlanOp::Shell { command: setup });
    ops.push(PlanOp::CleanupUciSections {
        config: "openvpn".into(),
        pattern: "vpn_client=config-openvpn".into(),
    });
    // the 1.x pattern `config=openvpn` matched NOTHING (uci show
    // renders the declaration with a hyphen; values are quoted) — dead
    // cleanup, so stale options like previous credentials survived
    // re-applies. The matching cleanup deletes the section; the
    // recreate below then rebuilds it option-clean (Codex #603 P2).
    ops.push(PlanOp::CleanupUciSections {
        config: "openvpn".into(),
        pattern: "vpn_client=openvpn".into(),
    });
    // section type `openvpn` (Codex #603 P1): the init script starts
    // instances via `config_foreach start_uci_instance 'openvpn'` —
    // the 1.x type `config-openvpn` was never started at all
    ops.push(PlanOp::Shell {
        command: "uci set openvpn.vpn_client=openvpn".into(),
    });
    let mut client_opts = vec![
        (
            "config".to_string(),
            literal("/etc/openvpn/vpn-client.ovpn".into()),
        ),
        ("enabled".to_string(), literal("1".into())),
    ];
    if !vo.username.is_empty() && !vo.password.is_empty() {
        client_opts.push(("username".to_string(), literal(vo.username.clone())));
        client_opts.push(("password".to_string(), literal(vo.password.clone())));
    }
    ops.push(PlanOp::SetUciOptions {
        config: "openvpn".into(),
        section: "vpn_client".into(),
        options: client_opts,
    });
    ops.push(PlanOp::CommitUci {
        config: "openvpn".into(),
    });
    ops.push(PlanOp::CleanupUciSections {
        config: "network".into(),
        pattern: "proto='openvpn'".into(),
    });
    // proto='openvpn' is NOT a netifd protocol (no handler ships) —
    // the 1.x vpn_if never came up and the zone referencing it never
    // matched. Unmanaged interface on the actual tunnel device, the
    // ansible/roles/pia_openvpn pattern (Codex #603 P1 finding 3).
    ops.push(PlanOp::CleanupUciSections {
        config: "network".into(),
        pattern: "vpn_if=interface".into(),
    });
    ops.push(PlanOp::Shell {
        command: "uci set network.vpn_if=interface".into(),
    });
    ops.push(PlanOp::SetUciOptions {
        config: "network".into(),
        section: "vpn_if".into(),
        options: vec![
            ("proto".to_string(), literal("none".into())),
            ("device".to_string(), literal("tun0".into())),
        ],
    });
    ops.push(PlanOp::CommitUci {
        config: "network".into(),
    });
    // shared firewall block (base.py build_firewall_ops, iface=vpn_if,
    // management on, kill switch per profile)
    for pattern in [
        "name='vpn'",
        "dest='vpn'",
        "name='KillSwitch-Reject-NonVPN'",
        "name='Allow-VPN-Management'",
    ] {
        ops.push(PlanOp::CleanupUciSections {
            config: "firewall".into(),
            pattern: pattern.into(),
        });
    }
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_zone".into(),
        section_type: "zone".into(),
        options: vec![
            ("name".into(), literal("vpn".into())),
            ("input".into(), literal("REJECT".into())),
            ("output".into(), literal("ACCEPT".into())),
            ("forward".into(), literal("REJECT".into())),
            ("masq".into(), literal("1".into())),
            ("mtu_fix".into(), literal("1".into())),
            ("network".into(), literal("vpn_if".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_fwd".into(),
        section_type: "forwarding".into(),
        options: vec![
            ("src".into(), literal("lan".into())),
            ("dest".into(), literal("vpn".into())),
        ],
    });
    ops.push(PlanOp::SetUciSection {
        config: "firewall".into(),
        section: "vpn_mgmt".into(),
        section_type: "rule".into(),
        options: vec![
            ("name".into(), literal("Allow-VPN-Management".into())),
            ("src".into(), literal("vpn".into())),
            ("proto".into(), literal("tcp".into())),
            ("dest_port".into(), literal("22 80 443".into())),
            ("target".into(), literal("ACCEPT".into())),
        ],
    });
    if vo.kill_switch {
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: "vpn_killswitch".into(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal("KillSwitch-Reject-NonVPN".into())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("proto".into(), literal("all".into())),
                ("target".into(), literal("REJECT".into())),
            ],
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    ops.push(PlanOp::Service {
        name: "openvpn".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Service {
        name: "network".into(),
        action: ServiceAction::Restart,
    });
    // fail-open tail (base.py build_verify_ops, kind=openvpn): the
    // commits/restarts are idempotent; the 45s tun-check auto-removes
    // the kill switch when the tunnel never comes up — the pairing
    // the 1.x preset forgot (fixed with this port)
    ops.push(PlanOp::CommitUci {
        config: "network".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "dhcp".into(),
    });
    ops.push(PlanOp::Service {
        name: "network".into(),
        action: ServiceAction::Restart,
    });
    ops.push(PlanOp::Service {
        name: "dnsmasq".into(),
        action: ServiceAction::Restart,
    });
    if vo.kill_switch {
        ops.push(PlanOp::Shell {
            command: "i=0; while [ $i -lt 45 ]; do \
                      if ip -4 addr show dev tun0 2>/dev/null | grep -q inet; then \
                      echo 'VPN: tun interface verified'; exit 0; \
                      fi; sleep 1; i=$((i+1)); \
                      done; \
                      echo 'VPN: tun interface failed — removing kill switch to restore WAN'; \
                      uci delete firewall.vpn_killswitch; \
                      uci commit firewall; \
                      fw4 restart"
                .into(),
        });
    }
    let verification = vec![
        VerificationCheck {
            description: "openvpn service section enabled".into(),
            command: "uci -q get openvpn.vpn_client.enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "tun interface carrying an address".into(),
            command: "ip -4 addr show dev tun0 2>/dev/null | grep -q inet && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "vpn-openvpn".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_tollgate(
    model: &DeviceModel,
    tg: &TollgateProfile,
) -> Result<Plan, Unsupported> {
    tg.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    // TLS-backend guard (plan_ssl's, Codex #601 P2): the libustream
    // variants all own libustream-ssl.so — unconditionally installing
    // wolfssl next to an existing backend is a file-clash abort under
    // `set -e` before the portal is configured. Install only when NO
    // provider is present (the 1.x packages list entry stays an
    // image-build choice); excluded from golden parity by the
    // established ssl-guard comparator filter.
    let mut ops: Vec<PlanOp> = vec![PlanOp::Shell {
        command: concat!(
            "if ! (opkg list-installed 2>/dev/null || apk info 2>/dev/null) ",
            "| grep -q '^libustream-'; then ",
            "if command -v apk >/dev/null 2>&1; then ",
            "apk add libustream-wolfssl || { apk update && apk add libustream-wolfssl; }; ",
            "else opkg update && opkg install libustream-wolfssl; fi; fi",
        )
        .into(),
    }];
    ops.extend(
        ["nodogsplash", "ca-bundle", "ca-certificates"]
            .iter()
            .map(|name| PlanOp::EnsurePackage {
                name: (*name).into(),
            }),
    );
    ops.push(PlanOp::SetUciOptions {
        config: "nodogsplash".into(),
        section: "@nodogsplash[0]".into(),
        options: vec![("enabled".into(), literal("1".into()))],
    });
    let mut branding = Vec::new();
    if !tg.gateway_name.is_empty() {
        branding.push(("gatewayname".to_string(), tg.gateway_name.clone()));
    }
    if !tg.gateway_domain.is_empty() {
        branding.push(("gatewaydomainname".to_string(), tg.gateway_domain.clone()));
    }
    if !tg.clientid.is_empty() {
        branding.push(("clientid".to_string(), tg.clientid.clone()));
    }
    if !branding.is_empty() {
        ops.push(PlanOp::SetUciOptions {
            config: "nodogsplash".into(),
            section: "@nodogsplash[0]".into(),
            options: branding.into_iter().map(|(k, v)| (k, literal(v))).collect(),
        });
    }
    // guarded del_list before each add_list — idempotent re-configure
    // (1.x plain-appended duplicates; fixed Python-side with this port)
    let mut rules = vec!["allow tcp port 2121", "allow tcp port 2050"];
    if tg.allow_lan_ssh {
        rules.push("allow tcp port 22");
    }
    for rule in rules {
        ops.push(PlanOp::Shell {
            command: format!(
                "uci -q del_list nodogsplash.@nodogsplash[0].users_to_router='{rule}' \
                 2>/dev/null || true"
            ),
        });
        ops.push(PlanOp::UciAddList {
            config: "nodogsplash".into(),
            section: "@nodogsplash[0]".into(),
            option: "users_to_router".into(),
            value: rule.into(),
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "nodogsplash".into(),
    });
    ops.push(PlanOp::Service {
        name: "nodogsplash".into(),
        action: ServiceAction::Enable,
    });
    ops.push(PlanOp::Service {
        name: "nodogsplash".into(),
        action: ServiceAction::Restart,
    });
    if tg.install_hotplug {
        // 1.x _HOTPLUG_SCRIPT, byte-verbatim (the \u2014 in the logger
        // line is a LITERAL escape sequence in the 1.x source, kept)
        let iface = &tg.hotplug_interface;
        ops.push(PlanOp::Shell {
            command: format!(
                "mkdir -p /etc/hotplug.d/iface && \
                 printf '%s' '#!/bin/sh\n\
                 [ \"$ACTION\" = \"ifup\" ] || exit 0\n\
                 [ \"$INTERFACE\" = \"{iface}\" ] || exit 0\n\
                 logger -t tollgate-hotplug \"{iface} up \\u2014 restarting tollgate\"\n\
                 /etc/init.d/tollgate-wrt restart &\n\
                 ' > /etc/hotplug.d/iface/95-tollgate-restart && \
                 chmod +x /etc/hotplug.d/iface/95-tollgate-restart"
            ),
        });
    }
    if !tg.mint_url.is_empty() || !tg.lightning_address.is_empty() || tg.price_per_minute != 1 {
        ops.push(PlanOp::Shell {
            command: "touch /etc/config/tollgate".into(),
        });
        let mut values: Vec<(String, UciValue)> = Vec::new();
        if !tg.mint_url.is_empty() {
            values.push(("mint_url".into(), literal(tg.mint_url.clone())));
        }
        if !tg.lightning_address.is_empty() {
            values.push((
                "lightning_address".into(),
                literal(tg.lightning_address.clone()),
            ));
        }
        if tg.price_per_minute != 1 {
            values.push((
                "price_per_minute".into(),
                literal(tg.price_per_minute.to_string()),
            ));
        }
        // named section — 1.x's anonymous `uci add` accumulated one
        // section per re-run (fixed Python-side with this port)
        ops.push(PlanOp::Shell {
            command: "uci set tollgate.payment=tollgate".into(),
        });
        ops.push(PlanOp::SetUciOptions {
            config: "tollgate".into(),
            section: "payment".into(),
            options: values,
        });
        ops.push(PlanOp::CommitUci {
            config: "tollgate".into(),
        });
    }
    if let Some((price, _origin)) = tg.derived_price_checked()? {
        ops.push(PlanOp::Shell {
            command: format!(
                "if [ -f /etc/tollgate/config.json ]; then \
                 SS=$(sed -n 's/.*\"step_size\":[ ]*\\([0-9][0-9]*\\).*/\\1/p' \
                 /etc/tollgate/config.json | head -1); \
                 [ -n \"$SS\" ] || SS=1048576; \
                 P=$(( ( {price} * SS + 1048575 ) / 1048576 )); \
                 sed -i 's/\"price_per_step\":[ ]*[0-9]*/\"price_per_step\": '\"$P\"'/g' \
                 /etc/tollgate/config.json \
                 && /etc/init.d/tollgate-wrt restart 2>/dev/null \
                 && echo \"tollgate: price_per_step=$P applied (step_size=$SS bytes; {price} sat/MiB)\" \
                 || echo \"tollgate: price patch FAILED on existing config.json\"; \
                 else echo \"tollgate: /etc/tollgate/config.json absent (ipk not installed yet) \
                 — re-run configure after deploy_tollgate_post_flash\"; fi"
            ),
        });
    }
    let mut verification = vec![
        VerificationCheck {
            description: "nodogsplash enabled".into(),
            command: "uci -q get nodogsplash.@nodogsplash[0].enabled".into(),
            expect_contains: "1".into(),
        },
        VerificationCheck {
            description: "portal service enabled at boot".into(),
            command: "/etc/init.d/nodogsplash enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    if !tg.mint_url.is_empty() {
        verification.push(VerificationCheck {
            description: "payment mint url persisted".into(),
            command: "uci -q get tollgate.payment.mint_url".into(),
            expect_contains: tg.mint_url.clone(),
        });
    }
    Ok(Plan {
        profile_id: "tollgate".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_tollgate_security(
    model: &DeviceModel,
    _ts: &TollgateSecurityProfile,
) -> Result<Plan, Unsupported> {
    let literal = |v: String| UciValue::Literal(v);
    let ranges = [
        ("10", "10.0.0.0/8"),
        ("172", "172.16.0.0/12"),
        ("192", "192.168.0.0/16"),
        ("LL", "169.254.0.0/16"),
    ];
    let mut ops: Vec<PlanOp> = Vec::new();
    for (suffix, cidr) in ranges {
        let name = format!("Block-LAN-To-RFC1918-{suffix}");
        ops.push(PlanOp::SetUciSection {
            config: "firewall".into(),
            section: name.clone(),
            section_type: "rule".into(),
            options: vec![
                ("name".into(), literal(name.clone())),
                ("src".into(), literal("lan".into())),
                ("dest".into(), literal("wan".into())),
                ("dest_ip".into(), literal(cidr.into())),
                ("proto".into(), literal("all".into())),
                ("family".into(), literal("ipv4".into())),
                ("target".into(), literal("DROP".into())),
            ],
        });
    }
    ops.push(PlanOp::CommitUci {
        config: "firewall".into(),
    });
    // Codex #601 P1: committed UCI alone leaves the RUNNING firewall
    // open until some later reload — activate before apply reports
    // success, and verify the LIVE ruleset (below), not just UCI.
    ops.push(PlanOp::Service {
        name: "firewall".into(),
        action: ServiceAction::Restart,
    });
    // client isolation over DISCOVERED wifi-iface sections (Codex #601
    // P2 round 2): hardcoded default_radio0/1 aborted mid-apply on
    // single-radio devices under `set -e` — firewall already
    // activated, isolation never applied. Factory section names are
    // not a guarantee; `done; true` guards zero-iface devices.
    ops.push(PlanOp::Shell {
        command: "for _s in $(uci show wireless 2>/dev/null | grep '=wifi-iface' \
                  | cut -d. -f2 | cut -d= -f1); do \
                  uci set wireless.$_s.isolate='1'; done; true"
            .into(),
    });
    ops.push(PlanOp::CommitUci {
        config: "wireless".into(),
    });
    ops.push(PlanOp::Shell {
        command: "wifi reload".into(),
    });
    let verification = vec![
        VerificationCheck {
            description: "ISP-LAN block rule persisted".into(),
            command: "uci -q get firewall.Block-LAN-To-RFC1918-192.target".into(),
            expect_contains: "DROP".into(),
        },
        VerificationCheck {
            description: "client isolation set on at least one wifi-iface".into(),
            command: "uci show wireless 2>/dev/null | grep -q \"isolate='1'\" && echo yes".into(),
            expect_contains: "yes".into(),
        },
        VerificationCheck {
            description: "block rule LIVE in the fw4 ruleset (effective \
                          protection, not just staged UCI)"
                .into(),
            // whole TABLE, not the base forward chain: fw4 emits
            // src='lan' rules into the forward_lan zone chain, and
            // `list chain` does not recurse into jump targets (Codex
            // #601 P1 round 2)
            command: "nft list table inet fw4 2>/dev/null \
                      | grep -q Block-LAN-To-RFC1918-192 && echo yes"
                .into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "tollgate-security".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_nodns(model: &DeviceModel, nd: &NodnsProfile) -> Result<Plan, Unsupported> {
    nd.validate()?;
    // curl is NOT in every base image (the preset's "no packages" claim
    // holds only where curl ships in base) — EnsurePackage it; the
    // golden comparator filters package lines, so parity is unaffected
    let mut ops: Vec<PlanOp> = vec![PlanOp::EnsurePackage {
        name: "curl".into(),
    }];
    let poll_script = substitute_tokens(
        NODNS_POLL_SCRIPT_TEMPLATE,
        &[
            ("__URL__", nd.api_url.as_str()),
            ("__ZONE__", nd.zone.as_str()),
            ("__POLL_INTERVAL__", &nd.poll_interval.to_string()),
        ],
    );
    ops.extend([
        PlanOp::Shell {
            command: "mkdir -p /etc/dnsmasq.d".into(),
        },
        PlanOp::Shell {
            command: "touch /etc/dnsmasq.d/nodns.hosts".into(),
        },
        PlanOp::Shell {
            command: format!(
                "cat > /etc/init.d/nodns-bridge << 'NODNS_INIT_EOF'\n{NODNS_INITD_SCRIPT}NODNS_INIT_EOF"
            ),
        },
        PlanOp::Shell {
            command: "chmod +x /etc/init.d/nodns-bridge".into(),
        },
        PlanOp::Shell {
            command: format!(
                "cat > /usr/bin/nodns-poll.sh << 'NODNS_POLL_EOF'\n{poll_script}NODNS_POLL_EOF"
            ),
        },
        PlanOp::Shell {
            command: "chmod +x /usr/bin/nodns-poll.sh".into(),
        },
        PlanOp::Shell {
            command:
                "uci -q del_list dhcp.@dnsmasq[0].addnhosts='/etc/dnsmasq.d/nodns.hosts'; true"
                    .into(),
        },
        PlanOp::UciAddList {
            config: "dhcp".into(),
            section: "@dnsmasq[0]".into(),
            option: "addnhosts".into(),
            value: "/etc/dnsmasq.d/nodns.hosts".into(),
        },
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        PlanOp::Service {
            name: "dnsmasq".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Service {
            name: "nodns-bridge".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "nodns-bridge".into(),
            action: ServiceAction::Start,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"nodns bridge configured: zone={} interval={}s url={}\"",
                nd.zone, nd.poll_interval, nd.api_url
            ),
        },
    ]);
    let verification = vec![VerificationCheck {
        description: "dnsmasq addnhosts registered".into(),
        command: "uci -q get dhcp.@dnsmasq[0].addnhosts".into(),
        expect_contains: "/etc/dnsmasq.d/nodns.hosts".into(),
    }];
    Ok(Plan {
        profile_id: "nodns".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_auto_sqm(
    model: &DeviceModel,
    asq: &AutoSqmProfile,
) -> Result<Plan, Unsupported> {
    asq.validate()?;
    let literal = |v: String| UciValue::Literal(v);
    let mut ops: Vec<PlanOp> = ["sqm-scripts", "luci-app-sqm", "jsonfilter", "iperf3"]
        .iter()
        .map(|name| PlanOp::EnsurePackage {
            name: (*name).into(),
        })
        .collect();
    ops.push(PlanOp::Shell {
        command: "touch /etc/config/auto_sqm".into(),
    });
    ops.push(PlanOp::SetUciSection {
        config: "auto_sqm".into(),
        section: "config".into(),
        section_type: "auto_sqm".into(),
        options: vec![
            ("mode".into(), literal(asq.mode.clone())),
            ("interface".into(), literal(asq.interface.clone())),
            ("device".into(), literal(asq.device.clone())),
            (
                "target_percent".into(),
                literal(asq.target_percent.to_string()),
            ),
            ("qdisc".into(), literal(asq.qdisc.clone())),
            ("script".into(), literal(asq.script.clone())),
            (
                "measurement_mode".into(),
                literal(asq.measurement_mode.clone()),
            ),
            ("iperf3_host".into(), literal(asq.iperf3_host.clone())),
            ("iperf3_port".into(), literal(asq.iperf3_port.to_string())),
            ("test_url".into(), literal(asq.test_url.clone())),
            (
                "download_kbps".into(),
                literal(asq.download_kbps.to_string()),
            ),
            ("upload_kbps".into(), literal(asq.upload_kbps.to_string())),
            (
                "upload_fallback_kbps".into(),
                literal(asq.upload_fallback_kbps.to_string()),
            ),
            (
                "hysteresis_percent".into(),
                literal(asq.hysteresis_percent.to_string()),
            ),
            (
                "dynamic_interval_hours".into(),
                literal(asq.dynamic_interval_hours.to_string()),
            ),
        ],
    });
    ops.push(PlanOp::CommitUci {
        config: "auto_sqm".into(),
    });
    ops.push(PlanOp::Shell {
        command: "cat <<'AUTO_SQM_EOF' > /usr/sbin/auto-sqm".into(),
    });
    // 1.x emits one Shell op per script line INCLUDING blanks — the
    // heredoc body must stay byte-faithful on-device (shell_lines
    // drops empties; that helper is for non-heredoc surfaces)
    for line in AUTO_SQM_SCRIPT.lines() {
        ops.push(PlanOp::Shell {
            command: line.into(),
        });
    }
    ops.push(PlanOp::Shell {
        command: "AUTO_SQM_EOF".into(),
    });
    ops.push(PlanOp::Shell {
        command: "chmod +x /usr/sbin/auto-sqm".into(),
    });
    ops.push(PlanOp::Shell {
        command: "mkdir -p /etc/hotplug.d/iface".into(),
    });
    ops.push(PlanOp::Shell {
        command: "cat <<'HOTPLUG_EOF' > /etc/hotplug.d/iface/10-sqm-autotune".into(),
    });
    ops.push(PlanOp::Shell {
        command: "#!/bin/sh".into(),
    });
    ops.push(PlanOp::Shell {
        command: format!(
            "[ \"$ACTION\" = \"ifup\" ] && [ \"$INTERFACE\" = \"{}\" ] && /usr/sbin/auto-sqm &",
            asq.interface
        ),
    });
    ops.push(PlanOp::Shell {
        command: "HOTPLUG_EOF".into(),
    });
    ops.push(PlanOp::Shell {
        command: "chmod +x /etc/hotplug.d/iface/10-sqm-autotune".into(),
    });
    if asq.mode == "dynamic" {
        ops.push(PlanOp::Shell {
            // idempotent re-apply: drop any previous auto-sqm entry before
            // appending (plain append accumulates duplicate jobs — the
            // 1.x shape; comparator filters both line forms, unit-pinned)
            command: format!(
                "sed -i '/auto-sqm/d' /etc/crontabs/root 2>/dev/null; \
                 echo '0 */{} * * * /usr/sbin/auto-sqm' >> /etc/crontabs/root",
                asq.dynamic_interval_hours
            ),
        });
        ops.push(PlanOp::Service {
            name: "cron".into(),
            action: ServiceAction::Enable,
        });
        ops.push(PlanOp::Service {
            name: "cron".into(),
            action: ServiceAction::Restart,
        });
    }
    if asq.mode == "static" && asq.download_kbps > 0 {
        ops.push(PlanOp::Shell {
            command: "/usr/sbin/auto-sqm".into(),
        });
    } else {
        ops.push(PlanOp::Shell {
            command: "echo 'auto-sqm: will measure and configure on WAN ifup'".into(),
        });
    }
    ops.push(PlanOp::Shell {
        command: "echo 'Auto-SQM configured'".into(),
    });
    let verification = vec![VerificationCheck {
        description: "auto_sqm config persisted".into(),
        command: "uci -q get auto_sqm.config.mode".into(),
        expect_contains: asq.mode.clone(),
    }];
    Ok(Plan {
        profile_id: "auto-sqm".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_guest_wifi(
    model: &DeviceModel,
    gw: &GuestWifiProfile,
) -> Result<Plan, Unsupported> {
    gw.validate()?;
    let net = &gw.network_name;
    let ssid_q = shell_quote(&gw.ssid);
    let key_q = shell_quote(&gw.key);
    let band_short = format!("{}g", gw.band.chars().next().unwrap_or('2'));
    let isolated = if gw.isolation { "1" } else { "0" };
    let literal = |v: String| UciValue::Literal(v);
    let section = |config: &str,
                   section: &str,
                   section_type: &str,
                   options: Vec<(&str, String)>| PlanOp::SetUciSection {
        config: config.into(),
        section: section.into(),
        section_type: section_type.into(),
        options: options
            .into_iter()
            .map(|(k, v)| (k.into(), literal(v)))
            .collect(),
    };

    // Guest subnet derives from the live LAN IP (third octet + 1) at
    // apply time — these lines are shell ops, exactly like 1.x.
    let mut ops = vec![
        PlanOp::Shell {
            command: "_lan_ip=$(uci get network.lan.ipaddr 2>/dev/null || echo '192.168.1.1')"
                .into(),
        },
        PlanOp::Shell {
            command: "_guest_o3=$(echo \"$_lan_ip\" | cut -d. -f3)".into(),
        },
        PlanOp::Shell {
            command: "_guest_o3=$((_guest_o3 + 1))".into(),
        },
        PlanOp::Shell {
            command: "[ \"$_guest_o3\" -gt 255 ] && _guest_o3=0".into(),
        },
        PlanOp::Shell {
            command: "_guest_prefix=$(echo \"$_lan_ip\" | cut -d. -f1-2).$_guest_o3".into(),
        },
        // Radio discovery + HARD GATE before any section is written
        // (#454): a band the device lacks aborts with ZERO partial
        // config. The loop's uci get is set -e-safe (missing radios
        // fail their get) — the old shape committed network/dhcp/
        // firewall first and only then probed.
        PlanOp::Shell {
            command: format!(
                "_radio=\"\"; for _r in radio0 radio1 radio2 radio3; do \
                 _b=$(uci get wireless.${{_r}}.band 2>/dev/null || true); \
                 if [ \"$_b\" = \"{band_short}\" ]; then _radio=$_r; break; fi; done; \
                 if [ -z \"$_radio\" ]; then \
                 echo 'guest-wifi: no {band_short} radio found — aborting before any config changes' >&2; \
                 exit 1; fi"
            ),
        },
        section("network", net, "interface", vec![]),
        PlanOp::Shell {
            command: format!("uci set network.{net}.ipaddr=\"$_guest_prefix.1\""),
        },
        PlanOp::SetUciOptions {
            config: "network".into(),
            section: net.clone(),
            options: vec![
                ("proto".into(), literal("static".into())),
                ("netmask".into(), literal("255.255.255.0".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "network".into(),
        },
        section(
            "dhcp",
            net,
            "dhcp",
            vec![
                ("interface", net.clone()),
                ("start", "100".into()),
                ("limit", "50".into()),
                ("leasetime", "1h".into()),
            ],
        ),
        PlanOp::CommitUci {
            config: "dhcp".into(),
        },
        section(
            "firewall",
            net,
            "zone",
            vec![
                ("name", net.clone()),
                ("network", net.clone()),
                ("input", "REJECT".into()),
                ("output", "ACCEPT".into()),
                ("forward", "REJECT".into()),
            ],
        ),
        section(
            "firewall",
            &format!("{net}_fwd"),
            "forwarding",
            vec![("src", net.clone()), ("dest", "wan".into())],
        ),
        section(
            "firewall",
            &format!("{net}_dns"),
            "rule",
            vec![
                ("name", format!("Allow-DNS-{net}")),
                ("src", net.clone()),
                ("dest_port", "53".into()),
                ("proto", "tcpudp".into()),
                ("target", "ACCEPT".into()),
            ],
        ),
        section(
            "firewall",
            &format!("{net}_dhcp"),
            "rule",
            vec![
                ("name", format!("Allow-DHCP-{net}")),
                ("src", net.clone()),
                ("dest_port", "67-68".into()),
                ("proto", "udp".into()),
                ("target", "ACCEPT".into()),
            ],
        ),
        PlanOp::CommitUci {
            config: "firewall".into(),
        },
        PlanOp::CleanupUciSections {
            config: "wireless".into(),
            pattern: format!("network='{net}'"),
        },
    ];
    // Radio discovery by band (1.x `_radio` loop) + named VAP section
    // (idempotent — overwrites on reconfigure). $_radio is guaranteed by
    // the hard gate before the first commit (#454) — the VAP sets are
    // unconditional; the loop itself now lives up front with the gate.
    let mut radio_line = format!(
        "uci set wireless.guest_ap=wifi-iface; \
         uci set wireless.guest_ap.device=$_radio; \
         uci set wireless.guest_ap.mode=ap; \
         uci set wireless.guest_ap.ssid={ssid_q}; \
         uci set wireless.guest_ap.encryption={}; \
         ",
        gw.encryption
    );
    if !gw.key.is_empty() {
        radio_line.push_str(&format!("uci set wireless.guest_ap.key={key_q}; "));
    }
    radio_line.push_str(&format!(
        "uci set wireless.guest_ap.network={net}; \
         uci set wireless.guest_ap.isolate={isolated}"
    ));
    ops.push(PlanOp::Shell {
        command: radio_line,
    });
    ops.extend([
        PlanOp::CommitUci {
            config: "wireless".into(),
        },
        PlanOp::Service {
            name: "network".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Service {
            name: "firewall".into(),
            action: ServiceAction::Restart,
        },
        PlanOp::Shell {
            command: format!(
                "echo \"Guest WiFi configured: SSID={ssid_q} network={net} isolated={isolated}\""
            ),
        },
    ]);
    let verification = vec![
        VerificationCheck {
            description: "guest firewall zone persisted".into(),
            command: format!("uci -q get firewall.{net}.name"),
            expect_contains: net.clone(),
        },
        VerificationCheck {
            description: "guest DNS rule persisted".into(),
            command: format!("uci -q get firewall.{net}_dns.dest_port"),
            expect_contains: "53".into(),
        },
    ];
    Ok(Plan {
        profile_id: "guest-wifi".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}

pub(super) fn plan_sqm(model: &DeviceModel, sqm: &SqmProfile) -> Result<Plan, Unsupported> {
    sqm.validate()?;
    let iface = &sqm.interface;
    let literal = |v: String| UciValue::Literal(v);
    // Op-for-op mirror of the 1.x builder (`scripts/use_cases/sqm.py`
    // `_build_sqm_ops`), closing the parity GAP recorded in
    // tests/fixtures/parity/manifest.json:
    //
    // - no `RevertUci` step: 1.x has no revert; its clear-sections loop
    //   below already deletes every staged AND committed `queue` section
    //   (`uci show` displays the merged view) before the fresh values are
    //   staged, so leftover `/tmp/.uci` debris cannot survive the commit.
    // - device resolution, section creation, and the `interface=` line
    //   render as the exact 1.x one-line shell idioms (`_sqm_dev`), in
    //   1.x order: create → interface → values. A typed
    //   `ResolveNetworkDevice` op renders a multi-line if/fi block with a
    //   `_conwrt_dev_wan` variable — same semantics, different bytes.
    // - the final echo summary line is part of the 1.x contract.
    //
    // The `EnsurePackage` preamble stays: like wireguard/doh/tether, it is
    // a deliberate 2.x extension excluded from parity comparison by the
    // shared normalization (see `parity.rs::command_lines`), because 1.x
    // delivers packages out-of-band (`UseCase.packages` bakes them into
    // the image).
    let ops = vec![
        PlanOp::EnsurePackage {
            name: "sqm-scripts".into(),
        },
        PlanOp::EnsurePackage {
            name: "luci-app-sqm".into(),
        },
        PlanOp::Shell {
            command: "for _s in $(uci -q show sqm 2>/dev/null | grep '=queue' | cut -d. -f2 | cut -d= -f1); do uci -q delete sqm.$_s; done; true".into(),
        },
        // Resolve UCI network name to actual linux device (e.g. wan →
        // phy1-sta0 on WiFi STA) — the 1.x `wan` lesson, 1.x shape.
        PlanOp::Shell {
            command: format!(
                "_sqm_dev=$(uci get network.{iface}.device 2>/dev/null || true); \
                 if [ -z \"$_sqm_dev\" ] || ! ip addr show \"$_sqm_dev\" 2>/dev/null | grep -q \"inet \"; then \
                 _sqm_dev=$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{{print $5}}' | head -1); fi; \
                 if [ -z \"$_sqm_dev\" ]; then _sqm_dev={iface}; fi"
            ),
        },
        PlanOp::Shell {
            command: format!("uci set sqm.{iface}=queue"),
        },
        // interface must be the actual device name, not a UCI network name
        PlanOp::Shell {
            command: format!("uci set sqm.{iface}.interface=\"$_sqm_dev\""),
        },
        PlanOp::SetUciOptions {
            config: "sqm".into(),
            section: iface.clone(),
            options: vec![
                ("enabled".into(), literal("1".into())),
                ("script".into(), literal(sqm.script.clone())),
                ("qdisc".into(), literal(sqm.qdisc.clone())),
                ("linklayer".into(), literal(sqm.link_layer.clone())),
                ("overhead".into(), literal(sqm.overhead.to_string())),
                ("download".into(), literal(sqm.download_kbps.to_string())),
                ("upload".into(), literal(sqm.upload_kbps.to_string())),
                (
                    "linklayer_adaptation_mechanism".into(),
                    literal("default".into()),
                ),
                ("debug_logging".into(), literal("0".into())),
                ("verbosity".into(), literal("5".into())),
            ],
        },
        PlanOp::CommitUci {
            config: "sqm".into(),
        },
        PlanOp::Service {
            name: "sqm".into(),
            action: ServiceAction::Enable,
        },
        PlanOp::Service {
            name: "sqm".into(),
            action: ServiceAction::Restart,
        },
        // 1.x closes with the human-facing summary on the resolved device
        PlanOp::Shell {
            command: format!(
                "echo \"SQM configured: {}/{} kbit/s ({}) on $_sqm_dev\"",
                sqm.download_kbps, sqm.upload_kbps, sqm.qdisc
            ),
        },
    ];
    let verification = vec![
        VerificationCheck {
            description: "download shaper rate persisted exactly".into(),
            command: format!(
                "test \"$(uci -q get sqm.{iface}.download)\" = {rate} && echo ok",
                rate = shell_quote(&sqm.download_kbps.to_string())
            ),
            expect_contains: "ok".into(),
        },
        VerificationCheck {
            // Codex P2 on #127: the download-only check let a lost upload
            // assignment pass every verification gate.
            description: "upload shaper rate persisted exactly".into(),
            command: format!(
                "test \"$(uci -q get sqm.{iface}.upload)\" = {rate} && echo ok",
                rate = shell_quote(&sqm.upload_kbps.to_string())
            ),
            expect_contains: "ok".into(),
        },
        VerificationCheck {
            // Scope to the shaped device: a global `tc qdisc show` is
            // satisfied by a matching qdisc on ANY interface (e.g. stale
            // state elsewhere), which would false-verify the apply.
            description: "qdisc active on the shaped device".into(),
            command: format!(
                "_d=$(uci get network.{iface}.device 2>/dev/null || true); \
                 if [ -z \"$_d\" ] || ! ip addr show \"$_d\" 2>/dev/null | grep -q 'inet '; then \
                 _d=$(ip route show default 0.0.0.0/0 2>/dev/null | awk '{{print $5}}' | head -1); fi; \
                 if [ -z \"$_d\" ]; then _d={iface}; fi; \
                 tc qdisc show dev \"$_d\""
            ),
            expect_contains: sqm.qdisc.clone(),
        },
        VerificationCheck {
            description: "service enabled at boot".into(),
            command: "/etc/init.d/sqm enabled && echo yes".into(),
            expect_contains: "yes".into(),
        },
    ];
    Ok(Plan {
        profile_id: "sqm".into(),
        model_id: model.id.clone(),
        ops,
        verification,
        warnings: Vec::new(),
    })
}
