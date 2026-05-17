# Redaction Patterns Specification

This document is the canonical reference for all redaction patterns used in the
conwrt project. It defines exactly which patterns are redacted, what tokens
replace them, and why each pattern matters.

---

## 1. Introduction

Network device investigation artifacts contain identifiers that can expose the
operator's identity, location, or specific hardware. Sharing these artifacts
openly (in a public repo, bug report, or forum post) without redaction would
leak sensitive information.

conwrt uses a two-artifact model to handle this:

- **Raw artifacts** (in `raw/`): These are the original, unmodified outputs
  from the investigation workflow. They stay local-only and are never committed
  to git. They may contain PII, public IPs, serial numbers, and other
  identifiers that could identify the operator or their network.

- **Redacted artifacts** (in `redacted/`): These are safe to commit and share.
  Every sensitive identifier has been replaced with a typed token like
  `<REDACTED:SERIAL>` or `<REDACTED:HOSTNAME>`. The structure and diagnostic
  value of the artifact is preserved, but the specific identifying values are
  gone.

The goal is to make redacted artifacts useful for debugging and collaboration
without exposing anything that could identify the operator.

---

## 2. Two-Pass Redaction Policy

Redaction happens in two stages, providing defense in depth.

### Pass 1: LLM Self-Redaction

The system prompt instructs the LLM to redact sensitive values before writing
any artifact to disk. This catches the vast majority of identifiers at the
source. The LLM understands context (e.g., it knows a serial number next to
"Serial Number" is sensitive, while a version number next to "Firmware" is not).

### Pass 2: Deterministic Script

After the LLM writes its output, `scripts/redact-output.sh` runs as a safety
net. This shell script applies the regex patterns defined in this document
using `sed -E`. It catches anything the LLM missed and provides a consistent,
auditable transformation.

Both passes must succeed for an artifact to appear in `redacted/`.

---

## 3. Fail-Closed Policy

Redaction failures are not silent. The system operates under a strict
fail-closed policy:

- If the redaction script encounters an error applying any pattern, the script
  **ABORTS** and leaves the `redacted/` directory empty.
- If the post-redaction verification scan finds any unredacted sensitive data,
  the script **ABORTS** and leaves the `redacted/` directory empty.
- The operator is alerted to the failure with a clear error message.
- Raw artifacts are **never** promoted to `redacted/` on failure. An empty or
  partially redacted artifact is worse than no artifact at all, because it
  creates a false sense of safety.

No artifact is published unless every pattern has been applied and verified.

---

## 4. Allowlist

Some values match sensitive patterns but are explicitly safe to keep. These are
public knowledge, not operator-specific. The allowlist lives at
`scripts/redact-allowlist.txt`, with one regex per line.

Default entries include:

- `linksyssmartwifi\.com` — the default management hostname for Linksys Velop
  routers. It is a public vendor domain, not something unique to the operator's
  network.
- `router\.asus\.com` — similar vendor default for ASUS routers.
- `tplinkwifi\.net` — similar vendor default for TP-Link routers.
- `mywifiext\.net` — similar vendor default for Netgear extenders.

When the redaction script encounters a match, it checks the allowlist first.
If the matched value appears in the allowlist, the value is kept as-is.

Operators can add their own entries to the allowlist file. This is useful for
vendor-specific domains, public CDN hostnames, or other values that are clearly
not operator-specific.

---

## 5. Pattern Reference Table

The following table documents every pattern the redaction script applies. Each
row includes the category, a description, the sed-compatible regex, the
replacement token, the rationale, and a concrete before/after example.

| # | Category | Description | Regex (sed -E) | Replacement | Rationale | Before | After |
|---|----------|-------------|----------------|-------------|-----------|--------|-------|
| 1 | Public IPv4 | IPv4 addresses that are NOT in RFC1918, loopback, link-local, or RFC5737 documentation ranges | See implementation notes; uses a bash function to check exclusions | `<REDACTED:PUBLIC-IP>` | Operator's public or WAN IP could reveal their location or ISP | `WAN IP: 203.0.113.42` | `WAN IP: <REDACTED:PUBLIC-IP>` |
| 2 | Public IPv6 | IPv6 addresses that are NOT link-local (fe80::) | `(?<!fe80:)([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}` (simplified; see implementation notes) | `<REDACTED:PUBLIC-IP6>` | Global IPv6 addresses can identify the operator's network | `2001:db8::1` | `<REDACTED:PUBLIC-IP6>` |
| 3 | MAC Address Tail | Keep the OUI (first 3 octets) for vendor identification; redact the last 3 octets | `([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}):[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}` | `\1:XX:XX:XX` | OUI identifies the vendor (useful for diagnostics); the last 3 octets identify the specific device (sensitive) | `MAC: aa:bb:cc:11:22:33` | `MAC: aa:bb:cc:XX:XX:XX` |
| 4 | Hostnames | FQDNs, .local names, .lan names that could identify the operator's network | `([a-zA-Z0-9][-a-zA-Z0-9]*\.)+(local\|lan\|internal\|home\|corp)` and other non-public TLDs; excludes allowlisted domains | `<REDACTED:HOSTNAME>` | Operator-chosen hostnames reveal network naming conventions and device roles | `Host: myrouter.local` | `Host: <REDACTED:HOSTNAME>` |
| 5 | Serial Numbers | Alphanumeric strings of 8 or more characters adjacent to serial number keywords | `(serial\s*(number)?|S/N|serialNumber)[:\s]+[A-Za-z0-9]{8,}` (case-insensitive) | Keyword portion + `<REDACTED:SERIAL>` | Serial numbers uniquely identify a specific hardware unit | `serialNumber: ABC12345XYZ` | `serialNumber: <REDACTED:SERIAL>` |
| 6 | SSIDs | Values adjacent to SSID-related keywords | `(ssid|SSID|wlan_name|networkName)["\s:=]+[^\s"'\`,}{\]]+` (case-sensitive for JSON keys, insensitive for labels) | Keyword portion + `<REDACTED:SSID>` | SSIDs reveal the operator's network name, which can be fingerprinted | `"ssid": "MyHomeNetwork"` | `"ssid": "<REDACTED:SSID>"` |
| 7 | Certificate Fingerprints | SHA1 (40 hex chars) or SHA256 (64 hex chars) in certificate or key context | `([Ss][Hh][Aa]\d?\s+[Ff]ingerprint[=:\s]+)[0-9A-Fa-f:]{40,}` | `\1<REDACTED:FINGERPRINT>` | Certificate fingerprints uniquely identify a specific certificate instance | `SHA1 Fingerprint=AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD` | `SHA1 Fingerprint=<REDACTED:FINGERPRINT>` |
| 8 | Auth Tokens / Cookies | Authorization header values, Bearer tokens, Cookie values, API keys | `(Authorization:\s*Bearer\s+|Cookie:\s*|api[_-]?key[=:]\s*)[^\s"'\`]+` | `\1<REDACTED:AUTH>` | Auth tokens grant access to the device or service; leaking them is a security incident | `Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0` | `Authorization: Bearer <REDACTED:AUTH>` |
| 9 | GPS Coordinates | Latitude/longitude pairs in JSON or text | `(?:"lat(itude)?"?\s*[:=]\s*)([+-]?\d{1,3}\.\d+)` and similar for lon/gitude | `\1<REDACTED:GEO>` | GPS coordinates reveal the operator's physical location | `"lat": 51.5074, "lon": -0.1278` | `"lat": <REDACTED:GEO>, "lon": <REDACTED:GEO>` |
| 10 | SSH Host Keys / PEM | PEM-encoded key material, SSH host key data, certificate blocks | `-----BEGIN (CERTIFICATE|RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (CERTIFICATE|RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----` | `<REDACTED:KEY>` | Key material can be used to impersonate the device or decrypt traffic | `-----BEGIN CERTIFICATE-----\nMIIB...` | `<REDACTED:KEY>` |

### Category Notes

**Category 1 (Public IPv4)**: The regex needs to distinguish public IPs from
private/reserved ranges. A single sed expression cannot do this reliably, so
the script uses a bash helper function. It matches any dotted-quad, then checks
whether it falls in one of these reserved ranges:

- RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Loopback: `127.0.0.0/8`
- Link-local: `169.254.0.0/16`
- RFC5737 documentation: `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`
- Broadcast/special: `255.255.255.255`, `0.0.0.0`

Only addresses that do not match any reserved range are replaced.

**Category 2 (Public IPv6)**: Link-local addresses starting with `fe80::` are
kept. The loopback `::1` is also kept. All other IPv6 addresses are replaced.

**Category 3 (MAC Address Tail)**: The regex captures the OUI prefix (first 3
octets) in a group and replaces only the last 3 octets with `XX:XX:XX`. This
preserves vendor identification. For example, the OUI `E8:9F:80` maps to Belkin
International Inc., which is useful diagnostic information.

**Category 4 (Hostnames)**: Only operator-chosen hostnames are redacted. Public
vendor domains in the allowlist are kept. A hostname like `Linksys20571.local`
gets redacted because the `Linksys20571` portion derives from the device serial
number, but `linksyssmartwifi.com` is kept because it is a generic vendor
domain.

**Category 5 (Serial Numbers)**: The pattern looks for serial number keywords
followed by an alphanumeric string of 8 or more characters. This avoids false
positives on shorter strings that happen to appear near the keyword.

**Category 7 (Certificate Fingerprints)**: The pattern matches SHA1
fingerprints (40 hex characters, possibly colon-separated) and SHA256
fingerprints (64 hex characters) when preceded by a fingerprint keyword.

**Category 10 (SSH Host Keys / PEM)**: The pattern uses sed's multiline mode
to match the entire PEM block from `-----BEGIN` to `-----END`, including all
the base64-encoded content between them.

---

## 6. What is NOT Redacted

The following values are intentionally preserved. They are either not
identifying, or their diagnostic value outweighs any privacy concern.

- **RFC1918 private IPv4 addresses**: `10.x.x.x`, `172.16.x.x` through
  `172.31.x.x`, `192.168.x.x`. These identify devices on the operator's LAN.
  Knowing that a router is at `192.168.1.1` tells you nothing about the
  operator; it is the most common default gateway in the world.

- **Loopback addresses**: `127.x.x.x` and `::1`. These are local-only and
  carry no identifying information.

- **Link-local addresses**: IPv4 `169.254.x.x` and IPv6 `fe80::/10`. These are
  auto-configured and not routable.

- **OUI prefixes**: The first 3 octets of a MAC address (e.g., `E8:9F:80` for
  Belkin). These identify the hardware vendor, which is the whole point of
  capturing MAC addresses in the first place.

- **Port numbers**: TCP/UDP port numbers are well-known service identifiers and
  carry no operator-specific information.

- **Software version strings**: Firmware versions, OS kernel versions, and
  application versions. These are needed for vulnerability research and
  diagnostics.

- **Public vendor hostnames**: Domains listed in `scripts/redact-allowlist.txt`,
  such as `linksyssmartwifi.com`. These are vendor defaults, not
  operator-specific.

---

## 7. Implementation Notes

### Script Location

All patterns are implemented in `scripts/redact-output.sh` as `sed -E`
functions. The script reads from `raw/`, applies every pattern, writes to a
temporary location, runs verification, and only then moves the results to
`redacted/`.

### IP Exclusion Logic

Determining whether an IPv4 address is public requires comparing against
multiple reserved ranges. A single sed regex cannot express this cleanly. The
script implements a bash function `is_private_ip()` that performs the check
using arithmetic comparison. The overall flow is:

1. Match all dotted-quad patterns in the file.
2. For each match, call `is_private_ip()` to check against reserved ranges.
3. If the address is private, skip it. If public, replace it with the token.

### Pattern Ordering

The order in which patterns run matters. More specific patterns must run before
more general ones to avoid double-replacement or incorrect matches. The script
applies patterns in this order:

1. PEM/SSH key blocks (must run first to consume entire key material before
   other patterns try to match hex strings within it)
2. Auth tokens and cookies
3. Certificate fingerprints
4. Serial numbers
5. SSIDs
6. GPS coordinates
7. MAC address tails
8. IPv6 addresses
9. IPv4 addresses (last, because the exclusion logic is most expensive)
10. Hostnames

### Allowlist Processing

The allowlist file is loaded at script startup into an associative array. Each
hostname match is checked against this array before replacement. If a match is
found in the allowlist, the value passes through unchanged.

### Verification

After all patterns are applied, the script runs a verification scan. This scan
uses the same patterns in read-only mode to confirm that no unredacted
sensitive values remain. If the scan finds any hits, the script aborts (see
Section 3, Fail-Closed Policy).

### Adding New Patterns

To add a new pattern:

1. Define the regex in this document (you are reading it).
2. Add a `sed` function to `scripts/redact-output.sh`.
3. Add the corresponding verification check.
4. Test with synthetic data that exercises both the match and the exclusion
   cases.
5. Update this table.

---

## Appendix: Synthetic Identifier Ranges for Examples

When writing documentation, test cases, or example outputs, use only these
RFC-reserved ranges for IP addresses:

| Range | RFC | Purpose |
|-------|-----|---------|
| `192.0.2.0/24` | 5737 | Documentation (TEST-NET-1) |
| `198.51.100.0/24` | 5737 | Documentation (TEST-NET-2) |
| `203.0.113.0/24` | 5737 | Documentation (TEST-NET-3) |
| `2001:db8::/32` | 3849 | Documentation (IPv6) |

For MAC addresses, use synthetic OUI prefixes like `aa:bb:cc` or `11:22:33`
followed by synthetic device suffixes like `dd:ee:ff`. Never use real MAC
addresses from actual hardware.

For serial numbers, use clearly synthetic values like `ABC12345XYZ` or
`FAKE987654321`. Never use serial numbers from real devices.
