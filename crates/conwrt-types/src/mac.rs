//! MAC address and OUI (organizationally unique identifier) prefix types.
//!
//! Species-level OUI prefixes come from each model's `mac_oui` array; unit
//! MACs are specimen-level data and must never be committed (AGENTS.md).

use alloc::{format, string::String, vec::Vec};
use core::fmt;
use core::str::FromStr;

/// A 48-bit MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Parse a MAC in colon, dash, or bare hexadecimal form
    /// (case-insensitive), e.g. `94:83:C4:00:11:22`.
    pub fn parse(s: &str) -> Result<Self, MacParseError> {
        let cleaned: String = s
            .chars()
            .filter(|c| *c != ':' && *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if cleaned.len() != 12 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(MacParseError(s.into()));
        }
        let mut bytes = [0u8; 6];
        for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap_or(0) as u8;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// The raw six octets.
    #[must_use]
    pub fn octets(&self) -> [u8; 6] {
        self.0
    }

    /// The 24-bit OUI prefix (first three octets).
    #[must_use]
    pub fn oui(&self) -> OuiPrefix {
        OuiPrefix([self.0[0], self.0[1], self.0[2]])
    }

    /// Canonical colon-separated lowercase form.
    #[must_use]
    pub fn to_string_canonical(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

impl FromStr for MacAddress {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_canonical())
    }
}

/// A 24-bit OUI prefix as used by `models/*.json` `mac_oui` entries
/// (e.g. `94:83:C4`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct OuiPrefix([u8; 3]);

impl OuiPrefix {
    /// Parse an OUI prefix (colon, dash, or bare form, case-insensitive).
    pub fn parse(s: &str) -> Result<Self, MacParseError> {
        let cleaned: String = s
            .chars()
            .filter(|c| *c != ':' && *c != '-')
            .map(|c| c.to_ascii_lowercase())
            .collect();
        if cleaned.len() != 6 || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(MacParseError(s.into()));
        }
        let mut bytes = [0u8; 3];
        for (i, chunk) in cleaned.as_bytes().chunks(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).unwrap_or(0) as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap_or(0) as u8;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }

    /// Parse all OUI prefixes from an iterator of strings, skipping
    /// (and reporting) malformed entries rather than failing outright —
    /// a bad prefix in one model must not break the registry.
    pub fn parse_all<'a, I>(items: I) -> (Vec<Self>, Vec<String>)
    where
        I: IntoIterator<Item = &'a str>,
    {
        let mut ok = Vec::new();
        let mut bad = Vec::new();
        for item in items {
            match Self::parse(item) {
                Ok(prefix) => ok.push(prefix),
                Err(_) => bad.push(String::from(item)),
            }
        }
        (ok, bad)
    }

    /// Whether a MAC address carries this OUI.
    #[must_use]
    pub fn matches(&self, mac: &MacAddress) -> bool {
        mac.octets()[..3] == self.0
    }
}

impl FromStr for OuiPrefix {
    type Err = MacParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for OuiPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}", self.0[0], self.0[1], self.0[2])
    }
}

/// A MAC or OUI string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacParseError(String);

impl fmt::Display for MacParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid MAC/OUI string: {:?}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MacParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_colon_dash_and_bare_forms() {
        let a = MacAddress::parse("94:83:C4:00:11:22").unwrap();
        let b = MacAddress::parse("94-83-c4-00-11-22").unwrap();
        let c = MacAddress::parse("9483C4001122").unwrap();
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_eq!(a.to_string(), "94:83:c4:00:11:22");
        assert_eq!(a.octets(), [0x94, 0x83, 0xc4, 0x00, 0x11, 0x22]);
    }

    #[test]
    fn rejects_malformed_macs() {
        for bad in [
            "",
            "94:83",
            "zz:83:c4:00:11:22",
            "94:83:c4:00:11:2g",
            "9483c400112",
        ] {
            assert!(MacAddress::parse(bad).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn oui_prefix_matches_only_first_three_octets() {
        let oui = OuiPrefix::parse("94:83:C4").unwrap();
        let matching = MacAddress::parse("94:83:c4:aa:bb:cc").unwrap();
        let other = MacAddress::parse("94:83:c5:aa:bb:cc").unwrap();
        assert!(oui.matches(&matching));
        assert!(!oui.matches(&other));
        assert_eq!(oui.to_string(), "94:83:c4");
    }

    #[test]
    fn parse_all_skips_and_reports_bad_entries() {
        let (ok, bad) = OuiPrefix::parse_all(["94:83:C4", "nope", "e0:63:da"]);
        assert_eq!(ok.len(), 2);
        assert_eq!(bad, ["nope"]);
    }
}
