//! Scripted mock provider — the reference `LinkProbe`/`Time` implementation
//! for tests, dry-runs, and CI (ADR-0011 ring 1).
//!
//! Every call is recorded so tests can assert exactly which capabilities a
//! workflow exercised (the foundation of the dry-run purity gate, #113).

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;
use core::net::IpAddr;

use crate::capability::{HttpProbeResult, LinkProbe, ProbeError, SshBanner, Time};
use conwrt_types::MacAddress;

/// A scripted per-address scenario.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Scenario {
    /// Carrier state reported by `link_up`.
    pub link_up: Option<bool>,
    /// ICMP result.
    pub ping: bool,
    /// HTTP response; `None` = connection refused.
    pub http: Option<HttpProbeResult>,
    /// SSH banner; `None` = nothing listening.
    pub ssh_banner: Option<SshBanner>,
    /// ARP entry for the address.
    pub mac: Option<MacAddress>,
}

/// Named scenarios matching the classifier's canonical states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamedScenario {
    /// Link down.
    Off,
    /// No responses.
    Unreachable,
    /// U-Boot recovery HTTP server.
    UbootRecovery,
    /// OpenWrt with dropbear + uhttpd.
    OpenWrt,
    /// Vendor web UI without SSH.
    StockVendor,
}

impl NamedScenario {
    /// Build a scenario with realistic evidence for the state.
    ///
    /// The MAC uses an OUI that exists in the real model corpus
    /// (`94:83:C4`, GL.iNet) so identification has something to match.
    #[must_use]
    pub fn evidence(self) -> Scenario {
        match self {
            NamedScenario::Off => Scenario {
                link_up: Some(false),
                ..Default::default()
            },
            NamedScenario::Unreachable => Scenario::default(),
            NamedScenario::UbootRecovery => Scenario {
                ping: true,
                http: Some(HttpProbeResult {
                    status: 200,
                    server_header: Some("uwWMPre/1.00".into()),
                    title: None,
                }),
                mac: Some(MacAddress::parse("94:83:c4:0a:0b:0c").unwrap()),
                ..Default::default()
            },
            NamedScenario::OpenWrt => Scenario {
                ping: true,
                http: Some(HttpProbeResult {
                    status: 200,
                    server_header: Some("uhttpd/1.0".into()),
                    title: Some("OpenWrt LuCI".into()),
                }),
                ssh_banner: Some(SshBanner {
                    software: "dropbear_2024.86".into(),
                }),
                mac: Some(MacAddress::parse("94:83:c4:0a:0b:0d").unwrap()),
                ..Default::default()
            },
            NamedScenario::StockVendor => Scenario {
                ping: true,
                http: Some(HttpProbeResult {
                    status: 200,
                    server_header: Some("lighttpd/1.4.64".into()),
                    title: Some("Vendor Setup".into()),
                }),
                mac: Some(MacAddress::parse("94:83:c4:0a:0b:0e").unwrap()),
                ..Default::default()
            },
        }
    }
}

/// A recorded capability call (for dry-run purity assertions).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `link_up()`.
    LinkUp,
    /// `ping(ip)`.
    Ping(IpAddr),
    /// `http_get(ip, path)`.
    HttpGet(IpAddr, String),
    /// `ssh_banner(ip)`.
    SshBanner(IpAddr),
    /// `arp_mac(ip)`.
    ArpMac(IpAddr),
    /// `sleep_ms(ms)`.
    Sleep(u64),
}

/// The mock provider: scripted scenarios per address + a call journal.
#[derive(Debug, Default)]
pub struct MockProber {
    scenarios: BTreeMap<IpAddr, Scenario>,
    default: Scenario,
    link: Option<bool>,
    calls: RefCell<Vec<Call>>,
}

impl MockProber {
    /// A mock that answers every address with `default`.
    #[must_use]
    pub fn from_scenario(default: Scenario) -> Self {
        Self {
            link: default.link_up,
            default,
            scenarios: BTreeMap::new(),
            calls: RefCell::new(Vec::new()),
        }
    }

    /// A mock answering one address with a named scenario.
    #[must_use]
    pub fn responding(ip: IpAddr, scenario: NamedScenario) -> Self {
        let mut mock = Self::default();
        mock.set(ip, scenario.evidence());
        mock
    }

    /// Script (or re-script) one address.
    ///
    /// The link-level carrier state is link-wide, not per-address: the most
    /// recent scripted `link_up` wins.
    pub fn set(&mut self, ip: IpAddr, scenario: Scenario) {
        if scenario.link_up.is_some() {
            self.link = scenario.link_up;
        }
        self.scenarios.insert(ip, scenario);
    }

    /// Override the link-wide carrier state.
    pub fn set_link(&mut self, up: Option<bool>) {
        self.link = up;
    }

    fn scenario_for(&self, ip: IpAddr) -> &Scenario {
        self.scenarios.get(&ip).unwrap_or(&self.default)
    }

    fn record(&self, call: Call) {
        self.calls.borrow_mut().push(call);
    }

    /// The journal of capability calls performed so far.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }
}

impl LinkProbe for MockProber {
    async fn link_up(&mut self) -> Result<Option<bool>, ProbeError> {
        self.record(Call::LinkUp);
        Ok(self.link)
    }

    async fn ping(&mut self, ip: IpAddr) -> Result<bool, ProbeError> {
        self.record(Call::Ping(ip));
        Ok(self.scenario_for(ip).ping)
    }

    async fn http_get(
        &mut self,
        ip: IpAddr,
        path: &str,
    ) -> Result<Option<HttpProbeResult>, ProbeError> {
        self.record(Call::HttpGet(ip, path.to_string()));
        Ok(self.scenario_for(ip).http.clone())
    }

    async fn ssh_banner(&mut self, ip: IpAddr) -> Result<Option<SshBanner>, ProbeError> {
        self.record(Call::SshBanner(ip));
        Ok(self.scenario_for(ip).ssh_banner.clone())
    }

    async fn arp_mac(&mut self, ip: IpAddr) -> Result<Option<MacAddress>, ProbeError> {
        self.record(Call::ArpMac(ip));
        Ok(self.scenario_for(ip).mac)
    }
}

impl Time for MockProber {
    async fn sleep_ms(&mut self, ms: u64) {
        self.record(Call::Sleep(ms));
    }
}

impl LinkProbe for &mut MockProber {
    async fn link_up(&mut self) -> Result<Option<bool>, ProbeError> {
        (**self).link_up().await
    }

    async fn ping(&mut self, ip: IpAddr) -> Result<bool, ProbeError> {
        (**self).ping(ip).await
    }

    async fn http_get(
        &mut self,
        ip: IpAddr,
        path: &str,
    ) -> Result<Option<HttpProbeResult>, ProbeError> {
        (**self).http_get(ip, path).await
    }

    async fn ssh_banner(&mut self, ip: IpAddr) -> Result<Option<SshBanner>, ProbeError> {
        (**self).ssh_banner(ip).await
    }

    async fn arp_mac(&mut self, ip: IpAddr) -> Result<Option<MacAddress>, ProbeError> {
        (**self).arp_mac(ip).await
    }
}

impl Time for &mut MockProber {
    async fn sleep_ms(&mut self, ms: u64) {
        (**self).sleep_ms(ms).await
    }
}

impl Clone for MockProber {
    fn clone(&self) -> Self {
        Self {
            scenarios: self.scenarios.clone(),
            default: self.default.clone(),
            link: self.link,
            calls: RefCell::new(self.calls.borrow().clone()),
        }
    }
}

impl MockProber {
    /// Render the call journal compactly (test-failure messages).
    #[must_use]
    pub fn calls_summary(&self) -> String {
        self.calls
            .borrow()
            .iter()
            .map(|c| match c {
                Call::LinkUp => "link_up".to_string(),
                Call::Ping(ip) => format!("ping({ip})"),
                Call::HttpGet(ip, p) => format!("http_get({ip}, {p})"),
                Call::SshBanner(ip) => format!("ssh_banner({ip})"),
                Call::ArpMac(ip) => format!("arp_mac({ip})"),
                Call::Sleep(ms) => format!("sleep_ms({ms})"),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}
