//! HTTP banner classification — the boot vocabulary of
//! `router-probe.py::probe_http_get` / `probe_http_head`, extracted
//! verbatim (match order and case sensitivity included).
//!
//! The pure part takes the received bytes; transport outcomes map to
//! `None` (no response / transport error). Python's `rc == 0 and
//! len(body) > 0` residue becomes [`HttpGetSignature::UnknownHttp`] for
//! non-empty unidentified bodies; empty bodies stay
//! [`HttpGetSignature::NoResponse`] like the Python `"no_response"`.

use crate::vocab::{contains, contains_ci};

/// `probe_http_get` outcome vocabulary (order of the Python if-chain).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpGetSignature {
    /// Nothing answered (connection refused/timeout; Python
    /// `"no_response"`).
    #[default]
    NoResponse,
    /// `"FIRMWARE UPDATE"` page, a firmware+`<form>` page, or a `uIP`
    /// body signature — bootloader recovery web server.
    Uboot,
    /// `luci`/`openwrt` in the body — the LuCI/OpenWrt web interface.
    OpenwrtLuci,
    /// `gl-inet`/`glinet` — the GL.iNet admin panel (stock).
    GlinetStock,
    /// `jnap`/`linksys` — the Linksys web interface (stock).
    LinksysStock,
    /// Bytes arrived but no known signature matched (Python
    /// `"unknown_http"`).
    UnknownHttp,
}

/// `probe_http_head` outcome vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HttpHeadSignature {
    /// Nothing answered.
    #[default]
    NoResponse,
    /// `uIP` in the headers — U-Boot's recovery httpd (uIP stack).
    Uboot,
    /// `HTTP/1.1 405` — HEAD rejected (MT3000 U-Boot behavior).
    MethodNotAllowed,
    /// Headers arrived with nothing identifying (Python
    /// `"headers_received"`; the `Server:` extraction stays a host
    /// display concern — see the fidelity note).
    HeadersReceived,
}

/// Classify an HTTP GET body exactly as `probe_http_get` does.
///
/// Match order is the Python if-chain and is load-bearing: the
/// case-SENSITIVE `"FIRMWARE UPDATE"` check comes first, the
/// case-sensitive `uIP` body check comes LAST (after the stock-vendor
/// checks), so e.g. a GL.iNet page carrying `uIP` still classifies as
/// GL.iNet stock — reordering changes observable behavior.
#[must_use]
pub fn classify_http_get(body: Option<&[u8]>) -> HttpGetSignature {
    let Some(body) = body else {
        return HttpGetSignature::NoResponse;
    };
    if contains(body, b"FIRMWARE UPDATE") {
        return HttpGetSignature::Uboot;
    }
    if contains_ci(body, b"firmware") && contains_ci(body, b"<form") {
        return HttpGetSignature::Uboot;
    }
    if contains_ci(body, b"luci") || contains_ci(body, b"openwrt") {
        return HttpGetSignature::OpenwrtLuci;
    }
    if contains_ci(body, b"gl-inet") || contains_ci(body, b"glinet") {
        return HttpGetSignature::GlinetStock;
    }
    if contains_ci(body, b"jnap") || contains_ci(body, b"linksys") {
        return HttpGetSignature::LinksysStock;
    }
    if contains(body, b"uIP") {
        return HttpGetSignature::Uboot;
    }
    if !body.is_empty() {
        return HttpGetSignature::UnknownHttp;
    }
    HttpGetSignature::NoResponse
}

/// Classify HTTP HEAD response headers exactly as `probe_http_head`
/// does (`uIP` is case-sensitive; `HTTP/1.1 405` is the MT3000 U-Boot
/// HEAD rejection).
#[must_use]
pub fn classify_http_head(headers: Option<&[u8]>) -> HttpHeadSignature {
    let Some(headers) = headers else {
        return HttpHeadSignature::NoResponse;
    };
    if contains(headers, b"uIP") {
        return HttpHeadSignature::Uboot;
    }
    if contains(headers, b"HTTP/1.1 405") {
        return HttpHeadSignature::MethodNotAllowed;
    }
    if !headers.is_empty() {
        return HttpHeadSignature::HeadersReceived;
    }
    HttpHeadSignature::NoResponse
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_is_no_response() {
        assert_eq!(classify_http_get(None), HttpGetSignature::NoResponse);
        assert_eq!(classify_http_head(None), HttpHeadSignature::NoResponse);
    }

    #[test]
    fn empty_body_is_no_response() {
        // Python: rc==0 but len(body)==0 -> stays "no_response"
        assert_eq!(classify_http_get(Some(b"")), HttpGetSignature::NoResponse);
        assert_eq!(classify_http_head(Some(b"")), HttpHeadSignature::NoResponse);
    }

    #[test]
    fn firmware_update_page_is_uboot() {
        assert_eq!(
            classify_http_get(Some(b"<html><title>FIRMWARE UPDATE</title>")),
            HttpGetSignature::Uboot
        );
    }

    #[test]
    fn firmware_form_page_is_uboot_case_insensitive() {
        assert_eq!(
            classify_http_get(Some(b"<FORM action=upload>Firmware Image</FORM>")),
            HttpGetSignature::Uboot
        );
    }

    #[test]
    fn luci_and_openwrt_bodies_classify() {
        assert_eq!(
            classify_http_get(Some(b"<title>LuCI</title>")),
            HttpGetSignature::OpenwrtLuci
        );
        assert_eq!(
            classify_http_get(Some(b"Powered by OpenWrt")),
            HttpGetSignature::OpenwrtLuci
        );
    }

    #[test]
    fn glinet_and_linksys_stock_classify() {
        assert_eq!(
            classify_http_get(Some(b"GL-iNet Admin Panel")),
            HttpGetSignature::GlinetStock
        );
        assert_eq!(
            classify_http_get(Some(b"<html>LINKSYS Smart Wi-Fi</html>")),
            HttpGetSignature::LinksysStock
        );
    }

    #[test]
    fn uip_body_is_uboot_but_loses_to_vendor_vocab() {
        // exact Python order: uIP body check runs LAST
        assert_eq!(
            classify_http_get(Some(b"server: uIP 1.0")),
            HttpGetSignature::Uboot
        );
        assert_eq!(
            classify_http_get(Some(b"GL-iNet panel on uIP")),
            HttpGetSignature::GlinetStock
        );
    }

    #[test]
    fn uip_is_case_sensitive_in_bodies() {
        // Python checks the raw body, not the lowered copy
        assert_eq!(
            classify_http_get(Some(b"running UIP stack")),
            HttpGetSignature::UnknownHttp
        );
    }

    #[test]
    fn unidentified_bytes_are_unknown_http() {
        assert_eq!(
            classify_http_get(Some(b"<html>Welcome to the setup wizard</html>")),
            HttpGetSignature::UnknownHttp
        );
    }

    #[test]
    fn head_uip_header_is_uboot() {
        assert_eq!(
            classify_http_head(Some(b"HTTP/1.0 200 OK\r\nServer: uIP/1.0\r\n\r\n")),
            HttpHeadSignature::Uboot
        );
    }

    #[test]
    fn head_405_is_method_not_allowed() {
        assert_eq!(
            classify_http_head(Some(b"HTTP/1.1 405 Method Not Allowed\r\n")),
            HttpHeadSignature::MethodNotAllowed
        );
    }

    #[test]
    fn head_plain_headers_are_headers_received() {
        assert_eq!(
            classify_http_head(Some(b"HTTP/1.1 200 OK\r\nServer: lighttpd\r\n")),
            HttpHeadSignature::HeadersReceived
        );
    }
}
