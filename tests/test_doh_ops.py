"""Ops characterization tests for doh.py."""
from profile.ops import render_shell
from use_cases.doh import _build_doh_ops


DEFAULT_PARAMS: dict = {}
GOOGLE_PARAMS: dict = {"provider": "google"}
CUSTOM_URL_PARAMS: dict = {"provider": "https://my-dns.example.com/dns-query"}
CUSTOM_PORT_PARAMS: dict = {"listen_port": 5353}


class TestDohOpsDefault:
    def test_sets_https_dns_proxy(self):
        rendered = render_shell(_build_doh_ops(DEFAULT_PARAMS))
        assert "uci set https-dns-proxy.main=https_dns_proxy" in rendered

    def test_cloudflare_default(self):
        rendered = render_shell(_build_doh_ops(DEFAULT_PARAMS))
        assert "cloudflare-dns.com" in rendered

    def test_default_port(self):
        rendered = render_shell(_build_doh_ops(DEFAULT_PARAMS))
        assert "5053" in rendered

    def test_enables_service(self):
        rendered = render_shell(_build_doh_ops(DEFAULT_PARAMS))
        assert "https-dns-proxy" in rendered
        assert "enable" in rendered

    def test_points_dnsmasq_to_proxy(self):
        rendered = render_shell(_build_doh_ops(DEFAULT_PARAMS))
        assert "noresolv" in rendered
        assert "127.0.0.1#5053" in rendered

    def test_restarts_dnsmasq(self):
        rendered = render_shell(_build_doh_ops(DEFAULT_PARAMS))
        assert "dnsmasq restart" in rendered


class TestDohOpsGoogle:
    def test_google_provider(self):
        rendered = render_shell(_build_doh_ops(GOOGLE_PARAMS))
        assert "dns.google" in rendered


class TestDohOpsCustomUrl:
    def test_custom_url(self):
        rendered = render_shell(_build_doh_ops(CUSTOM_URL_PARAMS))
        assert "my-dns.example.com" in rendered


class TestDohOpsCustomPort:
    def test_custom_port(self):
        rendered = render_shell(_build_doh_ops(CUSTOM_PORT_PARAMS))
        assert "5353" in rendered
        assert "127.0.0.1#5353" in rendered
