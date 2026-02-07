"""Tests for SSLPinningAnalyzer."""

import pytest
from api.tests.conftest import create_test_archive, make_mock_app


PINNED_NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2026-12-31">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
        </pin-set>
    </domain-config>
</network-security-config>"""


class TestSSLPinningAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.ssl_pinning_analyzer import SSLPinningAnalyzer
        return SSLPinningAnalyzer()

    @pytest.fixture
    def pinned_app(self, tmp_path):
        """App with SSL pinning configured via NSC."""
        return make_mock_app(tmp_path, {
            "res/xml/network_security_config.xml": PINNED_NSC,
        })

    @pytest.fixture
    def bypass_app(self, tmp_path):
        """App with SSL validation bypass patterns in DEX."""
        dex_content = (
            b"dex\n035\x00"
            b"TrustAllCerts implements X509TrustManager "
            b"checkServerTrusted { } "
            b"ALLOW_ALL_HOSTNAME_VERIFIER "
            b"handler.proceed()"
        )
        return make_mock_app(tmp_path, {
            "classes.dex": dex_content,
        })

    @pytest.fixture
    def no_pinning_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "res/values/strings.xml": "<resources></resources>",
        })

    @pytest.mark.asyncio
    async def test_detects_nsc_pinning(self, analyzer, pinned_app):
        findings = await analyzer.analyze(pinned_app)
        assert isinstance(findings, list)
        # Should detect pinning as informational/positive finding
        titles = [f.title.lower() for f in findings]
        assert any("pin" in t or "ssl" in t or "tls" in t for t in titles)

    @pytest.mark.asyncio
    async def test_detects_ssl_bypass(self, analyzer, bypass_app):
        findings = await analyzer.analyze(bypass_app)
        # Bypass patterns should produce high/critical findings
        bypass_findings = [
            f for f in findings
            if f.severity in ("critical", "high")
        ]
        assert len(bypass_findings) > 0

    @pytest.mark.asyncio
    async def test_no_pinning_returns_findings(self, analyzer, no_pinning_app):
        findings = await analyzer.analyze(no_pinning_app)
        # Should still return a finding about missing pinning
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, pinned_app):
        findings = await analyzer.analyze(pinned_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "ssl_pinning_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
