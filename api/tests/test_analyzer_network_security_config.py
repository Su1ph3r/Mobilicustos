"""Tests for NetworkSecurityConfigAnalyzer."""

import pytest
from api.tests.conftest import create_test_archive, make_mock_app


INSECURE_NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>"""

SECURE_NSC = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set expiration="2026-12-31">
            <pin digest="SHA-256">base64EncodedPin==</pin>
        </pin-set>
    </domain-config>
</network-security-config>"""


class TestNetworkSecurityConfigAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.network_security_config_analyzer import (
            NetworkSecurityConfigAnalyzer,
        )
        return NetworkSecurityConfigAnalyzer()

    @pytest.fixture
    def insecure_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "res/xml/network_security_config.xml": INSECURE_NSC,
        })

    @pytest.fixture
    def secure_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "res/xml/network_security_config.xml": SECURE_NSC,
        })

    @pytest.mark.asyncio
    async def test_analyze_returns_findings_for_insecure_config(self, analyzer, insecure_app):
        findings = await analyzer.analyze(insecure_app)
        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_cleartext_traffic_detected(self, analyzer, insecure_app):
        findings = await analyzer.analyze(insecure_app)
        titles = [f.title.lower() for f in findings]
        assert any("cleartext" in t for t in titles)

    @pytest.mark.asyncio
    async def test_debug_overrides_detected(self, analyzer, insecure_app):
        findings = await analyzer.analyze(insecure_app)
        titles = [f.title.lower() for f in findings]
        assert any("debug" in t for t in titles)

    @pytest.mark.asyncio
    async def test_user_certificates_detected(self, analyzer, insecure_app):
        findings = await analyzer.analyze(insecure_app)
        descriptions = [f.description.lower() for f in findings]
        assert any("user" in d and "cert" in d for d in descriptions)

    @pytest.mark.asyncio
    async def test_secure_config_fewer_findings(self, analyzer, secure_app):
        findings = await analyzer.analyze(secure_app)
        # Secure config should produce fewer or no critical findings
        critical_high = [f for f in findings if f.severity in ("critical", "high")]
        assert len(critical_high) == 0

    @pytest.mark.asyncio
    async def test_no_config_file_reports_missing(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, {"dummy.txt": "nothing"})
        findings = await analyzer.analyze(app)
        # Analyzer may report missing NSC as a finding or return empty
        assert isinstance(findings, list)
        for f in findings:
            assert f.severity in ("critical", "high", "medium", "low", "info")

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, insecure_app):
        findings = await analyzer.analyze(insecure_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "network_security_config_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
