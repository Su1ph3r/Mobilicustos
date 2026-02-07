"""Tests for DataLeakageAnalyzer."""

import pytest
from api.tests.conftest import make_mock_app


class TestDataLeakageAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.data_leakage_analyzer import DataLeakageAnalyzer
        return DataLeakageAnalyzer()

    @pytest.fixture
    def leaky_android_app(self, tmp_path):
        dex_content = (
            b"dex\n035\x00"
            b"ClipboardManager getClipboard setPrimaryClip "
            b"Log.d(TAG, password) "
            b"putExtra(KEY, session_token) "
        )
        return make_mock_app(tmp_path, {
            "classes.dex": dex_content,
        })

    @pytest.fixture
    def clean_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "res/values/strings.xml": "<resources></resources>",
        })

    @pytest.mark.asyncio
    async def test_detects_clipboard_usage(self, analyzer, leaky_android_app):
        findings = await analyzer.analyze(leaky_android_app)
        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.asyncio
    async def test_detects_logging_leakage(self, analyzer, leaky_android_app):
        findings = await analyzer.analyze(leaky_android_app)
        texts = " ".join((f.title + " " + f.description).lower() for f in findings)
        assert "log" in texts or "clipboard" in texts or "leakage" in texts

    @pytest.mark.asyncio
    async def test_clean_app_fewer_findings(self, analyzer, clean_app):
        findings = await analyzer.analyze(clean_app)
        critical = [f for f in findings if f.severity in ("critical", "high")]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, leaky_android_app):
        findings = await analyzer.analyze(leaky_android_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "data_leakage_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
