"""Tests for ObfuscationAnalyzer."""

import pytest
from api.tests.conftest import make_mock_app


class TestObfuscationAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.obfuscation_analyzer import ObfuscationAnalyzer
        return ObfuscationAnalyzer()

    @pytest.fixture
    def unobfuscated_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "smali/com/example/MainActivity.smali": ".class Lcom/example/MainActivity;",
            "smali/com/example/LoginActivity.smali": ".class Lcom/example/LoginActivity;",
            "smali/com/example/UserService.smali": ".class Lcom/example/UserService;",
        })

    @pytest.fixture
    def obfuscated_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "smali/com/example/a.smali": ".class Lcom/example/a;",
            "smali/com/example/b.smali": ".class Lcom/example/b;",
            "smali/com/example/c.smali": ".class Lcom/example/c;",
            "build.gradle": "minifyEnabled true\nproguardFiles getDefaultProguardFile('proguard-android.txt')",
        })

    @pytest.mark.asyncio
    async def test_detects_no_obfuscation(self, analyzer, unobfuscated_app):
        findings = await analyzer.analyze(unobfuscated_app)
        assert isinstance(findings, list)
        # Should report lack of obfuscation as a finding
        texts = " ".join(f.title.lower() for f in findings)
        assert "obfuscat" in texts or len(findings) >= 1

    @pytest.mark.asyncio
    async def test_obfuscated_app_different_findings(self, analyzer, obfuscated_app):
        findings = await analyzer.analyze(obfuscated_app)
        assert isinstance(findings, list)
        # Obfuscated app may have different severity findings
        for f in findings:
            assert f.severity in ("critical", "high", "medium", "low", "info")

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, unobfuscated_app):
        findings = await analyzer.analyze(unobfuscated_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "obfuscation_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
