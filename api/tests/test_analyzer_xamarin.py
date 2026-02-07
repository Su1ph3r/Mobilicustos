"""Tests for XamarinAnalyzer."""

import json
import pytest
from api.tests.conftest import make_mock_app


PACKAGES_CONFIG = """<?xml version="1.0" encoding="utf-8"?>
<packages>
  <package id="Newtonsoft.Json" version="12.0.3" />
  <package id="Xamarin.Forms" version="5.0.0.2578" />
</packages>"""

DEPS_JSON = json.dumps({
    "libraries": {
        "Newtonsoft.Json/12.0.3": {"type": "package"},
        "BouncyCastle/1.8.9": {"type": "package"},
    }
})

INSECURE_CS = """
using System.Net;
using Xamarin.Essentials;

public class ApiService {
    private string connectionString = "Server=db.example.com;Database=mydb;User=admin;Password=secret123;";

    public void Init() {
        ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
        Preferences.Set("auth_token", token);
    }
}
"""


class TestXamarinAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.xamarin_analyzer import XamarinAnalyzer
        return XamarinAnalyzer()

    @pytest.fixture
    def xamarin_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "assemblies/Xamarin.Forms.dll": b"\x00MZ\x00\x00Xamarin.Forms",
            "assemblies/MyApp.dll": b"\x00MZ\x00\x00MyApp",
            "assemblies/MyApp.pdb": b"\x00debug symbols\x00",
            "packages.config": PACKAGES_CONFIG,
        })

    @pytest.fixture
    def maui_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "assemblies/Microsoft.Maui.dll": b"\x00MZ\x00\x00Maui",
            "assemblies/MyApp.dll": b"\x00MZ\x00\x00MyApp",
        })

    @pytest.fixture
    def insecure_xamarin_app(self, tmp_path):
        return make_mock_app(tmp_path, {
            "assemblies/Xamarin.Forms.dll": b"\x00MZ\x00\x00Xamarin.Forms",
            "assemblies/MyApp.dll": INSECURE_CS.encode(),
            "sources/ApiService.cs": INSECURE_CS,
            "packages.config": PACKAGES_CONFIG,
            "deps.json": DEPS_JSON,
        })

    @pytest.mark.asyncio
    async def test_detects_xamarin_framework(self, analyzer, xamarin_app):
        findings = await analyzer.analyze(xamarin_app)
        assert isinstance(findings, list)
        assert len(findings) > 0
        titles = " ".join(f.title.lower() for f in findings)
        assert "xamarin" in titles or "detected" in titles

    @pytest.mark.asyncio
    async def test_detects_maui_framework(self, analyzer, maui_app):
        findings = await analyzer.analyze(maui_app)
        titles = " ".join(f.title.lower() for f in findings)
        assert "maui" in titles or "detected" in titles

    @pytest.mark.asyncio
    async def test_detects_debug_symbols(self, analyzer, xamarin_app):
        findings = await analyzer.analyze(xamarin_app)
        titles = " ".join(f.title.lower() for f in findings)
        assert "debug" in titles or "symbol" in titles or "pdb" in titles

    @pytest.mark.asyncio
    async def test_detects_insecure_patterns(self, analyzer, insecure_xamarin_app):
        findings = await analyzer.analyze(insecure_xamarin_app)
        titles = " ".join(f.title.lower() for f in findings)
        assert (
            "connection" in titles
            or "ssl" in titles
            or "certificate" in titles
            or "preferences" in titles
        )

    @pytest.mark.asyncio
    async def test_detects_vulnerable_packages(self, analyzer, insecure_xamarin_app):
        findings = await analyzer.analyze(insecure_xamarin_app)
        titles = " ".join(f.title.lower() for f in findings)
        assert "vulnerable" in titles or "nuget" in titles or "newtonsoft" in titles.lower()

    @pytest.mark.asyncio
    async def test_non_xamarin_app_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, {
            "classes.dex": b"dex\n035\x00regular android app",
        })
        findings = await analyzer.analyze(app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, xamarin_app):
        findings = await analyzer.analyze(xamarin_app)
        for f in findings:
            assert f.finding_id
            assert f.title
            assert f.description
            assert f.severity in ("critical", "high", "medium", "low", "info")
            assert f.tool == "xamarin_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
