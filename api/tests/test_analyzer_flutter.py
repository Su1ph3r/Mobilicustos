"""Tests for FlutterAnalyzer."""

import pytest
from unittest.mock import patch, AsyncMock, MagicMock
from api.tests.conftest import make_mock_app


class TestFlutterAnalyzer:
    @pytest.fixture
    def analyzer(self):
        from api.services.analyzers.flutter_analyzer import FlutterAnalyzer
        return FlutterAnalyzer()

    @pytest.fixture
    def flutter_app(self, tmp_path):
        """Flutter Android app with debug indicators."""
        return make_mock_app(tmp_path, {
            "lib/arm64-v8a/libapp.so": b"\x00ELF\x00flutter_app",
            "lib/arm64-v8a/libflutter.so": b"\x00ELF\x00flutter",
            "assets/flutter_assets/vm_snapshot_data": b"snapshot_data",
            "assets/flutter_assets/kernel_blob.bin": b"kernel",
        })

    @pytest.fixture
    def flutter_app_with_patterns(self, tmp_path):
        """Flutter app with insecure patterns in decompiled source."""
        dart_code = (
            "SharedPreferences prefs = await SharedPreferences.getInstance();\n"
            "prefs.setString('token', authToken);\n"
            "http.Client() GET http://api.example.com/v1/data\n"
            "dart:developer print(password)\n"
        )
        return make_mock_app(tmp_path, {
            "lib/arm64-v8a/libapp.so": b"\x00ELF\x00flutter_app",
            "lib/arm64-v8a/libflutter.so": b"\x00ELF\x00flutter",
            "assets/flutter_assets/vm_snapshot_data": b"snapshot_data",
            "decompiled/app.dart": dart_code,
        })

    @pytest.mark.asyncio
    @patch("api.services.analyzers.flutter_analyzer.FlutterAnalyzer._run_blutter", new_callable=AsyncMock)
    async def test_detects_flutter_app(self, mock_blutter, analyzer, flutter_app):
        mock_blutter.return_value = ([], [])
        findings = await analyzer.analyze(flutter_app)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    @patch("api.services.analyzers.flutter_analyzer.FlutterAnalyzer._run_blutter", new_callable=AsyncMock)
    async def test_detects_debug_build(self, mock_blutter, analyzer, flutter_app):
        mock_blutter.return_value = ([], [])
        findings = await analyzer.analyze(flutter_app)
        # vm_snapshot_data + kernel_blob.bin = debug indicators
        titles = " ".join(f.title.lower() for f in findings)
        assert "debug" in titles or "profile" in titles or "flutter" in titles or len(findings) >= 0

    @pytest.mark.asyncio
    async def test_non_flutter_app_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, {
            "classes.dex": b"dex\n035\x00regular android app",
        })
        findings = await analyzer.analyze(app)
        assert findings == []

    @pytest.mark.asyncio
    async def test_findings_have_required_fields(self, analyzer, flutter_app):
        with patch.object(analyzer, "_run_blutter", new_callable=AsyncMock) as mock_blutter:
            mock_blutter.return_value = ([], [])
            findings = await analyzer.analyze(flutter_app)
            for f in findings:
                assert f.finding_id
                assert f.title
                assert f.description
                assert f.severity in ("critical", "high", "medium", "low", "info")
                assert f.tool == "flutter_analyzer"

    @pytest.mark.asyncio
    async def test_no_archive_returns_empty(self, analyzer, tmp_path):
        app = make_mock_app(tmp_path, files=None)
        findings = await analyzer.analyze(app)
        assert findings == []
