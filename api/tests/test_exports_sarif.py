"""Tests for enhanced SARIF export."""

import json
import pytest
from unittest.mock import MagicMock
from api.routers.exports import _export_sarif, _build_rule_tags, _severity_to_sarif_level


def _make_finding(**overrides):
    """Create a mock Finding with default fields."""
    defaults = {
        "finding_id": "test-001",
        "canonical_id": "insecure_config_debuggable_app_test_android",
        "app_id": "test-app",
        "tool": "manifest_analyzer",
        "platform": "android",
        "severity": "high",
        "status": "open",
        "category": "Insecure Configuration",
        "title": "Debuggable Application",
        "description": "The application is marked as debuggable in the manifest.",
        "impact": "Attackers can attach debuggers.",
        "remediation": "Set android:debuggable to false in release builds.",
        "file_path": "AndroidManifest.xml",
        "line_number": 10,
        "code_snippet": 'android:debuggable="true"',
        "cwe_id": "CWE-489",
        "cwe_name": "Active Debug Code",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "owasp_masvs_category": "MASVS-RESILIENCE",
        "owasp_masvs_control": None,
        "owasp_mastg_test": None,
        "poc_evidence": None,
        "poc_verification": None,
        "poc_commands": [],
        "poc_frida_script": None,
        "poc_screenshot_path": None,
        "remediation_commands": [],
        "remediation_code": {},
        "remediation_resources": [],
        "resource_type": None,
        "risk_score": None,
        "tool_sources": ["manifest_analyzer"],
    }
    defaults.update(overrides)
    finding = MagicMock()
    for k, v in defaults.items():
        setattr(finding, k, v)
    return finding


def _make_app(package_name="com.example.testapp"):
    app = MagicMock()
    app.package_name = package_name
    return app


class TestSeverityMapping:
    def test_critical_maps_to_error(self):
        assert _severity_to_sarif_level("critical") == "error"

    def test_high_maps_to_error(self):
        assert _severity_to_sarif_level("high") == "error"

    def test_medium_maps_to_warning(self):
        assert _severity_to_sarif_level("medium") == "warning"

    def test_low_maps_to_note(self):
        assert _severity_to_sarif_level("low") == "note"

    def test_info_maps_to_note(self):
        assert _severity_to_sarif_level("info") == "note"

    def test_unknown_maps_to_note(self):
        assert _severity_to_sarif_level("unknown") == "note"


class TestBuildRuleTags:
    def test_includes_cwe_tag(self):
        finding = _make_finding(cwe_id="CWE-489")
        tags = _build_rule_tags(finding)
        assert "external/cwe/CWE-489" in tags

    def test_includes_owasp_tag(self):
        finding = _make_finding(owasp_masvs_category="MASVS-RESILIENCE")
        tags = _build_rule_tags(finding)
        assert "external/owasp/MASVS-RESILIENCE" in tags

    def test_includes_severity_tag(self):
        finding = _make_finding(severity="high")
        tags = _build_rule_tags(finding)
        assert "security/severity/high" in tags

    def test_always_includes_security_tag(self):
        finding = _make_finding()
        tags = _build_rule_tags(finding)
        assert "security" in tags


def _get_sarif(response) -> dict:
    """Extract SARIF JSON from a StreamingResponse."""
    import asyncio

    async def _read():
        chunks = []
        async for chunk in response.body_iterator:
            if isinstance(chunk, str):
                chunks.append(chunk.encode())
            else:
                chunks.append(chunk)
        return b"".join(chunks)

    content = asyncio.get_event_loop().run_until_complete(_read())
    return json.loads(content)


class TestExportSarif:
    def test_sarif_schema_and_version(self):
        app = _make_app()
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif

    def test_tool_metadata(self):
        app = _make_app()
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "Mobilicustos"
        assert driver["version"] == "0.1.3"

    def test_rules_have_full_description(self):
        app = _make_app()
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) > 0
        assert "fullDescription" in rules[0]
        assert "text" in rules[0]["fullDescription"]

    def test_rules_have_help(self):
        app = _make_app()
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "help" in rules[0]
        assert "Set android:debuggable" in rules[0]["help"]["text"]

    def test_rules_have_tags(self):
        app = _make_app()
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        tags = rules[0]["properties"]["tags"]
        assert "security" in tags
        assert "external/cwe/CWE-489" in tags

    def test_cwe_taxonomy_present(self):
        app = _make_app()
        findings = [_make_finding(cwe_id="CWE-489")]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        run = sarif["runs"][0]
        assert "taxonomies" in run
        assert run["taxonomies"][0]["name"] == "CWE"
        taxa_ids = [t["id"] for t in run["taxonomies"][0]["taxa"]]
        assert "CWE-489" in taxa_ids

    def test_cwe_relationships(self):
        app = _make_app()
        findings = [_make_finding(cwe_id="CWE-489")]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert "relationships" in rules[0]
        assert rules[0]["relationships"][0]["target"]["id"] == "CWE-489"

    def test_no_taxonomy_without_cwe(self):
        app = _make_app()
        findings = [_make_finding(cwe_id=None)]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        assert "taxonomies" not in sarif["runs"][0]

    def test_result_fingerprints(self):
        app = _make_app()
        findings = [_make_finding(canonical_id="test_canonical_id")]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        result = sarif["runs"][0]["results"][0]
        assert "fingerprints" in result
        assert result["fingerprints"]["mobilicustos/canonical/v1"] == "test_canonical_id"

    def test_result_code_snippet(self):
        app = _make_app()
        findings = [_make_finding(code_snippet='android:debuggable="true"')]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        result = sarif["runs"][0]["results"][0]
        region = result["locations"][0]["physicalLocation"]["region"]
        assert "snippet" in region
        assert 'debuggable' in region["snippet"]["text"]

    def test_result_properties(self):
        app = _make_app()
        findings = [_make_finding(cvss_score=7.5, severity="high")]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        result = sarif["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["cvssScore"] == 7.5
        assert result["properties"]["severity"] == "high"

    def test_message_includes_description(self):
        app = _make_app()
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        msg = sarif["runs"][0]["results"][0]["message"]["text"]
        assert "Debuggable Application" in msg
        assert "debuggable" in msg.lower()

    def test_filename_uses_package_name(self):
        app = _make_app("com.example.myapp")
        findings = [_make_finding()]
        response = _export_sarif(app, findings)
        disposition = response.headers["Content-Disposition"]
        assert "com.example.myapp" in disposition
        assert ".sarif" in disposition

    def test_empty_findings(self):
        app = _make_app()
        response = _export_sarif(app, [])
        sarif = _get_sarif(response)
        assert sarif["runs"][0]["results"] == []
        assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

    def test_multiple_findings_same_category(self):
        app = _make_app()
        findings = [
            _make_finding(finding_id="f1", title="Finding 1"),
            _make_finding(finding_id="f2", title="Finding 2"),
        ]
        response = _export_sarif(app, findings)
        sarif = _get_sarif(response)
        # Same category should produce only one rule
        assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
        assert len(sarif["runs"][0]["results"]) == 2

    def test_no_app_uses_generic_filename(self):
        response = _export_sarif(None, [_make_finding()])
        disposition = response.headers["Content-Disposition"]
        assert "all_findings.sarif" in disposition
