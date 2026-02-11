"""Tests for finding deduplication logic in the scan orchestrator."""

from datetime import datetime
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from api.models.database import AttackPath, Finding, MobileApp, Scan
from api.services.scan_orchestrator import ScanOrchestrator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(**overrides) -> Finding:
    """Create a Finding with sensible defaults, overridable by kwargs."""
    defaults = dict(
        finding_id=f"test-{uuid4().hex[:8]}",
        canonical_id=None,
        app_id="com.example.app",
        scan_id=None,
        tool="test_tool",
        tool_sources=["test_tool"],
        platform="android",
        severity="medium",
        status="open",
        category="Configuration",
        title="Test Finding",
        description="Short description",
        impact="Some impact",
        remediation="Fix it",
        resource_type="file",
        file_path=None,
        line_number=None,
        code_snippet=None,
        poc_evidence=None,
        poc_verification=None,
        poc_commands=[],
        poc_frida_script=None,
        poc_screenshot_path=None,
        remediation_commands=[],
        remediation_code={},
        remediation_resources=[],
        risk_score=None,
        cvss_score=None,
        cvss_vector=None,
        cwe_id=None,
        cwe_name=None,
        owasp_masvs_category=None,
        owasp_masvs_control=None,
        owasp_mastg_test=None,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        created_at=datetime.utcnow(),
    )
    defaults.update(overrides)
    return Finding(**defaults)


def _make_scan(**overrides) -> Scan:
    defaults = dict(
        scan_id=uuid4(),
        app_id="com.example.app",
        scan_type="static",
        status="running",
    )
    defaults.update(overrides)
    return Scan(**defaults)


def _make_app(**overrides) -> MobileApp:
    defaults = dict(
        app_id="com.example.app",
        package_name="com.example.app",
        platform="android",
    )
    defaults.update(overrides)
    return MobileApp(**defaults)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMergeFindingGroup:
    """Tests for _merge_finding_group (within-scan dedup)."""

    def test_two_findings_same_canonical_merged(self):
        """Two findings with the same canonical_id are merged into one."""
        f1 = _make_finding(
            canonical_id="dup_1",
            tool="manifest_analyzer",
            tool_sources=["manifest_analyzer"],
            severity="medium",
            description="Short desc",
        )
        f2 = _make_finding(
            canonical_id="dup_1",
            tool="semgrep",
            tool_sources=["semgrep"],
            severity="high",
            description="A much longer and more detailed description",
        )
        merged = ScanOrchestrator._merge_finding_group([f1, f2])

        assert merged is not None
        assert len(merged.tool_sources) == 2
        assert "manifest_analyzer" in merged.tool_sources
        assert "semgrep" in merged.tool_sources

    def test_tool_sources_accumulation(self):
        """tool_sources from all findings are unioned."""
        f1 = _make_finding(canonical_id="x", tool_sources=["a"])
        f2 = _make_finding(canonical_id="x", tool_sources=["b"])
        f3 = _make_finding(canonical_id="x", tool_sources=["a", "c"])
        merged = ScanOrchestrator._merge_finding_group([f1, f2, f3])

        assert merged.tool_sources == ["a", "b", "c"]

    def test_severity_escalation(self):
        """Highest severity wins."""
        f1 = _make_finding(canonical_id="x", severity="low")
        f2 = _make_finding(canonical_id="x", severity="critical")
        f3 = _make_finding(canonical_id="x", severity="medium")
        merged = ScanOrchestrator._merge_finding_group([f1, f2, f3])

        assert merged.severity == "critical"

    def test_longer_description_wins(self):
        """The longest description is kept."""
        short = _make_finding(canonical_id="x", description="Short")
        long = _make_finding(
            canonical_id="x",
            description="A very long and detailed description with more context",
        )
        merged = ScanOrchestrator._merge_finding_group([short, long])

        assert "very long" in merged.description

    def test_poc_commands_combined(self):
        """poc_commands from all findings are combined, deduplicated by command."""
        f1 = _make_finding(
            canonical_id="x",
            poc_commands=[{"command": "adb shell am start", "type": "shell"}],
        )
        f2 = _make_finding(
            canonical_id="x",
            poc_commands=[
                {"command": "adb shell am start", "type": "shell"},
                {"command": "frida -U", "type": "frida"},
            ],
        )
        merged = ScanOrchestrator._merge_finding_group([f1, f2])

        commands = [c["command"] for c in merged.poc_commands]
        assert len(commands) == 2
        assert "adb shell am start" in commands
        assert "frida -U" in commands


class TestDeduplicateAndPersistFindings:
    """Tests for the full _deduplicate_and_persist_findings flow."""

    @pytest.mark.asyncio
    async def test_findings_without_canonical_pass_through(self):
        """Findings without canonical_id are persisted without merging."""
        db = AsyncMock()
        db.add = MagicMock()
        orch = ScanOrchestrator(db)
        scan = _make_scan()
        app = _make_app()

        f1 = _make_finding(canonical_id=None, finding_id="f1")
        f2 = _make_finding(canonical_id=None, finding_id="f2")

        persisted = await orch._deduplicate_and_persist_findings([f1, f2], scan, app)

        assert len(persisted) == 2
        assert db.add.call_count == 2

    @pytest.mark.asyncio
    async def test_within_scan_dedup_merges(self):
        """Two findings with same canonical_id in one batch produce one persisted finding."""
        db = AsyncMock()
        db.add = MagicMock()
        # No existing finding in DB
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        db.execute = AsyncMock(return_value=mock_result)

        orch = ScanOrchestrator(db)
        scan = _make_scan()
        app = _make_app()

        f1 = _make_finding(
            canonical_id="same_cid",
            tool_sources=["tool_a"],
            severity="medium",
        )
        f2 = _make_finding(
            canonical_id="same_cid",
            tool_sources=["tool_b"],
            severity="high",
        )

        persisted = await orch._deduplicate_and_persist_findings([f1, f2], scan, app)

        # Only one finding should be persisted (the merged one)
        assert len(persisted) == 1
        assert persisted[0].severity == "high"
        assert set(persisted[0].tool_sources) == {"tool_a", "tool_b"}

    @pytest.mark.asyncio
    async def test_cross_scan_dedup_updates_existing(self):
        """If a finding with the same canonical_id exists in DB, it is updated, not duplicated."""
        existing = _make_finding(
            canonical_id="existing_cid",
            finding_id="existing-abc123",
            tool_sources=["manifest_analyzer"],
            severity="medium",
            description="Old description",
            last_seen=datetime(2024, 1, 1),
        )

        db = AsyncMock()
        db.add = MagicMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = existing
        db.execute = AsyncMock(return_value=mock_result)

        orch = ScanOrchestrator(db)
        scan = _make_scan()
        app = _make_app()

        incoming = _make_finding(
            canonical_id="existing_cid",
            tool_sources=["semgrep"],
            severity="high",
            description="A much more detailed description from semgrep analysis",
        )

        persisted = await orch._deduplicate_and_persist_findings([incoming], scan, app)

        # Should return the existing (updated) finding, not add a new one
        assert len(persisted) == 1
        assert persisted[0] is existing
        assert db.add.call_count == 0  # No new add
        assert existing.severity == "high"  # Upgraded
        assert "semgrep" in existing.tool_sources
        assert "manifest_analyzer" in existing.tool_sources
        assert existing.scan_id == scan.scan_id


class TestUpdateExistingFinding:
    """Tests for _update_existing_finding."""

    def test_tool_sources_merged(self):
        existing = _make_finding(tool_sources=["a", "b"])
        incoming = _make_finding(tool_sources=["b", "c"])
        scan = _make_scan()

        ScanOrchestrator._update_existing_finding(existing, incoming, scan)

        assert existing.tool_sources == ["a", "b", "c"]

    def test_severity_upgraded(self):
        existing = _make_finding(severity="low")
        incoming = _make_finding(severity="critical")
        scan = _make_scan()

        ScanOrchestrator._update_existing_finding(existing, incoming, scan)

        assert existing.severity == "critical"

    def test_severity_not_downgraded(self):
        existing = _make_finding(severity="critical")
        incoming = _make_finding(severity="info")
        scan = _make_scan()

        ScanOrchestrator._update_existing_finding(existing, incoming, scan)

        assert existing.severity == "critical"

    def test_scan_id_updated(self):
        scan = _make_scan()
        existing = _make_finding(scan_id=uuid4())
        incoming = _make_finding()

        ScanOrchestrator._update_existing_finding(existing, incoming, scan)

        assert existing.scan_id == scan.scan_id

    def test_last_seen_updated(self):
        old_time = datetime(2020, 1, 1)
        existing = _make_finding(last_seen=old_time)
        incoming = _make_finding()
        scan = _make_scan()

        ScanOrchestrator._update_existing_finding(existing, incoming, scan)

        assert existing.last_seen > old_time


class TestGenerateAttackPaths:
    """Tests for _generate_attack_paths integration."""

    @pytest.mark.asyncio
    async def test_attack_paths_generated_post_scan(self):
        """Attack path generation is called and results are added to DB."""
        db = AsyncMock()
        db.add = MagicMock()
        db.execute = AsyncMock()

        orch = ScanOrchestrator(db)
        scan = _make_scan()
        app = _make_app()

        # Add some findings to the orchestrator
        orch.findings = [
            _make_finding(category="Component Security", severity="high"),
            _make_finding(category="Data Protection", severity="critical"),
        ]

        await orch._generate_attack_paths(scan, app)

        # Verify db.add was called for attack path rows
        # (AttackPathAnalyzer should find the "Data Exfiltration via Exported Component" template)
        assert db.add.call_count > 0

    @pytest.mark.asyncio
    async def test_attack_path_failure_is_non_fatal(self):
        """If attack path generation fails, the scan continues."""
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=Exception("DB error"))

        orch = ScanOrchestrator(db)
        scan = _make_scan()
        app = _make_app()
        orch.findings = []

        # Should not raise
        await orch._generate_attack_paths(scan, app)


class TestTriggerWebhook:
    """Tests for _trigger_webhook integration."""

    @pytest.mark.asyncio
    async def test_webhook_called_at_correct_points(self):
        """Webhook trigger does not raise on success."""
        db = AsyncMock()
        db.execute = AsyncMock(return_value=MagicMock(fetchall=MagicMock(return_value=[])))

        orch = ScanOrchestrator(db)

        # Should not raise even if no webhooks are configured
        await orch._trigger_webhook("scan.started", {"scan_id": "test"})
        await orch._trigger_webhook("scan.completed", {"scan_id": "test"})
        await orch._trigger_webhook("scan.failed", {"scan_id": "test"})
        await orch._trigger_webhook("finding.new", {"count": 1})

    @pytest.mark.asyncio
    async def test_webhook_failure_is_non_fatal(self):
        """Webhook failures never break the scan."""
        db = AsyncMock()

        orch = ScanOrchestrator(db)

        with patch(
            "api.services.webhook_service.WebhookService.trigger_event",
            side_effect=Exception("Connection refused"),
        ):
            # Should not raise
            await orch._trigger_webhook("scan.completed", {"scan_id": "test"})
