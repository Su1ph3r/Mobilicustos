"""Scan orchestrator service for coordinating analysis."""

import asyncio
import logging
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from api.config import get_settings
from api.models.database import Finding, MobileApp, Scan, Secret
from api.services.docker_executor import DockerExecutor

logger = logging.getLogger(__name__)
settings = get_settings()


# Static analyzers configuration
STATIC_ANALYZERS = {
    "android": [
        "manifest_analyzer",
        "dex_analyzer",
        "network_security_config_analyzer",
        "native_lib_analyzer",
        "resource_analyzer",
        "secret_scanner",
        "ssl_pinning_analyzer",
        "code_quality_analyzer",
        "firebase_analyzer",
        "authentication_analyzer",
        "data_leakage_analyzer",
    ],
    "ios": [
        "plist_analyzer",
        "ios_binary_analyzer",
        "entitlements_analyzer",
        "secret_scanner",
        "ssl_pinning_analyzer",
        "code_quality_analyzer",
        "firebase_analyzer",
        "authentication_analyzer",
        "data_leakage_analyzer",
    ],
    "cross_platform": [
        "flutter_analyzer",
        "react_native_analyzer",
        "ml_model_analyzer",
    ],
}


async def run_scan(scan_id: UUID) -> None:
    """Run a scan asynchronously."""
    # Create new database session for background task
    engine = create_async_engine(settings.database_url)
    async_session = async_sessionmaker(engine, expire_on_commit=False)

    async with async_session() as db:
        try:
            # Get scan
            result = await db.execute(select(Scan).where(Scan.scan_id == scan_id))
            scan = result.scalar_one_or_none()

            if not scan:
                logger.error(f"Scan not found: {scan_id}")
                return

            # Get app
            result = await db.execute(
                select(MobileApp).where(MobileApp.app_id == scan.app_id)
            )
            app = result.scalar_one_or_none()

            if not app:
                logger.error(f"App not found: {scan.app_id}")
                scan.status = "failed"
                scan.error_message = "App not found"
                await db.commit()
                return

            # Update scan status
            scan.status = "running"
            scan.started_at = datetime.utcnow()
            await db.commit()

            orchestrator = ScanOrchestrator(db)
            await orchestrator.execute_scan(scan, app)

        except Exception as e:
            logger.error(f"Scan failed: {e}")
            try:
                await db.rollback()
                scan.status = "failed"
                scan.error_message = str(e)[:500]
                scan.completed_at = datetime.utcnow()
                await db.commit()
            except Exception as commit_error:
                logger.error(f"Failed to update scan status: {commit_error}")


class ScanOrchestrator:
    """Orchestrates the scan process."""

    def __init__(self, db: AsyncSession):
        self.db = db
        self.docker = DockerExecutor()
        self.findings: list[Finding] = []

    async def execute_scan(self, scan: Scan, app: MobileApp) -> None:
        """Execute a complete scan."""
        try:
            # Determine analyzers to run
            analyzers = self._get_analyzers(scan, app)
            total_analyzers = len(analyzers)

            logger.info(f"Starting scan with {total_analyzers} analyzers")

            # Run each analyzer
            for i, analyzer_name in enumerate(analyzers):
                if scan.status == "cancelled":
                    break

                try:
                    # Update progress
                    scan.current_analyzer = analyzer_name
                    scan.progress = int((i / total_analyzers) * 100)
                    await self.db.commit()

                    # Run analyzer
                    logger.info(f"Running analyzer: {analyzer_name}")
                    findings = await self._run_analyzer(analyzer_name, app)

                    # Save findings — set scan_id and make finding_id unique per scan
                    for finding in findings:
                        finding.scan_id = scan.scan_id
                        # Append scan_id to finding_id to prevent collisions across scans
                        finding.finding_id = f"{finding.finding_id}-{str(scan.scan_id)[:8]}"
                        self.db.add(finding)
                        self.findings.append(finding)

                    # Flush findings to database before creating secrets (foreign key constraint)
                    await self.db.flush()

                    # Create Secret entries for secret_scanner findings
                    if analyzer_name == "secret_scanner":
                        for finding in findings:
                            if finding.category == "Secrets":
                                self._create_secret_from_finding(finding, scan)

                except Exception as e:
                    logger.error(f"Analyzer {analyzer_name} failed: {e}")
                    await self.db.rollback()
                    scan.analyzer_errors = scan.analyzer_errors + [
                        {"analyzer": analyzer_name, "error": str(e)[:200]}
                    ]

            # Update scan completion
            scan.status = "completed"
            scan.progress = 100
            scan.current_analyzer = None
            scan.completed_at = datetime.utcnow()
            scan.findings_count = self._count_findings()

            # Update app status
            app.status = "completed"
            app.last_analyzed = datetime.utcnow()

            await self.db.commit()
            logger.info(f"Scan completed: {len(self.findings)} findings")

        except Exception as e:
            await self.db.rollback()
            scan.status = "failed"
            scan.error_message = str(e)[:500]
            scan.completed_at = datetime.utcnow()
            await self.db.commit()
            raise

    def _get_analyzers(self, scan: Scan, app: MobileApp) -> list[str]:
        """Determine which analyzers to run."""
        if scan.analyzers_enabled:
            return scan.analyzers_enabled

        if scan.scan_type == "dynamic":
            # Dynamic scans run only dynamic analyzers
            return ["runtime_analyzer", "network_analyzer"]

        # Static / full scans: platform-specific static analyzers
        analyzers = STATIC_ANALYZERS.get(app.platform, []).copy()

        # Add cross-platform analyzers if applicable
        if app.framework in ("flutter", "react_native", "xamarin", "maui"):
            analyzers.extend(STATIC_ANALYZERS.get("cross_platform", []))

        # Full scans include both static and dynamic
        if scan.scan_type == "full":
            analyzers.extend(["runtime_analyzer", "network_analyzer"])

        return analyzers

    async def _run_analyzer(
        self,
        analyzer_name: str,
        app: MobileApp,
    ) -> list[Finding]:
        """Run a specific analyzer."""
        # Import analyzer module dynamically
        try:
            if analyzer_name == "manifest_analyzer":
                from api.services.analyzers.manifest_analyzer import ManifestAnalyzer
                analyzer = ManifestAnalyzer()
            elif analyzer_name == "dex_analyzer":
                from api.services.analyzers.dex_analyzer import DexAnalyzer
                analyzer = DexAnalyzer()
            elif analyzer_name == "secret_scanner":
                from api.services.analyzers.secret_scanner import SecretScanner
                analyzer = SecretScanner()
            elif analyzer_name == "flutter_analyzer":
                from api.services.analyzers.flutter_analyzer import FlutterAnalyzer
                analyzer = FlutterAnalyzer()
            elif analyzer_name == "react_native_analyzer":
                from api.services.analyzers.react_native_analyzer import ReactNativeAnalyzer
                analyzer = ReactNativeAnalyzer()
            elif analyzer_name == "plist_analyzer":
                from api.services.analyzers.plist_analyzer import PlistAnalyzer
                analyzer = PlistAnalyzer()
            elif analyzer_name == "ios_binary_analyzer":
                from api.services.analyzers.ios_binary_analyzer import iOSBinaryAnalyzer
                analyzer = iOSBinaryAnalyzer()
            elif analyzer_name == "network_security_config_analyzer":
                from api.services.analyzers.network_security_config_analyzer import NetworkSecurityConfigAnalyzer
                analyzer = NetworkSecurityConfigAnalyzer()
            elif analyzer_name == "native_lib_analyzer":
                from api.services.analyzers.native_lib_analyzer import NativeLibAnalyzer
                analyzer = NativeLibAnalyzer()
            elif analyzer_name == "resource_analyzer":
                from api.services.analyzers.resource_analyzer import ResourceAnalyzer
                analyzer = ResourceAnalyzer()
            elif analyzer_name == "entitlements_analyzer":
                from api.services.analyzers.entitlements_analyzer import EntitlementsAnalyzer
                analyzer = EntitlementsAnalyzer()
            elif analyzer_name == "ml_model_analyzer":
                from api.services.ml_analyzer import MLModelAnalyzer
                analyzer = MLModelAnalyzer()
            elif analyzer_name == "ssl_pinning_analyzer":
                from api.services.analyzers.ssl_pinning_analyzer import SSLPinningAnalyzer
                analyzer = SSLPinningAnalyzer()
            elif analyzer_name == "code_quality_analyzer":
                from api.services.analyzers.code_quality_analyzer import CodeQualityAnalyzer
                analyzer = CodeQualityAnalyzer()
            elif analyzer_name == "firebase_analyzer":
                from api.services.analyzers.firebase_analyzer import FirebaseAnalyzer
                analyzer = FirebaseAnalyzer()
            elif analyzer_name == "authentication_analyzer":
                from api.services.analyzers.authentication_analyzer import AuthenticationAnalyzer
                analyzer = AuthenticationAnalyzer()
            elif analyzer_name == "data_leakage_analyzer":
                from api.services.analyzers.data_leakage_analyzer import DataLeakageAnalyzer
                analyzer = DataLeakageAnalyzer()
            elif analyzer_name == "runtime_analyzer":
                from api.services.analyzers.runtime_analyzer import RuntimeAnalyzer
                analyzer = RuntimeAnalyzer()
            elif analyzer_name == "network_analyzer":
                from api.services.analyzers.network_analyzer import NetworkAnalyzer
                analyzer = NetworkAnalyzer()
            else:
                logger.warning(f"Unknown analyzer: {analyzer_name}")
                return []

            return await analyzer.analyze(app)

        except ImportError as e:
            logger.warning(f"Analyzer not implemented: {analyzer_name} - {e}")
            return []

    def _count_findings(self) -> dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def _create_secret_from_finding(self, finding: Finding, scan: Scan) -> None:
        """Create a Secret entry from a secret_scanner finding."""
        import hashlib
        import re

        # Extract secret type from title (e.g., "Hardcoded AWS Access Key (aws)")
        title = finding.title or ""
        provider = None

        # Extract provider from title if present
        provider_match = re.search(r'\(([^)]+)\)$', title)
        if provider_match:
            provider = provider_match.group(1)

        # Determine secret type from title
        type_map = {
            "api key": "api_key",
            "secret key": "api_key",
            "token": "token",
            "password": "password",
            "private key": "private_key",
            "oauth": "oauth_secret",
            "database": "database_url",
            "firebase": "api_key",
            "bearer": "token",
        }
        secret_type = "api_key"  # default
        title_lower = title.lower()
        for keyword, stype in type_map.items():
            if keyword in title_lower:
                secret_type = stype
                break

        # Extract redacted value from poc_evidence if available
        redacted_value = None
        if finding.poc_evidence:
            # Look for pattern like "Found AWS Access Key: AKIA****XXXX"
            match = re.search(r':\s*([^\n]+)', finding.poc_evidence)
            if match:
                redacted_value = match.group(1).strip()[:256]

        # Create hash from finding_id for deduplication
        secret_hash = hashlib.sha256(finding.finding_id.encode()).hexdigest()[:16]

        # Create Secret entry
        secret = Secret(
            app_id=finding.app_id,
            scan_id=scan.scan_id,
            finding_id=finding.finding_id,
            secret_type=secret_type,
            provider=provider,
            file_path=finding.file_path,
            line_number=finding.line_number,
            context=finding.code_snippet,
            secret_value_redacted=redacted_value,
            secret_hash=secret_hash,
            exposure_risk=finding.severity,
        )
        self.db.add(secret)
