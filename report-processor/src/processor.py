"""
Report Processor for Mobilicustos

Processes raw analyzer outputs and normalizes them into unified findings.
Maps findings to OWASP MASVS/MASTG controls.
"""

import os
import json
import hashlib
import logging
from pathlib import Path
from typing import Any
from datetime import datetime

import yaml
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class FindingNormalizer:
    """Normalizes findings from various analyzers into a unified format."""

    def __init__(self, mappings_dir: Path):
        self.mappings_dir = mappings_dir
        self.masvs_mappings = self._load_masvs_mappings()
        self.severity_mappings = self._load_severity_mappings()
        self.remediation_templates = self._load_remediation_templates()

    def _load_masvs_mappings(self) -> dict:
        """Load OWASP MASVS category mappings."""
        mapping_file = self.mappings_dir / "masvs_mappings.yaml"
        if mapping_file.exists():
            with open(mapping_file) as f:
                return yaml.safe_load(f) or {}
        return {}

    def _load_severity_mappings(self) -> dict:
        """Load severity normalization mappings."""
        mapping_file = self.mappings_dir / "severity_mappings.yaml"
        if mapping_file.exists():
            with open(mapping_file) as f:
                return yaml.safe_load(f) or {}
        return {
            "critical": ["critical", "urgent", "severity1"],
            "high": ["high", "severe", "severity2"],
            "medium": ["medium", "moderate", "severity3"],
            "low": ["low", "minor", "severity4"],
            "info": ["info", "informational", "note", "severity5"]
        }

    def _load_remediation_templates(self) -> dict:
        """Load remediation templates for common finding types."""
        template_file = self.mappings_dir / "remediation_templates.yaml"
        if template_file.exists():
            with open(template_file) as f:
                return yaml.safe_load(f) or {}
        return {}

    def normalize_severity(self, raw_severity: str) -> str:
        """Normalize severity to standard values."""
        raw_lower = raw_severity.lower().strip()
        for severity, aliases in self.severity_mappings.items():
            if raw_lower in aliases or raw_lower == severity:
                return severity
        return "info"

    def generate_finding_id(self, finding: dict) -> str:
        """Generate a unique, deterministic finding ID."""
        key_parts = [
            finding.get("tool", ""),
            finding.get("app_id", ""),
            finding.get("title", ""),
            finding.get("file_path", ""),
            str(finding.get("line_number", ""))
        ]
        hash_input = "|".join(key_parts)
        return hashlib.sha256(hash_input.encode()).hexdigest()[:32]

    def map_to_masvs(self, finding: dict) -> dict:
        """Map finding to OWASP MASVS/MASTG controls."""
        category = finding.get("category", "")
        title = finding.get("title", "").lower()

        # Try category-based mapping
        if category in self.masvs_mappings:
            mapping = self.masvs_mappings[category]
            return {
                "owasp_masvs_category": mapping.get("category"),
                "owasp_masvs_control": mapping.get("control"),
                "owasp_mastg_test": mapping.get("test")
            }

        # Keyword-based fallback
        keyword_mappings = {
            "storage": ("MASVS-STORAGE", "MASVS-STORAGE-1", "MASTG-TEST-0001"),
            "crypto": ("MASVS-CRYPTO", "MASVS-CRYPTO-1", "MASTG-TEST-0013"),
            "auth": ("MASVS-AUTH", "MASVS-AUTH-1", "MASTG-TEST-0016"),
            "network": ("MASVS-NETWORK", "MASVS-NETWORK-1", "MASTG-TEST-0019"),
            "platform": ("MASVS-PLATFORM", "MASVS-PLATFORM-1", "MASTG-TEST-0024"),
            "code": ("MASVS-CODE", "MASVS-CODE-1", "MASTG-TEST-0038"),
            "resilience": ("MASVS-RESILIENCE", "MASVS-RESILIENCE-1", "MASTG-TEST-0048"),
            "privacy": ("MASVS-PRIVACY", "MASVS-PRIVACY-1", "MASTG-TEST-0054"),
        }

        for keyword, (cat, control, test) in keyword_mappings.items():
            if keyword in title or keyword in category.lower():
                return {
                    "owasp_masvs_category": cat,
                    "owasp_masvs_control": control,
                    "owasp_mastg_test": test
                }

        return {
            "owasp_masvs_category": None,
            "owasp_masvs_control": None,
            "owasp_mastg_test": None
        }

    def enrich_remediation(self, finding: dict) -> dict:
        """Enrich finding with detailed remediation guidance."""
        category = finding.get("category", "")
        platform = finding.get("platform", "android")

        if category in self.remediation_templates:
            template = self.remediation_templates[category]
            platform_remediation = template.get(platform, template.get("general", {}))

            return {
                "remediation": platform_remediation.get("description", finding.get("remediation", "")),
                "remediation_code": platform_remediation.get("code", {}),
                "remediation_commands": platform_remediation.get("commands", []),
                "remediation_resources": platform_remediation.get("resources", [])
            }

        return {
            "remediation": finding.get("remediation", "Review and address this finding."),
            "remediation_code": {},
            "remediation_commands": [],
            "remediation_resources": []
        }

    def normalize_finding(self, raw_finding: dict) -> dict:
        """Normalize a raw finding into the standard format."""
        # Base normalization
        normalized = {
            "finding_id": self.generate_finding_id(raw_finding),
            "tool": raw_finding.get("tool", "unknown"),
            "platform": raw_finding.get("platform", "android"),
            "severity": self.normalize_severity(raw_finding.get("severity", "info")),
            "status": "open",
            "category": raw_finding.get("category", ""),
            "title": raw_finding.get("title", ""),
            "description": raw_finding.get("description", ""),
            "impact": raw_finding.get("impact", ""),
            "file_path": raw_finding.get("file_path"),
            "line_number": raw_finding.get("line_number"),
            "code_snippet": raw_finding.get("code_snippet"),
            "poc_evidence": raw_finding.get("poc_evidence"),
            "poc_verification": raw_finding.get("poc_verification"),
            "poc_commands": raw_finding.get("poc_commands", []),
            "cwe_id": raw_finding.get("cwe_id"),
            "cwe_name": raw_finding.get("cwe_name"),
            "cvss_score": raw_finding.get("cvss_score"),
            "cvss_vector": raw_finding.get("cvss_vector"),
        }

        # Add MASVS mapping
        masvs = self.map_to_masvs(raw_finding)
        normalized.update(masvs)

        # Add enriched remediation
        remediation = self.enrich_remediation({**raw_finding, **normalized})
        normalized.update(remediation)

        # Calculate risk score
        severity_weights = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 0}
        normalized["risk_score"] = severity_weights.get(normalized["severity"], 0)

        return normalized


class ReportProcessor:
    """Processes analyzer reports and stores normalized findings."""

    def __init__(self):
        self.db_url = self._get_db_url()
        self.engine = create_engine(self.db_url)
        self.Session = sessionmaker(bind=self.engine)

        mappings_dir = Path(os.getenv("MAPPINGS_DIR", "/app/mappings"))
        self.normalizer = FindingNormalizer(mappings_dir)

    def _get_db_url(self) -> str:
        """Construct database URL from environment."""
        host = os.getenv("POSTGRES_HOST", "localhost")
        port = os.getenv("POSTGRES_PORT", "5432")
        db = os.getenv("POSTGRES_DB", "mobilicustos")
        user = os.getenv("POSTGRES_USER", "mobilicustos")
        password = os.getenv("POSTGRES_PASSWORD", "changeme")
        return f"postgresql://{user}:{password}@{host}:{port}/{db}"

    def process_report(self, report_path: Path, scan_id: str, app_id: str) -> list[dict]:
        """Process a single report file."""
        if not report_path.exists():
            logger.warning(f"Report file not found: {report_path}")
            return []

        with open(report_path) as f:
            if report_path.suffix == ".json":
                raw_findings = json.load(f)
            elif report_path.suffix in [".yaml", ".yml"]:
                raw_findings = yaml.safe_load(f)
            else:
                logger.warning(f"Unsupported report format: {report_path.suffix}")
                return []

        if isinstance(raw_findings, dict):
            raw_findings = raw_findings.get("findings", [raw_findings])

        normalized = []
        for raw in raw_findings:
            raw["scan_id"] = scan_id
            raw["app_id"] = app_id
            finding = self.normalizer.normalize_finding(raw)
            finding["scan_id"] = scan_id
            finding["app_id"] = app_id
            normalized.append(finding)

        return normalized

    def store_findings(self, findings: list[dict]) -> int:
        """Store normalized findings in the database."""
        if not findings:
            return 0

        session = self.Session()
        inserted = 0

        try:
            for finding in findings:
                # Use upsert pattern
                insert_sql = text("""
                    INSERT INTO findings (
                        finding_id, scan_id, app_id, tool, platform, severity, status,
                        category, title, description, impact, remediation,
                        file_path, line_number, code_snippet,
                        poc_evidence, poc_verification, poc_commands,
                        remediation_code, remediation_commands, remediation_resources,
                        risk_score, cvss_score, cvss_vector, cwe_id, cwe_name,
                        owasp_masvs_category, owasp_masvs_control, owasp_mastg_test
                    ) VALUES (
                        :finding_id, :scan_id, :app_id, :tool, :platform, :severity, :status,
                        :category, :title, :description, :impact, :remediation,
                        :file_path, :line_number, :code_snippet,
                        :poc_evidence, :poc_verification, :poc_commands,
                        :remediation_code, :remediation_commands, :remediation_resources,
                        :risk_score, :cvss_score, :cvss_vector, :cwe_id, :cwe_name,
                        :owasp_masvs_category, :owasp_masvs_control, :owasp_mastg_test
                    )
                    ON CONFLICT (finding_id) DO UPDATE SET
                        last_seen = NOW(),
                        status = EXCLUDED.status
                """)

                session.execute(insert_sql, {
                    **finding,
                    "poc_commands": json.dumps(finding.get("poc_commands", [])),
                    "remediation_code": json.dumps(finding.get("remediation_code", {})),
                    "remediation_commands": json.dumps(finding.get("remediation_commands", [])),
                    "remediation_resources": json.dumps(finding.get("remediation_resources", []))
                })
                inserted += 1

            session.commit()
            logger.info(f"Stored {inserted} findings")
        except Exception as e:
            session.rollback()
            logger.error(f"Error storing findings: {e}")
            raise
        finally:
            session.close()

        return inserted

    def process_scan_reports(self, scan_id: str, app_id: str, reports_dir: Path) -> dict:
        """Process all reports for a scan."""
        results = {
            "scan_id": scan_id,
            "processed_files": 0,
            "total_findings": 0,
            "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        }

        scan_reports_dir = reports_dir / scan_id
        if not scan_reports_dir.exists():
            logger.warning(f"No reports directory for scan: {scan_id}")
            return results

        all_findings = []
        for report_file in scan_reports_dir.glob("*.json"):
            findings = self.process_report(report_file, scan_id, app_id)
            all_findings.extend(findings)
            results["processed_files"] += 1

        for report_file in scan_reports_dir.glob("*.yaml"):
            findings = self.process_report(report_file, scan_id, app_id)
            all_findings.extend(findings)
            results["processed_files"] += 1

        if all_findings:
            self.store_findings(all_findings)
            results["total_findings"] = len(all_findings)
            for finding in all_findings:
                severity = finding.get("severity", "info")
                results["findings_by_severity"][severity] += 1

        return results


def main():
    """Main entry point for the report processor."""
    logger.info("Starting Mobilicustos Report Processor")

    reports_dir = Path(os.getenv("REPORTS_DIR", "/app/reports"))
    processor = ReportProcessor()

    # Process any pending reports
    # In production, this would be triggered by a message queue or API call
    logger.info(f"Watching reports directory: {reports_dir}")
    logger.info("Report processor ready. Waiting for reports...")

    # Keep the container running
    import time
    while True:
        time.sleep(60)


if __name__ == "__main__":
    main()
