"""Semgrep-based static code analysis for mobile security vulnerabilities.

Uses Semgrep (https://semgrep.dev) to scan decompiled/extracted source code
from mobile applications for security issues including:

    - **Insecure cryptography**: Hardcoded encryption keys, weak algorithms,
      insecure random number generation (CWE-327, MASVS-CRYPTO).
    - **Authentication issues**: Hardcoded credentials, insecure session
      management, biometric bypass (CWE-798, MASVS-AUTH).
    - **Data leakage**: Sensitive data in logs, clipboard, NSUserDefaults,
      SharedPreferences (CWE-532, MASVS-STORAGE).
    - **Network security**: Hardcoded HTTP URLs, insecure WebView configs,
      certificate validation bypass (CWE-319, MASVS-NETWORK).
    - **Platform-specific issues**: Android exported components without
      permissions, iOS insecure data storage, SQL injection (MASVS-PLATFORM).

Architecture:
    Extracts the application archive to a temporary directory, runs semgrep
    with platform-specific and common rule sets, parses JSON output, maps
    results to MASVS categories, and deduplicates findings by check_id +
    file_path + line_number.

OWASP references:
    - MASVS-CRYPTO, MASVS-AUTH, MASVS-STORAGE, MASVS-NETWORK, MASVS-PLATFORM
    - MASTG-TEST-0014 (Crypto), MASTG-TEST-0019 (Auth), MASTG-TEST-0024 (Storage)
"""

import asyncio
import json
import logging
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class SemgrepAnalyzer(BaseAnalyzer):
    """Analyzes mobile app source code using Semgrep SAST tool.

    Runs Semgrep with bundled security rules tailored for Android (Java/Kotlin),
    iOS (Swift/Objective-C), and cross-platform frameworks (JavaScript, Dart).
    Each finding includes file location, line number, code snippet, severity,
    and MASVS mapping based on rule metadata.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("cross-platform").
    """

    name = "semgrep_analyzer"
    platform = "cross-platform"

    # Severity mapping from semgrep to Mobilicustos
    SEVERITY_MAP = {
        "ERROR": "high",
        "WARNING": "medium",
        "INFO": "low",
    }

    # MASVS mapping based on common vulnerability patterns
    MASVS_CATEGORY_MAP = {
        "crypto": "MASVS-CRYPTO",
        "hardcoded": "MASVS-STORAGE",
        "authentication": "MASVS-AUTH",
        "network": "MASVS-NETWORK",
        "webview": "MASVS-PLATFORM",
        "storage": "MASVS-STORAGE",
        "sql": "MASVS-PLATFORM",
        "logging": "MASVS-STORAGE",
        "clipboard": "MASVS-STORAGE",
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze mobile app source code using Semgrep.

        Extracts the archive to a temporary directory, runs semgrep with
        platform-specific and common rules, and parses the JSON output
        to create Finding objects.

        Args:
            app: The mobile application to analyze. Must have file_path
                pointing to the APK or IPA archive.

        Returns:
            A list of Finding objects representing detected security
            issues. Returns empty list if semgrep is not installed or
            analysis fails.
        """
        findings: list[Finding] = []

        if not app.file_path:
            logger.warning("No file path provided for semgrep analysis")
            return findings

        extracted_path = None
        try:
            # Create temp directory and extract archive
            extracted_path = Path(tempfile.mkdtemp(prefix="semgrep_analyzer_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                # Validate no path traversal in zip entries (Zip Slip protection)
                for member in archive.namelist():
                    member_path = (extracted_path / member).resolve()
                    if not str(member_path).startswith(str(extracted_path.resolve())):
                        raise ValueError(f"Zip entry escapes extraction dir: {member}")
                archive.extractall(extracted_path)

            logger.info(f"Extracted app to {extracted_path} for semgrep analysis")

            # Run semgrep with platform-specific and common rules
            semgrep_results = await self._run_semgrep(extracted_path, app.platform)

            if semgrep_results:
                findings.extend(await self._parse_semgrep_results(app, semgrep_results, extracted_path))

            logger.info(f"Semgrep analysis found {len(findings)} issues")

        except zipfile.BadZipFile as e:
            logger.error(f"Invalid archive file: {e}")
        except Exception as e:
            logger.error(f"Semgrep analysis failed: {e}", exc_info=True)
        finally:
            # Clean up temp directory
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception as e:
                    logger.warning(f"Failed to clean up temp directory: {e}")

        return findings

    async def _run_semgrep(
        self,
        target_path: Path,
        platform: str,
    ) -> dict[str, Any] | None:
        """Run semgrep with platform-specific and common rules.

        Executes semgrep as a subprocess with --json output format and
        platform-specific rule configurations.

        Args:
            target_path: Path to the extracted application directory.
            platform: Either "android" or "ios".

        Returns:
            Parsed JSON output from semgrep, or None if execution failed.
        """
        try:
            # Build semgrep command with rule configs
            rule_paths = []

            # Resolve rules directory from module location
            rules_dir = Path(__file__).resolve().parent.parent.parent / "semgrep-rules"

            # Add platform-specific rules
            if platform == "android":
                rule_paths.append(str(rules_dir / "android"))
            elif platform == "ios":
                rule_paths.append(str(rules_dir / "ios"))

            # Add common rules for all platforms
            rule_paths.append(str(rules_dir / "common"))

            # Build command
            cmd = ["semgrep", "scan", "--json", "--quiet"]
            for rule_path in rule_paths:
                cmd.extend(["--config", rule_path])
            cmd.append(str(target_path))

            logger.info(f"Running semgrep with command: {' '.join(cmd)}")

            # Run semgrep in thread pool to avoid blocking
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
            )

            # Exit code 0 = no findings, 1 = findings found, 2+ = actual error
            if result.returncode not in (0, 1):
                logger.error(f"Semgrep failed with exit code {result.returncode}: {result.stderr}")
                return None

            # Parse JSON output
            if result.stdout:
                return json.loads(result.stdout)

            return None

        except subprocess.TimeoutExpired:
            logger.error("Semgrep execution timed out after 5 minutes")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse semgrep JSON output: {e}")
            return None
        except FileNotFoundError:
            logger.error("Semgrep not found. Install with: pip install semgrep")
            return None
        except Exception as e:
            logger.error(f"Semgrep execution failed: {e}", exc_info=True)
            return None

    async def _parse_semgrep_results(
        self,
        app: MobileApp,
        results: dict[str, Any],
        extracted_path: Path,
    ) -> list[Finding]:
        """Parse semgrep JSON output and create Finding objects.

        Deduplicates findings by check_id + file_path + line_number and
        maps semgrep metadata to MASVS categories.

        Args:
            app: The mobile application being analyzed.
            results: Parsed JSON output from semgrep.
            extracted_path: Path to the extracted app directory for
                computing relative file paths.

        Returns:
            List of Finding objects from semgrep results.
        """
        findings: list[Finding] = []
        seen_findings: set[tuple[str, str, int]] = set()

        # Extract results array
        semgrep_findings = results.get("results", [])

        for result in semgrep_findings:
            try:
                # Extract basic fields
                check_id = result.get("check_id", "unknown")
                severity = result.get("extra", {}).get("severity", "WARNING")
                message = result.get("extra", {}).get("message", result.get("check_id", ""))

                # Extract location info
                path = result.get("path", "")
                start_line = result.get("start", {}).get("line", 0)
                end_line = result.get("end", {}).get("line", 0)

                # Get code snippet
                code_snippet = result.get("extra", {}).get("lines", "")

                # Compute relative path
                try:
                    rel_path = str(Path(path).relative_to(extracted_path))
                except ValueError:
                    rel_path = path

                # Deduplicate by check_id + file_path + line_number
                finding_key = (check_id, rel_path, start_line)
                if finding_key in seen_findings:
                    continue
                seen_findings.add(finding_key)

                # Map severity
                mapped_severity = self.SEVERITY_MAP.get(severity, "medium")

                # Determine MASVS category from check_id
                masvs_category = self._determine_masvs_category(check_id, result)

                # Extract CWE if present in metadata
                cwe_id = None
                cwe_name = None
                metadata = result.get("extra", {}).get("metadata", {})
                if "cwe" in metadata:
                    cwe_list = metadata["cwe"]
                    if isinstance(cwe_list, list) and cwe_list:
                        cwe_id = cwe_list[0] if cwe_list[0].startswith("CWE-") else f"CWE-{cwe_list[0]}"

                # Build description
                description = message
                if metadata.get("references"):
                    refs = metadata["references"]
                    if isinstance(refs, list):
                        description += f"\n\nReferences:\n" + "\n".join(f"- {ref}" for ref in refs)

                # Build remediation guidance
                remediation = metadata.get("fix_regex", {}).get("message", "")
                if not remediation:
                    remediation = f"Review the code at {rel_path}:{start_line} and apply security best practices."

                # Create finding
                finding = self.create_finding(
                    app=app,
                    title=check_id.replace(".", " ").replace("-", " ").title(),
                    description=description,
                    severity=mapped_severity,
                    category="Code Quality",
                    impact=f"Security issue detected by Semgrep rule {check_id}",
                    remediation=remediation,
                    file_path=rel_path,
                    line_number=start_line,
                    code_snippet=code_snippet,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    owasp_masvs_category=masvs_category,
                )

                findings.append(finding)

            except Exception as e:
                logger.warning(f"Failed to parse semgrep result: {e}")
                continue

        logger.info(f"Parsed {len(findings)} unique findings from semgrep results")
        return findings

    def _determine_masvs_category(self, check_id: str, result: dict[str, Any]) -> str | None:
        """Determine MASVS category based on check_id and metadata.

        Args:
            check_id: Semgrep rule identifier.
            result: Full semgrep result object with metadata.

        Returns:
            MASVS category string, or None if no mapping found.
        """
        check_id_lower = check_id.lower()

        # Check metadata for explicit MASVS mapping
        metadata = result.get("extra", {}).get("metadata", {})
        if "owasp" in metadata:
            owasp_data = metadata["owasp"]
            if isinstance(owasp_data, list):
                for item in owasp_data:
                    if isinstance(item, str) and item.startswith("MASVS-"):
                        return item

        # Fallback to pattern matching
        for pattern, category in self.MASVS_CATEGORY_MAP.items():
            if pattern in check_id_lower:
                return category

        return None
