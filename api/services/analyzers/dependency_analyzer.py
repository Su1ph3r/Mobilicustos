"""Dependency vulnerability scanner for mobile application supply chain analysis.

Analyzes application dependencies for known vulnerabilities by:

    1. **Dependency file parsing**: Extracts version-pinned dependencies from
       build.gradle/build.gradle.kts (Android/Maven), Podfile/Podfile.lock
       (iOS/CocoaPods), package.json (React Native/Cordova/npm), and
       pubspec.yaml/pubspec.lock (Flutter/Pub).

    2. **Vulnerability database lookup**: Queries the OSV (Open Source
       Vulnerabilities) API for each dependency to find known CVEs with
       severity ratings, affected version ranges, and fix versions.

    3. **Library fingerprinting**: Uses the ``LibraryFingerprinter`` to detect
       native libraries and SDKs embedded in the binary that may not appear
       in manifest dependency files.

Vulnerability severity is determined from CVSS v3 scores in OSV data,
with fallback to database-specific severity fields.

OWASP references:
    - CWE-1395: Dependency on Vulnerable Third-Party Component
    - MASVS-CODE, MSTG-CODE-5
"""

import asyncio
import json
import logging
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from api.models.database import MobileApp, Finding
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult
from api.services.cve import CVEDetector, LibraryFingerprinter
from api.services.cve.models import LibrarySource, DetectionMethod

logger = logging.getLogger(__name__)

# OSV API endpoint
OSV_API_URL = "https://api.osv.dev/v1/query"

# NVD API endpoint (requires API key for higher rate limits)
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class Dependency:
    """Represents a single dependency."""
    package_manager: str
    name: str
    version: str | None
    source_file: str


@dataclass
class VulnerabilityInfo:
    """Vulnerability information from databases."""
    id: str
    severity: str
    summary: str
    details: str | None = None
    fixed_version: str | None = None
    references: list[str] | None = None


class DependencyAnalyzer(BaseAnalyzer):
    """Analyzes application dependencies for known vulnerabilities."""

    name = "dependency_analyzer"
    description = "Scans dependencies for known vulnerabilities"

    # Ecosystem mapping for OSV
    ECOSYSTEM_MAP = {
        "gradle": "Maven",
        "cocoapods": "CocoaPods",
        "npm": "npm",
        "pub": "Pub",
        "swiftpm": "SwiftPM",
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze dependencies in the app archive.

        Extracts the app to a temporary directory, parses dependency files,
        and checks for known vulnerabilities.
        """
        if not app.file_path:
            logger.warning("No file path for dependency analysis")
            return []

        results: list[AnalyzerResult] = []
        dependencies: list[Dependency] = []

        # Extract to temp directory for analysis
        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="dep_analyzer_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            # Parse dependency files based on platform
            if app.platform == "android":
                dependencies.extend(await self._parse_gradle_files(extracted_path))
                dependencies.extend(await self._parse_package_json(extracted_path))
                dependencies.extend(await self._parse_yarn_lock(extracted_path))
            elif app.platform == "ios":
                dependencies.extend(await self._parse_podfile(extracted_path))
                dependencies.extend(await self._parse_swift_package_resolved(extracted_path))
                dependencies.extend(await self._parse_package_json(extracted_path))
                dependencies.extend(await self._parse_yarn_lock(extracted_path))

            # Check for Flutter/React Native
            if app.framework == "flutter":
                dependencies.extend(await self._parse_pubspec(extracted_path))
            elif app.framework == "react_native":
                dependencies.extend(await self._parse_package_json(extracted_path))
                dependencies.extend(await self._parse_yarn_lock(extracted_path))

            logger.info(f"Found {len(dependencies)} dependencies to analyze")

            # Check each dependency for vulnerabilities
            vulnerable_deps = []
            for dep in dependencies:
                vulns = await self._check_vulnerability(dep)
                if vulns:
                    vulnerable_deps.append((dep, vulns))
                    results.append(self._create_finding(dep, vulns, app))

            # Also run library fingerprinting for native libs and SDKs
            try:
                fingerprinter = LibraryFingerprinter()
                detected_libs = fingerprinter.fingerprint_all(extracted_path)

                for lib in detected_libs:
                    # Convert to Dependency for existing vulnerability check
                    dep = Dependency(
                        package_manager=lib.source.value,
                        name=lib.name,
                        version=lib.version,
                        source_file=lib.file_path or "native"
                    )
                    vulns = await self._check_vulnerability(dep)
                    if vulns:
                        vulnerable_deps.append((dep, vulns))
                        results.append(self._create_finding(dep, vulns, app))

                logger.info(f"Fingerprinted {len(detected_libs)} additional libraries")
            except Exception as e:
                logger.warning(f"Library fingerprinting failed: {e}")

            # Run SDK fingerprinting for Android apps
            if app.platform == "android":
                try:
                    sdk_deps = await self._fingerprint_sdks(extracted_path)
                    dependencies.extend(sdk_deps)
                    logger.info(f"Fingerprinted {len(sdk_deps)} SDKs via class patterns")
                except Exception as e:
                    logger.warning(f"SDK fingerprinting failed: {e}")

            # Add summary finding if vulnerabilities found
            if vulnerable_deps:
                results.append(self._create_summary_finding(vulnerable_deps, app))

        except zipfile.BadZipFile as e:
            logger.error(f"Invalid archive file: {e}")
            return []
        except Exception as e:
            logger.error(f"Dependency analysis failed: {e}")
            return []
        finally:
            # Clean up temp directory
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception as e:
                    logger.warning(f"Failed to clean up temp directory: {e}")

        # Convert AnalyzerResults to Findings
        findings = []
        for result in results:
            finding = self.result_to_finding(app, result)
            findings.append(finding)

        return findings

    async def _parse_gradle_files(self, extracted_path: Path) -> list[Dependency]:
        """Parse build.gradle, build.gradle.kts, and gradle.lockfile files."""
        dependencies = []

        gradle_patterns = [
            r'implementation\s*[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]',
            r'api\s*[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]',
            r'compile\s*[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]',
            r'implementation\s*\(\s*[\'"]([^:]+):([^:]+):([^\'"]+)[\'"]\s*\)',
        ]

        for gradle_file in extracted_path.rglob("*.gradle*"):
            try:
                content = gradle_file.read_text(errors='ignore')
                for pattern in gradle_patterns:
                    matches = re.findall(pattern, content)
                    for match in matches:
                        group_id, artifact_id, version = match
                        dependencies.append(Dependency(
                            package_manager="gradle",
                            name=f"{group_id}:{artifact_id}",
                            version=version.strip(),
                            source_file=str(gradle_file.relative_to(extracted_path))
                        ))
            except Exception as e:
                logger.warning(f"Error parsing {gradle_file}: {e}")

        # Parse gradle.lockfile for transitive dependencies
        for lockfile in extracted_path.rglob("gradle.lockfile"):
            try:
                content = lockfile.read_text(errors='ignore')
                # Format: group:artifact:version=...
                lockfile_pattern = r'^([^:]+):([^:]+):([^=]+)='
                for line in content.split('\n'):
                    match = re.match(lockfile_pattern, line.strip())
                    if match:
                        group_id, artifact_id, version = match.groups()
                        dependencies.append(Dependency(
                            package_manager="gradle",
                            name=f"{group_id}:{artifact_id}",
                            version=version.strip(),
                            source_file=str(lockfile.relative_to(extracted_path))
                        ))
            except Exception as e:
                logger.warning(f"Error parsing {lockfile}: {e}")

        return dependencies

    async def _parse_podfile(self, extracted_path: Path) -> list[Dependency]:
        """Parse Podfile and Podfile.lock."""
        dependencies = []

        # Parse Podfile.lock (more accurate versions)
        podfile_lock = extracted_path / "Podfile.lock"
        if podfile_lock.exists():
            try:
                content = podfile_lock.read_text(errors='ignore')
                # Parse PODS section
                pods_match = re.search(r'PODS:\n((?:  - .+\n)+)', content)
                if pods_match:
                    pods_section = pods_match.group(1)
                    for line in pods_section.split('\n'):
                        match = re.match(r'  - ([^/\s]+)\s*\(([^)]+)\)', line.strip())
                        if match:
                            name, version = match.groups()
                            dependencies.append(Dependency(
                                package_manager="cocoapods",
                                name=name,
                                version=version,
                                source_file="Podfile.lock"
                            ))
            except Exception as e:
                logger.warning(f"Error parsing Podfile.lock: {e}")

        # Fallback to Podfile
        if not dependencies:
            podfile = extracted_path / "Podfile"
            if podfile.exists():
                try:
                    content = podfile.read_text(errors='ignore')
                    pattern = r"pod\s+['\"]([^'\"]+)['\"](?:,\s*['\"]([^'\"]+)['\"])?"
                    matches = re.findall(pattern, content)
                    for match in matches:
                        name = match[0]
                        version = match[1] if len(match) > 1 and match[1] else None
                        dependencies.append(Dependency(
                            package_manager="cocoapods",
                            name=name,
                            version=version,
                            source_file="Podfile"
                        ))
                except Exception as e:
                    logger.warning(f"Error parsing Podfile: {e}")

        return dependencies

    async def _parse_package_json(self, extracted_path: Path) -> list[Dependency]:
        """Parse package.json files (React Native, Cordova, etc.)."""
        dependencies = []

        for pkg_file in extracted_path.rglob("package.json"):
            # Skip node_modules
            if "node_modules" in str(pkg_file):
                continue

            try:
                content = json.loads(pkg_file.read_text(errors='ignore'))
                for dep_type in ["dependencies", "devDependencies"]:
                    if dep_type in content:
                        for name, version in content[dep_type].items():
                            # Clean version string
                            clean_version = re.sub(r'^[\^~>=<]+', '', version)
                            dependencies.append(Dependency(
                                package_manager="npm",
                                name=name,
                                version=clean_version,
                                source_file=str(pkg_file.relative_to(extracted_path))
                            ))
            except Exception as e:
                logger.warning(f"Error parsing {pkg_file}: {e}")

        return dependencies

    async def _parse_pubspec(self, extracted_path: Path) -> list[Dependency]:
        """Parse pubspec.yaml and pubspec.lock (Flutter)."""
        dependencies = []

        # Try pubspec.lock first (accurate versions)
        pubspec_lock = extracted_path / "pubspec.lock"
        if pubspec_lock.exists():
            try:
                content = pubspec_lock.read_text(errors='ignore')
                # Simple YAML-like parsing
                current_package = None
                for line in content.split('\n'):
                    if line.startswith('  ') and ':' in line and not line.startswith('    '):
                        current_package = line.strip().rstrip(':')
                    elif 'version:' in line and current_package:
                        version = line.split('version:')[1].strip().strip('"\'')
                        dependencies.append(Dependency(
                            package_manager="pub",
                            name=current_package,
                            version=version,
                            source_file="pubspec.lock"
                        ))
            except Exception as e:
                logger.warning(f"Error parsing pubspec.lock: {e}")

        return dependencies

    async def _parse_swift_package_resolved(self, extracted_path: Path) -> list[Dependency]:
        """Parse Package.resolved (SwiftPM) for iOS apps.

        Supports both v1 and v2 format:
        - v1: object.pins[].package, object.pins[].state.version
        - v2: pins[].identity, pins[].state.version
        """
        dependencies = []

        for resolved_file in extracted_path.rglob("Package.resolved"):
            try:
                content = json.loads(resolved_file.read_text(errors='ignore'))

                # Detect version format
                if "object" in content and "pins" in content.get("object", {}):
                    # v1 format
                    pins = content["object"]["pins"]
                    for pin in pins:
                        name = pin.get("package")
                        version = pin.get("state", {}).get("version")
                        if name:
                            dependencies.append(Dependency(
                                package_manager="swiftpm",
                                name=name,
                                version=version,
                                source_file=str(resolved_file.relative_to(extracted_path))
                            ))
                elif "pins" in content:
                    # v2 format
                    pins = content["pins"]
                    for pin in pins:
                        name = pin.get("identity")
                        version = pin.get("state", {}).get("version")
                        if name:
                            dependencies.append(Dependency(
                                package_manager="swiftpm",
                                name=name,
                                version=version,
                                source_file=str(resolved_file.relative_to(extracted_path))
                            ))
            except Exception as e:
                logger.warning(f"Error parsing {resolved_file}: {e}")

        return dependencies

    async def _parse_yarn_lock(self, extracted_path: Path) -> list[Dependency]:
        """Parse yarn.lock for JavaScript dependencies.

        Format: "package@version":
                  version "x.y.z"
        """
        dependencies = []

        for yarn_lock in extracted_path.rglob("yarn.lock"):
            # Skip node_modules
            if "node_modules" in str(yarn_lock):
                continue

            try:
                content = yarn_lock.read_text(errors='ignore')
                lines = content.split('\n')

                current_package = None
                for i, line in enumerate(lines):
                    # Match package declaration like: "package@version":
                    pkg_match = re.match(r'^"?([^@"]+)@[^"]*"?:\s*$', line.strip())
                    if pkg_match:
                        current_package = pkg_match.group(1)
                    # Match version line like:   version "1.2.3"
                    elif current_package and line.strip().startswith('version '):
                        version_match = re.search(r'version\s+"([^"]+)"', line)
                        if version_match:
                            version = version_match.group(1)
                            dependencies.append(Dependency(
                                package_manager="npm",
                                name=current_package,
                                version=version,
                                source_file=str(yarn_lock.relative_to(extracted_path))
                            ))
                            current_package = None
            except Exception as e:
                logger.warning(f"Error parsing {yarn_lock}: {e}")

        return dependencies

    async def _fingerprint_sdks(self, extracted_path: Path) -> list[Dependency]:
        """Fingerprint known SDKs via class pattern detection in Android apps.

        Scans for known SDK class patterns in decompiled source or DEX files.
        """
        dependencies = []

        # SDK pattern database: package prefix -> SDK name
        SDK_PATTERNS = {
            "com.google.firebase": "Firebase SDK",
            "com.facebook.sdk": "Facebook SDK",
            "com.adjust.sdk": "Adjust SDK",
            "io.sentry": "Sentry SDK",
            "com.appboy": "Braze SDK (Appboy)",
            "com.braze": "Braze SDK",
            "com.appsflyer": "AppsFlyer SDK",
        }

        detected_sdks = set()

        try:
            # Search for class files in decompiled source
            for java_file in extracted_path.rglob("*.java"):
                if "node_modules" in str(java_file):
                    continue

                try:
                    content = java_file.read_text(errors='ignore')
                    # Look for package declarations and imports
                    for pattern, sdk_name in SDK_PATTERNS.items():
                        if pattern in content and sdk_name not in detected_sdks:
                            detected_sdks.add(sdk_name)
                            dependencies.append(Dependency(
                                package_manager="gradle",
                                name=pattern,
                                version=None,  # Version unknown from fingerprinting
                                source_file=str(java_file.relative_to(extracted_path))
                            ))
                except Exception as e:
                    logger.debug(f"Error scanning {java_file}: {e}")

            # Also check smali files if available
            for smali_file in extracted_path.rglob("*.smali"):
                try:
                    content = smali_file.read_text(errors='ignore')
                    for pattern, sdk_name in SDK_PATTERNS.items():
                        # Convert Java package to smali format: com/google/firebase
                        smali_pattern = pattern.replace(".", "/")
                        if smali_pattern in content and sdk_name not in detected_sdks:
                            detected_sdks.add(sdk_name)
                            dependencies.append(Dependency(
                                package_manager="gradle",
                                name=pattern,
                                version=None,
                                source_file=str(smali_file.relative_to(extracted_path))
                            ))
                except Exception as e:
                    logger.debug(f"Error scanning {smali_file}: {e}")

        except Exception as e:
            logger.warning(f"SDK fingerprinting error: {e}")

        return dependencies

    async def _check_vulnerability(self, dep: Dependency) -> list[VulnerabilityInfo]:
        """Check a dependency against vulnerability databases."""
        vulnerabilities = []

        ecosystem = self.ECOSYSTEM_MAP.get(dep.package_manager, dep.package_manager)

        # Check OSV database
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                payload = {
                    "package": {
                        "name": dep.name.split(":")[-1] if ":" in dep.name else dep.name,
                        "ecosystem": ecosystem
                    }
                }
                if dep.version:
                    payload["version"] = dep.version

                response = await client.post(OSV_API_URL, json=payload)
                if response.status_code == 200:
                    data = response.json()
                    for vuln in data.get("vulns", []):
                        severity = self._parse_osv_severity(vuln)
                        vulnerabilities.append(VulnerabilityInfo(
                            id=vuln.get("id", "UNKNOWN"),
                            severity=severity,
                            summary=vuln.get("summary", ""),
                            details=vuln.get("details"),
                            fixed_version=self._get_fixed_version(vuln),
                            references=[ref.get("url") for ref in vuln.get("references", [])]
                        ))
        except Exception as e:
            logger.debug(f"OSV check failed for {dep.name}: {e}")

        return vulnerabilities

    def _parse_osv_severity(self, vuln: dict) -> str:
        """Extract severity from OSV vulnerability."""
        severity_info = vuln.get("severity", [])
        if severity_info:
            for sev in severity_info:
                if sev.get("type") == "CVSS_V3":
                    score = sev.get("score", "")
                    # Parse CVSS score
                    try:
                        cvss_score = float(score.split("/")[0].split(":")[1]) if ":" in score else float(score)
                        if cvss_score >= 9.0:
                            return "critical"
                        elif cvss_score >= 7.0:
                            return "high"
                        elif cvss_score >= 4.0:
                            return "medium"
                        else:
                            return "low"
                    except:
                        pass

        # Fallback to database_specific severity
        db_specific = vuln.get("database_specific", {})
        if "severity" in db_specific:
            return db_specific["severity"].lower()

        return "medium"

    def _get_fixed_version(self, vuln: dict) -> str | None:
        """Extract fixed version from OSV vulnerability."""
        for affected in vuln.get("affected", []):
            for range_info in affected.get("ranges", []):
                for event in range_info.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
        return None

    def _create_finding(
        self,
        dep: Dependency,
        vulns: list[VulnerabilityInfo],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create a finding for a vulnerable dependency."""
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        highest_severity = max(vulns, key=lambda v: severity_order.get(v.severity, 2))

        vuln_ids = [v.id for v in vulns]
        vuln_summaries = "\n".join([f"- {v.id}: {v.summary}" for v in vulns[:5]])

        fixed_versions = [v.fixed_version for v in vulns if v.fixed_version]
        fix_recommendation = f"Update to version {fixed_versions[0]}" if fixed_versions else "Update to latest version"

        return AnalyzerResult(
            title=f"Vulnerable Dependency: {dep.name}",
            description=f"The dependency '{dep.name}' version {dep.version or 'unknown'} has known vulnerabilities:\n\n{vuln_summaries}",
            severity=highest_severity.severity,
            category="Vulnerable Dependencies",
            impact=f"Using vulnerable dependencies can expose the application to known exploits. {len(vulns)} vulnerabilities found affecting this component.",
            remediation=f"{fix_recommendation}. Review the vulnerability details and assess the impact on your application.",
            file_path=dep.source_file,
            code_snippet=f'{dep.package_manager} dependency:\n{dep.name}:{dep.version or "unknown"}',
            poc_evidence=f"CVE/Advisory IDs: {', '.join(vuln_ids)}",
            poc_verification=f"1. Check dependency version in {dep.source_file}\n2. Search for {vuln_ids[0]} in vulnerability databases\n3. Verify if affected code paths are used",
            cwe_id="CWE-1395",
            cwe_name="Dependency on Vulnerable Third-Party Component",
            owasp_masvs_category="MASVS-CODE",
            owasp_masvs_control="MSTG-CODE-5",
            cvss_score=8.0 if highest_severity.severity == "critical" else 6.0,
            metadata={
                "dependency_name": dep.name,
                "dependency_version": dep.version,
                "package_manager": dep.package_manager,
                "vulnerability_ids": vuln_ids,
                "fixed_versions": fixed_versions,
            }
        )

    def _create_summary_finding(
        self,
        vulnerable_deps: list[tuple[Dependency, list[VulnerabilityInfo]]],
        app: MobileApp
    ) -> AnalyzerResult:
        """Create a summary finding for all vulnerable dependencies."""
        total_vulns = sum(len(vulns) for _, vulns in vulnerable_deps)
        critical_count = sum(
            1 for _, vulns in vulnerable_deps
            for v in vulns if v.severity == "critical"
        )
        high_count = sum(
            1 for _, vulns in vulnerable_deps
            for v in vulns if v.severity == "high"
        )

        severity = "critical" if critical_count > 0 else "high" if high_count > 0 else "medium"

        dep_list = "\n".join([
            f"- {dep.name}:{dep.version or 'unknown'} ({len(vulns)} vulnerabilities)"
            for dep, vulns in vulnerable_deps[:10]
        ])

        return AnalyzerResult(
            title=f"Multiple Vulnerable Dependencies Detected ({len(vulnerable_deps)} packages)",
            description=f"The application uses {len(vulnerable_deps)} dependencies with known vulnerabilities, totaling {total_vulns} security issues.\n\nAffected packages:\n{dep_list}",
            severity=severity,
            category="Vulnerable Dependencies",
            impact=f"Critical: {critical_count}, High: {high_count}. Using outdated and vulnerable dependencies significantly increases the attack surface.",
            remediation="1. Update all vulnerable dependencies to their latest secure versions\n2. Use dependency scanning in CI/CD pipeline\n3. Enable automated security updates (Dependabot, Renovate)\n4. Review and minimize unnecessary dependencies",
            cwe_id="CWE-1395",
            cwe_name="Dependency on Vulnerable Third-Party Component",
            owasp_masvs_category="MASVS-CODE",
            owasp_masvs_control="MSTG-CODE-5",
            cvss_score=9.0 if critical_count > 0 else 7.0,
            metadata={
                "total_vulnerable_packages": len(vulnerable_deps),
                "total_vulnerabilities": total_vulns,
                "critical_count": critical_count,
                "high_count": high_count,
            }
        )
