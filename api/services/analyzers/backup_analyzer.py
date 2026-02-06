"""Backup configuration analyzer for Android application data extraction risk.

Evaluates the android:allowBackup setting, fullBackupContent rules,
dataExtractionRules (Android 12+), and custom BackupAgent presence
in the AndroidManifest.xml to determine whether application data can
be extracted via ADB backup commands.

Security checks performed:
    - **Unrestricted Backup**: Detects allowBackup=true (or default true)
      without any backup rules, enabling full data extraction via ADB.
    - **Weak Backup Rules**: Validates that fullBackupContent or
      dataExtractionRules adequately exclude SharedPreferences and
      database directories from backups.
    - **Custom Backup Agent**: Notes the presence of a BackupAgent class
      that may control backup behavior programmatically.
    - **Backup Disabled**: Confirms allowBackup=false as a positive
      security control.

OWASP references:
    - MASVS-STORAGE: Data Storage and Privacy
    - MASVS-STORAGE-2: Testing Backups
    - MASTG-TEST-0008: Testing Backups for Sensitive Data
    - CWE-530: Exposure of Backup File to an Unauthorized Control Sphere
"""

import logging
import re
import shutil
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# Android namespace
NS = {"android": "http://schemas.android.com/apk/res/android"}


class BackupAnalyzer(BaseAnalyzer):
    """Analyzes Android backup configuration for data extraction risk.

    Parses AndroidManifest.xml to evaluate allowBackup, fullBackupContent,
    dataExtractionRules, and backupAgent attributes. Validates backup
    rules XML for adequate sensitive data exclusion.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("android").
    """

    name = "backup_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze Android backup configuration for security issues.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering backup enablement,
            rule adequacy, and backup agent configuration.
        """
        if not app.file_path:
            return []

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="backup_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            # Parse AndroidManifest.xml
            manifest_xml = None
            manifest_path = extracted_path / "AndroidManifest.xml"

            if manifest_path.exists():
                try:
                    manifest_xml = manifest_path.read_text(errors='ignore')
                except Exception:
                    pass

            if not manifest_xml:
                try:
                    from androguard.core.axml import AXMLPrinter
                    with zipfile.ZipFile(app.file_path, "r") as apk:
                        manifest_data = apk.read("AndroidManifest.xml")
                        axml = AXMLPrinter(manifest_data)
                        manifest_xml = axml.get_xml()
                except Exception:
                    pass

            if not manifest_xml:
                return findings

            try:
                root = ET.fromstring(manifest_xml)
            except ET.ParseError:
                return findings

            application = root.find("application")
            if application is None:
                return findings

            # Check allowBackup
            allow_backup = application.get(f"{{{NS['android']}}}allowBackup")
            # Check fullBackupContent
            full_backup_content = application.get(f"{{{NS['android']}}}fullBackupContent")
            # Check dataExtractionRules (Android 12+)
            data_extraction_rules = application.get(f"{{{NS['android']}}}dataExtractionRules")
            # Check backupAgent
            backup_agent = application.get(f"{{{NS['android']}}}backupAgent")

            # allowBackup is true by default if not specified
            backup_enabled = allow_backup != "false"

            if backup_enabled and not full_backup_content and not data_extraction_rules and not backup_agent:
                # Worst case: backup enabled with no rules at all
                findings.append(self.create_finding(
                    app=app,
                    title="Application Backup Enabled Without Restrictions",
                    description=(
                        "The application allows full data backup via ADB without any backup rules. "
                        "android:allowBackup is "
                        f"{'not set (defaults to true)' if allow_backup is None else 'set to true'}. "
                        "No fullBackupContent or dataExtractionRules are configured.\n\n"
                        "All application data including SharedPreferences, databases, and internal "
                        "files can be extracted via USB debugging."
                    ),
                    severity="high",
                    category="Data Protection",
                    impact=(
                        "An attacker with physical access or ADB access can extract all application "
                        "data including credentials, tokens, encryption keys, and personal information "
                        "stored in SharedPreferences, SQLite databases, and internal files."
                    ),
                    remediation=(
                        "Option 1: Disable backup entirely:\n"
                        '  android:allowBackup="false"\n\n'
                        "Option 2: Configure selective backup rules:\n"
                        '  android:fullBackupContent="@xml/backup_rules"\n\n'
                        "Option 3 (Android 12+):\n"
                        '  android:dataExtractionRules="@xml/data_extraction_rules"'
                    ),
                    file_path="AndroidManifest.xml",
                    code_snippet=f'android:allowBackup="{allow_backup if allow_backup else "true (default)"}"',
                    cwe_id="CWE-530",
                    cwe_name="Exposure of Backup File to an Unauthorized Control Sphere",
                    cvss_score=7.1,
                    cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MASVS-STORAGE-2",
                    owasp_mastg_test="MASTG-TEST-0008",
                    poc_commands=[
                        {
                            "type": "adb",
                            "command": f"adb backup -f backup.ab -apk {app.package_name}",
                            "description": "Create backup of application data",
                        },
                        {
                            "type": "bash",
                            "command": (
                                "dd if=backup.ab bs=24 skip=1 | "
                                "python3 -c \"import zlib,sys;sys.stdout.buffer.write("
                                "zlib.decompress(sys.stdin.buffer.read()))\" > backup.tar"
                            ),
                            "description": "Extract the backup archive",
                        },
                        {
                            "type": "bash",
                            "command": "tar -xf backup.tar && find apps -type f",
                            "description": "List all backed up files",
                        },
                    ],
                    remediation_code={
                        "xml": (
                            '<!-- Option 1: Disable backup -->\n'
                            '<application\n'
                            '    android:allowBackup="false">\n\n'
                            '<!-- Option 2: Selective backup (API < 31) -->\n'
                            '<application\n'
                            '    android:allowBackup="true"\n'
                            '    android:fullBackupContent="@xml/backup_rules">\n\n'
                            '<!-- Option 3: Android 12+ -->\n'
                            '<application\n'
                            '    android:allowBackup="true"\n'
                            '    android:dataExtractionRules="@xml/data_extraction_rules">'
                        ),
                        "xml-backup-rules": (
                            '<?xml version="1.0" encoding="utf-8"?>\n'
                            '<full-backup-content>\n'
                            '    <exclude domain="sharedpref" path="." />\n'
                            '    <exclude domain="database" path="." />\n'
                            '    <exclude domain="file" path="sensitive_data/" />\n'
                            '</full-backup-content>'
                        ),
                    },
                    remediation_resources=[
                        {
                            "title": "OWASP MASTG - Testing Backups for Sensitive Data",
                            "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-STORAGE/MASTG-TEST-0008/",
                            "type": "documentation",
                        },
                        {
                            "title": "Android - Back up user data",
                            "url": "https://developer.android.com/guide/topics/data/backup",
                            "type": "documentation",
                        },
                    ],
                ))

            elif backup_enabled and (full_backup_content or data_extraction_rules):
                # Backup enabled with rules -- check if rules are restrictive enough
                rules_adequate = await self._check_backup_rules(
                    extracted_path, full_backup_content, data_extraction_rules
                )

                if not rules_adequate:
                    findings.append(self.create_finding(
                        app=app,
                        title="Weak Backup Rules Configured",
                        description=(
                            "The application has backup rules configured but they may not "
                            "adequately protect sensitive data. SharedPreferences and databases "
                            "should be explicitly excluded from backups."
                        ),
                        severity="medium",
                        category="Data Protection",
                        impact=(
                            "Sensitive data stored in SharedPreferences or databases may still "
                            "be included in backups, exposing it to extraction."
                        ),
                        remediation=(
                            "Review backup rules to ensure all sensitive data storage locations "
                            "are excluded:\n"
                            "- SharedPreferences containing tokens/credentials\n"
                            "- Databases with user data\n"
                            "- Files containing encryption keys"
                        ),
                        file_path="AndroidManifest.xml",
                        cwe_id="CWE-530",
                        cwe_name="Exposure of Backup File to an Unauthorized Control Sphere",
                        cvss_score=5.3,
                        cvss_vector="CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                        owasp_masvs_category="MASVS-STORAGE",
                        owasp_masvs_control="MASVS-STORAGE-2",
                    ))
                else:
                    findings.append(self.create_finding(
                        app=app,
                        title="Backup Rules Configured",
                        description=(
                            "The application has backup rules that appear to exclude sensitive data. "
                            "Verify that all sensitive storage locations are properly excluded."
                        ),
                        severity="info",
                        category="Data Protection",
                        impact="Properly configured backup rules protect sensitive data from extraction.",
                        remediation="Periodically review backup rules when adding new data storage.",
                        owasp_masvs_category="MASVS-STORAGE",
                        owasp_masvs_control="MASVS-STORAGE-2",
                    ))

            elif backup_enabled and backup_agent:
                # Custom backup agent -- informational
                findings.append(self.create_finding(
                    app=app,
                    title="Custom Backup Agent Configured",
                    description=(
                        f"The application uses a custom BackupAgent: {backup_agent}. "
                        "Verify that the agent properly excludes sensitive data from backups."
                    ),
                    severity="low",
                    category="Data Protection",
                    impact="Custom backup agents control what data is backed up. Improper implementation may leak data.",
                    remediation="Review the BackupAgent implementation to ensure sensitive data is excluded.",
                    file_path="AndroidManifest.xml",
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MASVS-STORAGE-2",
                ))

            else:
                # Backup disabled
                findings.append(self.create_finding(
                    app=app,
                    title="Application Backup Disabled",
                    description='android:allowBackup is set to "false". Application data cannot be extracted via ADB backup.',
                    severity="info",
                    category="Data Protection",
                    impact="Backup data extraction is prevented.",
                    remediation="No action needed.",
                    owasp_masvs_category="MASVS-STORAGE",
                    owasp_masvs_control="MASVS-STORAGE-2",
                ))

            return findings

        except Exception as e:
            logger.error(f"Backup analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    async def _check_backup_rules(
        self,
        extracted_path: Path,
        full_backup_content: str | None,
        data_extraction_rules: str | None,
    ) -> bool:
        """Check if backup rules adequately exclude sensitive data.

        Locates the backup rules XML resource file and verifies that
        SharedPreferences and database domains are excluded, or that
        include-only mode is used.

        Args:
            extracted_path: Root directory of the extracted APK.
            full_backup_content: Value of android:fullBackupContent
                attribute (e.g., "@xml/backup_rules"), or None.
            data_extraction_rules: Value of android:dataExtractionRules
                attribute (Android 12+), or None.

        Returns:
            True if the rules adequately protect sensitive data.
        """
        rules_content = None

        # Try to find the rules XML file
        for rules_ref in [full_backup_content, data_extraction_rules]:
            if not rules_ref:
                continue

            # Extract resource name from @xml/name
            match = re.search(r'@xml/(\w+)', rules_ref)
            if match:
                rules_name = match.group(1)
                for xml_file in extracted_path.rglob(f"{rules_name}.xml"):
                    try:
                        rules_content = xml_file.read_text(errors='ignore')
                        break
                    except Exception:
                        pass

        if not rules_content:
            return False

        # Check if rules exclude sensitive directories
        excludes_prefs = bool(re.search(r'exclude.*domain.*sharedpref', rules_content, re.IGNORECASE))
        excludes_db = bool(re.search(r'exclude.*domain.*database', rules_content, re.IGNORECASE))

        # Also check for include-only mode (more restrictive)
        is_include_only = bool(re.search(r'<include\b', rules_content))

        return excludes_prefs or excludes_db or is_include_only
