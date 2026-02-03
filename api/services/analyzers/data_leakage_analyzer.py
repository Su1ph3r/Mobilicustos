"""Data leakage analyzer for mobile applications."""

import logging
import re
import zipfile
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class DataLeakageAnalyzer(BaseAnalyzer):
    """Analyzes data leakage vectors in mobile applications."""

    name = "data_leakage_analyzer"
    platform = "cross-platform"

    # Clipboard patterns
    CLIPBOARD_PATTERNS = {
        "android_clipboard": {
            "pattern": r'ClipboardManager|setPrimaryClip|getPrimaryClip',
            "name": "Clipboard Usage Detected",
            "severity": "info",
        },
        "ios_clipboard": {
            "pattern": r'UIPasteboard|generalPasteboard',
            "name": "Clipboard Usage Detected",
            "severity": "info",
        },
        "sensitive_clipboard": {
            "pattern": r'clipboard.*password|clipboard.*token|clipboard.*credit',
            "name": "Sensitive Data to Clipboard",
            "severity": "high",
        },
    }

    # Screenshot/Screen recording patterns
    SCREENSHOT_PATTERNS = {
        "no_screenshot_prevention": {
            "pattern": r'FLAG_SECURE',
            "name": "Screenshot Prevention",
            "severity": "info",
            "positive": True,
        },
        "ios_screenshot_notification": {
            "pattern": r'userDidTakeScreenshotNotification|screenshotNotification',
            "name": "Screenshot Detection",
            "severity": "info",
            "positive": True,
        },
    }

    # Keyboard cache patterns
    KEYBOARD_PATTERNS = {
        "android_no_suggestions": {
            "pattern": r'TYPE_TEXT_FLAG_NO_SUGGESTIONS|InputType\.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD',
            "name": "Keyboard Suggestions Disabled",
            "severity": "info",
            "positive": True,
        },
        "ios_secure_text": {
            "pattern": r'secureTextEntry\s*=\s*true|isSecureTextEntry',
            "name": "Secure Text Entry",
            "severity": "info",
            "positive": True,
        },
        "ios_autocorrect": {
            "pattern": r'autocorrectionType\s*=\s*\.no|UITextAutocorrectionTypeNo',
            "name": "Autocorrection Disabled",
            "severity": "info",
            "positive": True,
        },
    }

    # Backup leakage patterns
    BACKUP_PATTERNS = {
        "exclude_from_backup": {
            "pattern": r'NSURLIsExcludedFromBackupKey|setExcludedFromBackup',
            "name": "Backup Exclusion Configured",
            "severity": "info",
            "positive": True,
        },
        "sensitive_in_documents": {
            "pattern": r'Documents.*password|Documents.*token|Documents.*key',
            "name": "Sensitive Data in Documents",
            "severity": "medium",
        },
    }

    # Logging patterns
    LOGGING_PATTERNS = {
        "sensitive_log": {
            "pattern": r'Log\.(d|v|i|w|e)\([^)]*password|NSLog\([^)]*password',
            "name": "Password in Logs",
            "severity": "high",
        },
        "token_log": {
            "pattern": r'Log\.(d|v|i|w|e)\([^)]*token|NSLog\([^)]*token',
            "name": "Token in Logs",
            "severity": "high",
        },
        "key_log": {
            "pattern": r'Log\.(d|v|i|w|e)\([^)]*key|NSLog\([^)]*key',
            "name": "Key in Logs",
            "severity": "high",
        },
        "credit_card_log": {
            "pattern": r'Log\.(d|v|i|w|e)\([^)]*card|NSLog\([^)]*card|Log\.(d|v|i|w|e)\([^)]*cvv',
            "name": "Credit Card in Logs",
            "severity": "critical",
        },
    }

    # IPC leakage patterns
    IPC_PATTERNS = {
        "broadcast_sensitive": {
            "pattern": r'sendBroadcast\([^)]*password|sendBroadcast\([^)]*token',
            "name": "Sensitive Data in Broadcast",
            "severity": "high",
        },
        "intent_sensitive": {
            "pattern": r'putExtra\([^)]*password|putExtra\([^)]*token',
            "name": "Sensitive Data in Intent",
            "severity": "medium",
        },
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze data leakage vectors."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            if app.platform == "android":
                findings.extend(await self._analyze_android(app))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios(app))
        except Exception as e:
            logger.error(f"Data leakage analysis failed: {e}")

        return findings

    async def _analyze_android(self, app: MobileApp) -> list[Finding]:
        """Analyze Android app for data leakage."""
        findings: list[Finding] = []
        flag_secure_found = False

        try:
            with zipfile.ZipFile(app.file_path, "r") as apk:
                for name in apk.namelist():
                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        dex_text = dex_data.decode("utf-8", errors="ignore")

                        # Check screenshot prevention
                        if re.search(r'FLAG_SECURE', dex_text):
                            flag_secure_found = True
                            findings.append(self.create_finding(
                                app=app,
                                title="Screenshot Prevention Implemented",
                                severity="info",
                                category="Data Leakage",
                                description="FLAG_SECURE is used to prevent screenshots.",
                                impact="Positive - sensitive screens are protected from screenshots.",
                                remediation="Ensure FLAG_SECURE is applied to all sensitive activities.",
                                file_path=name,
                                owasp_masvs_category="MASVS-STORAGE",
                            ))

                        # Check clipboard patterns
                        for pattern_name, info in self.CLIPBOARD_PATTERNS.items():
                            if re.search(info["pattern"], dex_text, re.IGNORECASE):
                                findings.append(self._create_clipboard_finding(app, info, name))

                        # Check logging patterns
                        for pattern_name, info in self.LOGGING_PATTERNS.items():
                            if re.search(info["pattern"], dex_text, re.IGNORECASE):
                                findings.append(self._create_logging_finding(app, info, name))

                        # Check IPC patterns
                        for pattern_name, info in self.IPC_PATTERNS.items():
                            if re.search(info["pattern"], dex_text, re.IGNORECASE):
                                findings.append(self._create_ipc_finding(app, info, name))

                        # Check keyboard patterns
                        for pattern_name, info in self.KEYBOARD_PATTERNS.items():
                            if "android" in pattern_name and re.search(info["pattern"], dex_text):
                                findings.append(self.create_finding(
                                    app=app,
                                    title=info["name"],
                                    severity="info",
                                    category="Data Leakage",
                                    description="Keyboard security control detected.",
                                    impact="Positive - keyboard caching is limited.",
                                    remediation="Ensure applied to all sensitive input fields.",
                                    file_path=name,
                                    owasp_masvs_category="MASVS-STORAGE",
                                ))

                # Check if screenshot prevention is missing
                if not flag_secure_found:
                    findings.append(self.create_finding(
                        app=app,
                        title="Screenshot Prevention Not Detected",
                        severity="medium",
                        category="Data Leakage",
                        description="FLAG_SECURE not detected. Sensitive screens may be captured.",
                        impact="Screenshots and screen recordings can capture sensitive data.",
                        remediation="Add FLAG_SECURE to sensitive activities: getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)",
                        file_path="N/A",
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                        owasp_masvs_category="MASVS-STORAGE",
                        owasp_masvs_control="MASVS-STORAGE-9",
                        owasp_mastg_test="MASTG-TEST-0007",
                    ))

        except Exception as e:
            logger.error(f"Android data leakage analysis failed: {e}")

        return findings

    async def _analyze_ios(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS app for data leakage."""
        findings: list[Finding] = []
        secure_text_found = False

        try:
            with zipfile.ZipFile(app.file_path, "r") as ipa:
                for name in ipa.namelist():
                    if "/Payload/" in name:
                        try:
                            file_data = ipa.read(name)
                            file_text = file_data.decode("utf-8", errors="ignore")

                            # Check clipboard patterns
                            for pattern_name, info in self.CLIPBOARD_PATTERNS.items():
                                if "ios" in pattern_name and re.search(info["pattern"], file_text, re.IGNORECASE):
                                    findings.append(self._create_clipboard_finding(app, info, name))

                            # Check logging patterns
                            for pattern_name, info in self.LOGGING_PATTERNS.items():
                                if re.search(info["pattern"], file_text, re.IGNORECASE):
                                    findings.append(self._create_logging_finding(app, info, name))

                            # Check keyboard patterns
                            for pattern_name, info in self.KEYBOARD_PATTERNS.items():
                                if "ios" in pattern_name and re.search(info["pattern"], file_text):
                                    secure_text_found = True
                                    findings.append(self.create_finding(
                                        app=app,
                                        title=info["name"],
                                        severity="info",
                                        category="Data Leakage",
                                        description="Keyboard security control detected.",
                                        impact="Positive - keyboard caching limited for sensitive fields.",
                                        remediation="Ensure applied to all sensitive input fields.",
                                        file_path=name,
                                        owasp_masvs_category="MASVS-STORAGE",
                                    ))

                            # Check backup exclusion
                            for pattern_name, info in self.BACKUP_PATTERNS.items():
                                if re.search(info["pattern"], file_text):
                                    if info.get("positive", False):
                                        findings.append(self.create_finding(
                                            app=app,
                                            title=info["name"],
                                            severity="info",
                                            category="Data Leakage",
                                            description="Backup exclusion configured for sensitive files.",
                                            impact="Positive - sensitive data excluded from backups.",
                                            remediation="Verify all sensitive files are excluded.",
                                            file_path=name,
                                            owasp_masvs_category="MASVS-STORAGE",
                                        ))

                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"iOS data leakage analysis failed: {e}")

        return findings

    def _create_clipboard_finding(self, app: MobileApp, info: dict[str, Any], file_path: str) -> Finding:
        """Create clipboard-related finding."""
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Data Leakage",
            description="Clipboard operations detected. Clipboard data can be accessed by other apps.",
            impact="Data copied to clipboard can be read by other apps on the device.",
            remediation="Avoid copying sensitive data to clipboard. On Android 13+, use FLAG_SENSITIVE.",
            file_path=file_path,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-10",
            owasp_mastg_test="MASTG-TEST-0005",
        )

    def _create_logging_finding(self, app: MobileApp, info: dict[str, Any], file_path: str) -> Finding:
        """Create logging-related finding."""
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Data Leakage",
            description=f"Sensitive data may be logged: {info['name']}",
            impact="Logged sensitive data can be read via ADB logcat or system logs.",
            remediation="Remove logging of sensitive data. Use ProGuard to strip debug logs in release builds.",
            file_path=file_path,
            cwe_id="CWE-532",
            cwe_name="Insertion of Sensitive Information into Log File",
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-3",
            owasp_mastg_test="MASTG-TEST-0003",
            poc_commands=[
                {"type": "adb", "command": "adb logcat -d | grep -iE 'password|token|key'", "description": "Search logs for sensitive data"},
            ],
        )

    def _create_ipc_finding(self, app: MobileApp, info: dict[str, Any], file_path: str) -> Finding:
        """Create IPC-related finding."""
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Data Leakage",
            description=f"Sensitive data in IPC: {info['name']}",
            impact="Sensitive data in broadcasts or intents can be intercepted by other apps.",
            remediation="Use LocalBroadcastManager for internal broadcasts. Encrypt sensitive intent extras.",
            file_path=file_path,
            cwe_id="CWE-927",
            cwe_name="Use of Implicit Intent for Sensitive Communication",
            owasp_masvs_category="MASVS-PLATFORM",
            owasp_masvs_control="MASVS-PLATFORM-1",
        )
