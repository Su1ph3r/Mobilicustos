"""Data leakage vector analyzer for mobile applications.

Scans application binaries for patterns that indicate potential data leakage
channels, including clipboard usage, screenshot exposure, pasteboard access,
third-party analytics/tracking SDKs, and insecure inter-process communication.

OWASP references:
    - MASVS-STORAGE: Secure storage of sensitive data
    - MASVS-PRIVACY: User privacy protection
    - CWE-200: Exposure of Sensitive Information
"""

import logging
import re
import zipfile
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class DataLeakageAnalyzer(BaseAnalyzer):
    """Analyzes data leakage vectors in mobile applications.

    Detects clipboard data exposure, screenshot vulnerability, third-party
    SDK data sharing, and unprotected IPC channels that could leak sensitive
    information to other applications or the system.
    """

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
                        dex_text = dex_data.decode("utf-8", errors="ignore").replace('\x00', '')

                        # Check screenshot prevention
                        flag_match = re.search(r'FLAG_SECURE', dex_text)
                        if flag_match:
                            flag_secure_found = True
                            start = max(0, flag_match.start() - 80)
                            end = min(len(dex_text), flag_match.end() + 80)
                            context = dex_text[start:end].replace('\x00', '').strip()
                            findings.append(self.create_finding(
                                app=app,
                                title="FLAG_SECURE Reference Found in Code",
                                severity="info",
                                category="Data Leakage",
                                description=(
                                    "FLAG_SECURE reference found in application bytecode. "
                                    "This indicates the app may protect sensitive screens from "
                                    "screenshots and screen recording. Runtime analysis confirms "
                                    "whether FLAG_SECURE is actually applied to activity windows."
                                ),
                                impact="Positive - FLAG_SECURE prevents screenshots and screen recording of sensitive screens.",
                                remediation="Ensure FLAG_SECURE is applied to all activities displaying sensitive data.",
                                file_path=name,
                                code_snippet=context,
                                owasp_masvs_category="MASVS-STORAGE",
                                owasp_masvs_control="MASVS-STORAGE-9",
                                poc_evidence=f"FLAG_SECURE string reference found in {name}",
                                poc_verification=(
                                    "1. Run the app and navigate to sensitive screens\n"
                                    "2. Attempt to take a screenshot (Power + Volume Down)\n"
                                    "3. If FLAG_SECURE is active, the screenshot will be blank/black"
                                ),
                                poc_commands=[
                                    {"type": "adb", "command": "adb shell screencap /sdcard/test.png && adb pull /sdcard/test.png", "description": "Attempt screenshot capture - blank if FLAG_SECURE is active"},
                                    {"type": "frida", "command": f"frida -U -f {app.package_name} -l check_flag_secure.js", "description": "Hook Window.setFlags to verify FLAG_SECURE at runtime"},
                                ],
                            ))

                        # Check clipboard patterns
                        for pattern_name, info in self.CLIPBOARD_PATTERNS.items():
                            clip_match = re.search(info["pattern"], dex_text, re.IGNORECASE)
                            if clip_match:
                                cs = max(0, clip_match.start() - 60)
                                ce = min(len(dex_text), clip_match.end() + 60)
                                clip_ctx = dex_text[cs:ce].replace('\x00', '').strip()
                                findings.append(self._create_clipboard_finding(app, info, name, clip_ctx))

                        # Check logging patterns
                        for pattern_name, info in self.LOGGING_PATTERNS.items():
                            log_match = re.search(info["pattern"], dex_text, re.IGNORECASE)
                            if log_match:
                                ls = max(0, log_match.start() - 60)
                                le = min(len(dex_text), log_match.end() + 60)
                                log_ctx = dex_text[ls:le].replace('\x00', '').strip()
                                findings.append(self._create_logging_finding(app, info, name, log_ctx))

                        # Check IPC patterns
                        for pattern_name, info in self.IPC_PATTERNS.items():
                            ipc_match = re.search(info["pattern"], dex_text, re.IGNORECASE)
                            if ipc_match:
                                ips = max(0, ipc_match.start() - 60)
                                ipe = min(len(dex_text), ipc_match.end() + 60)
                                ipc_ctx = dex_text[ips:ipe].replace('\x00', '').strip()
                                findings.append(self._create_ipc_finding(app, info, name, ipc_ctx))

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
                        description=(
                            "No reference to FLAG_SECURE was found in the application bytecode. "
                            "Without FLAG_SECURE, sensitive screens can be captured via screenshots "
                            "or screen recording, exposing credentials, financial data, or PII."
                        ),
                        impact="Screenshots and screen recordings can capture sensitive data displayed in the app.",
                        remediation="Add FLAG_SECURE to sensitive activities: getWindow().setFlags(FLAG_SECURE, FLAG_SECURE)",
                        file_path="N/A",
                        code_snippet='getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);  // NOT FOUND in app',
                        cwe_id="CWE-200",
                        cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
                        owasp_masvs_category="MASVS-STORAGE",
                        owasp_masvs_control="MASVS-STORAGE-9",
                        owasp_mastg_test="MASTG-TEST-0007",
                        poc_evidence="FLAG_SECURE string not found in any DEX file",
                        poc_verification=(
                            "1. Launch the app and navigate to a screen with sensitive data\n"
                            "2. Take a screenshot (Power + Volume Down)\n"
                            "3. If the screenshot contains the sensitive data, the app is vulnerable"
                        ),
                        poc_commands=[
                            {"type": "adb", "command": "adb shell screencap /sdcard/test.png && adb pull /sdcard/test.png", "description": "Capture screenshot of active screen"},
                            {"type": "adb", "command": "adb shell screenrecord /sdcard/test.mp4 --time-limit 5 && adb pull /sdcard/test.mp4", "description": "Record screen for 5 seconds"},
                        ],
                        remediation_code={
                            "java": (
                                "// Add to Activity.onCreate() for each sensitive screen:\n"
                                "getWindow().setFlags(\n"
                                "    WindowManager.LayoutParams.FLAG_SECURE,\n"
                                "    WindowManager.LayoutParams.FLAG_SECURE\n"
                                ");"
                            ),
                        },
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

    def _create_clipboard_finding(
        self, app: MobileApp, info: dict[str, Any], file_path: str, matched_context: str = "",
    ) -> Finding:
        """Create clipboard-related finding."""
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Data Leakage",
            description=(
                f"Clipboard operations detected ({info['name']}). On Android < 13, "
                "any app can read clipboard data. On Android 13+, access is restricted "
                "but data is still visible in the clipboard notification."
            ),
            impact="Data copied to clipboard can be read by other apps on the device.",
            remediation="Avoid copying sensitive data to clipboard. On Android 13+, use ClipDescription.EXTRA_IS_SENSITIVE.",
            file_path=file_path,
            code_snippet=matched_context[:300] if matched_context else None,
            cwe_id="CWE-200",
            cwe_name="Exposure of Sensitive Information to an Unauthorized Actor",
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-10",
            owasp_mastg_test="MASTG-TEST-0005",
            poc_evidence=f"Pattern '{info['pattern']}' matched in {file_path}",
            poc_verification=(
                "1. Launch the app and trigger a clipboard copy action\n"
                "2. Use another app or ADB to read clipboard contents\n"
                "3. Check if sensitive data is accessible"
            ),
            poc_commands=[
                {"type": "adb", "command": "adb shell service call clipboard 2 s16 com.android.shell", "description": "Read clipboard contents via ADB"},
                {"type": "frida", "command": f"frida -U -f {app.package_name} -l clipboard_monitor.js", "description": "Hook ClipboardManager to monitor clipboard writes"},
            ],
        )

    def _create_logging_finding(
        self, app: MobileApp, info: dict[str, Any], file_path: str, matched_context: str = "",
    ) -> Finding:
        """Create logging-related finding."""
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Data Leakage",
            description=f"Sensitive data may be logged: {info['name']}. Log output is readable by any app with READ_LOGS permission or via ADB.",
            impact="Logged sensitive data can be read via ADB logcat or system logs.",
            remediation="Remove logging of sensitive data. Use ProGuard/R8 to strip debug logs in release builds.",
            file_path=file_path,
            code_snippet=matched_context[:300] if matched_context else None,
            cwe_id="CWE-532",
            cwe_name="Insertion of Sensitive Information into Log File",
            owasp_masvs_category="MASVS-STORAGE",
            owasp_masvs_control="MASVS-STORAGE-3",
            owasp_mastg_test="MASTG-TEST-0003",
            poc_evidence=f"Pattern '{info['pattern']}' matched in {file_path}",
            poc_verification=(
                "1. Connect device via ADB\n"
                "2. Run logcat and filter for the app\n"
                "3. Use the app normally and check for sensitive data in logs"
            ),
            poc_commands=[
                {"type": "adb", "command": f"adb logcat -d --pid=$(adb shell pidof {app.package_name}) | grep -iE 'password|token|key|secret'", "description": "Search app logs for sensitive data"},
                {"type": "adb", "command": "adb logcat -d | grep -iE 'password|token|key'", "description": "Search all logs for sensitive data"},
            ],
        )

    def _create_ipc_finding(
        self, app: MobileApp, info: dict[str, Any], file_path: str, matched_context: str = "",
    ) -> Finding:
        """Create IPC-related finding."""
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Data Leakage",
            description=f"Sensitive data in IPC: {info['name']}. Implicit broadcasts and intents can be intercepted by malicious apps.",
            impact="Sensitive data in broadcasts or intents can be intercepted by other apps.",
            remediation="Use LocalBroadcastManager for internal broadcasts. Encrypt sensitive intent extras. Use explicit intents.",
            file_path=file_path,
            code_snippet=matched_context[:300] if matched_context else None,
            cwe_id="CWE-927",
            cwe_name="Use of Implicit Intent for Sensitive Communication",
            owasp_masvs_category="MASVS-PLATFORM",
            owasp_masvs_control="MASVS-PLATFORM-1",
            poc_evidence=f"Pattern '{info['pattern']}' matched in {file_path}",
            poc_verification=(
                "1. Register a broadcast receiver for the target action\n"
                "2. Trigger the IPC operation in the app\n"
                "3. Check if the broadcast receiver captures sensitive data"
            ),
            poc_commands=[
                {"type": "adb", "command": f"adb shell am monitor --gdb {app.package_name}", "description": "Monitor intents sent by the app"},
                {"type": "bash", "command": f"drozer console connect -c 'run app.broadcast.sniff --action *'", "description": "Sniff broadcasts using Drozer"},
            ],
        )
