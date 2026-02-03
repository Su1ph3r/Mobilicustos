"""Authentication implementation analyzer."""

import logging
import re
import zipfile
from typing import Any

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)


class AuthenticationAnalyzer(BaseAnalyzer):
    """Analyzes authentication implementation patterns."""

    name = "authentication_analyzer"
    platform = "cross-platform"

    # Android authentication patterns
    ANDROID_AUTH_PATTERNS = {
        "biometric": {
            "pattern": r'BiometricPrompt|FingerprintManager|BiometricManager',
            "name": "Biometric Authentication",
            "severity": "info",
            "positive": True,
        },
        "keystore_auth": {
            "pattern": r'setUserAuthenticationRequired\(true\)',
            "name": "Keystore Authentication Required",
            "severity": "info",
            "positive": True,
        },
        "shared_prefs_password": {
            "pattern": r'SharedPreferences.*password|putString.*password|getString.*password',
            "name": "Password in SharedPreferences",
            "severity": "high",
            "positive": False,
        },
        "hardcoded_password": {
            "pattern": r'password\s*=\s*["\'][^"\']{8,}["\']|PASSWORD\s*=\s*["\'][^"\']{8,}["\']',
            "name": "Hardcoded Password",
            "severity": "critical",
            "positive": False,
        },
        "weak_pin_check": {
            "pattern": r'\.equals\(["\']1234["\']|\.equals\(["\']0000["\']|\.equals\(["\']1111["\']',
            "name": "Weak PIN Check",
            "severity": "high",
            "positive": False,
        },
    }

    # iOS authentication patterns
    IOS_AUTH_PATTERNS = {
        "local_auth": {
            "pattern": r'LAContext|canEvaluatePolicy|evaluatePolicy',
            "name": "Local Authentication (Face ID/Touch ID)",
            "severity": "info",
            "positive": True,
        },
        "keychain_auth": {
            "pattern": r'kSecAccessControlBiometryAny|kSecAccessControlUserPresence',
            "name": "Keychain Biometric Protection",
            "severity": "info",
            "positive": True,
        },
        "userdefaults_password": {
            "pattern": r'UserDefaults.*password|standardUserDefaults.*password',
            "name": "Password in UserDefaults",
            "severity": "high",
            "positive": False,
        },
    }

    # Token handling patterns
    TOKEN_PATTERNS = {
        "token_in_logs": {
            "pattern": r'Log\.(d|v|i|w|e)\([^)]*token|NSLog\([^)]*token',
            "name": "Token Logged",
            "severity": "high",
            "positive": False,
        },
        "token_in_url": {
            "pattern": r'[?&]token=|[?&]access_token=|[?&]api_key=',
            "name": "Token in URL Parameter",
            "severity": "medium",
            "positive": False,
        },
        "jwt_decode": {
            "pattern": r'JWTDecode|jwt-decode|JsonWebToken|decode.*jwt',
            "name": "JWT Token Handling",
            "severity": "info",
            "positive": True,
        },
    }

    # Session management patterns
    SESSION_PATTERNS = {
        "no_session_timeout": {
            "pattern": r'setSessionTimeout\(0\)|sessionTimeout\s*=\s*0',
            "name": "No Session Timeout",
            "severity": "medium",
            "positive": False,
        },
        "remember_me_insecure": {
            "pattern": r'rememberMe.*SharedPreferences|rememberMe.*UserDefaults',
            "name": "Insecure Remember Me",
            "severity": "medium",
            "positive": False,
        },
    }

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze authentication implementation."""
        findings: list[Finding] = []

        if not app.file_path:
            return findings

        try:
            if app.platform == "android":
                findings.extend(await self._analyze_android(app))
            elif app.platform == "ios":
                findings.extend(await self._analyze_ios(app))
        except Exception as e:
            logger.error(f"Authentication analysis failed: {e}")

        return findings

    async def _analyze_android(self, app: MobileApp) -> list[Finding]:
        """Analyze Android authentication patterns."""
        findings: list[Finding] = []
        biometric_found = False

        try:
            with zipfile.ZipFile(app.file_path, "r") as apk:
                for name in apk.namelist():
                    if name.endswith(".dex"):
                        dex_data = apk.read(name)
                        dex_text = dex_data.decode("utf-8", errors="ignore")

                        # Check Android-specific patterns
                        for pattern_name, info in self.ANDROID_AUTH_PATTERNS.items():
                            if re.search(info["pattern"], dex_text, re.IGNORECASE):
                                if info["positive"]:
                                    if "biometric" in pattern_name.lower():
                                        biometric_found = True
                                    findings.append(self._create_positive_finding(app, info, name))
                                else:
                                    findings.append(self._create_negative_finding(app, info, name))

                        # Check token patterns
                        for pattern_name, info in self.TOKEN_PATTERNS.items():
                            if re.search(info["pattern"], dex_text, re.IGNORECASE):
                                if not info["positive"]:
                                    findings.append(self._create_negative_finding(app, info, name))

                        # Check session patterns
                        for pattern_name, info in self.SESSION_PATTERNS.items():
                            if re.search(info["pattern"], dex_text, re.IGNORECASE):
                                if not info["positive"]:
                                    findings.append(self._create_negative_finding(app, info, name))

                # Check if biometric auth is missing
                if not biometric_found:
                    findings.append(self.create_finding(
                        app=app,
                        title="Biometric Authentication Not Detected",
                        severity="info",
                        category="Authentication",
                        description="No biometric authentication implementation detected.",
                        impact="Users cannot use fingerprint or face unlock for app security.",
                        remediation="Consider implementing BiometricPrompt for sensitive operations.",
                        file_path="N/A",
                        owasp_masvs_category="MASVS-AUTH",
                        owasp_masvs_control="MASVS-AUTH-2",
                    ))

        except Exception as e:
            logger.error(f"Android auth analysis failed: {e}")

        return findings

    async def _analyze_ios(self, app: MobileApp) -> list[Finding]:
        """Analyze iOS authentication patterns."""
        findings: list[Finding] = []
        local_auth_found = False

        try:
            with zipfile.ZipFile(app.file_path, "r") as ipa:
                for name in ipa.namelist():
                    if "/Payload/" in name:
                        try:
                            file_data = ipa.read(name)
                            file_text = file_data.decode("utf-8", errors="ignore")

                            # Check iOS-specific patterns
                            for pattern_name, info in self.IOS_AUTH_PATTERNS.items():
                                if re.search(info["pattern"], file_text, re.IGNORECASE):
                                    if info["positive"]:
                                        if "local_auth" in pattern_name:
                                            local_auth_found = True
                                        findings.append(self._create_positive_finding(app, info, name))
                                    else:
                                        findings.append(self._create_negative_finding(app, info, name))

                            # Check token patterns
                            for pattern_name, info in self.TOKEN_PATTERNS.items():
                                if re.search(info["pattern"], file_text, re.IGNORECASE):
                                    if not info["positive"]:
                                        findings.append(self._create_negative_finding(app, info, name))

                        except Exception:
                            continue

        except Exception as e:
            logger.error(f"iOS auth analysis failed: {e}")

        return findings

    def _create_positive_finding(self, app: MobileApp, info: dict[str, Any], file_path: str) -> Finding:
        """Create a positive security finding."""
        return self.create_finding(
            app=app,
            title=f"Security Control Detected: {info['name']}",
            severity=info["severity"],
            category="Authentication",
            description=f"Positive finding: {info['name']} implementation detected.",
            impact="This is a positive security control.",
            remediation="Ensure the implementation follows best practices.",
            file_path=file_path,
            owasp_masvs_category="MASVS-AUTH",
        )

    def _create_negative_finding(self, app: MobileApp, info: dict[str, Any], file_path: str) -> Finding:
        """Create a security issue finding."""
        remediation = self._get_remediation(info["name"])
        return self.create_finding(
            app=app,
            title=info["name"],
            severity=info["severity"],
            category="Authentication",
            description=f"Security issue detected: {info['name']}",
            impact=self._get_impact(info["name"]),
            remediation=remediation,
            file_path=file_path,
            cwe_id=self._get_cwe_id(info["name"]),
            cwe_name=self._get_cwe_name(info["name"]),
            owasp_masvs_category="MASVS-AUTH",
            owasp_masvs_control="MASVS-AUTH-1",
            poc_commands=self._get_poc_commands(info["name"], app),
        )

    def _get_impact(self, finding_name: str) -> str:
        """Get impact description."""
        impacts = {
            "Password in SharedPreferences": "Passwords stored in SharedPreferences can be extracted from backups or rooted devices.",
            "Password in UserDefaults": "Passwords stored in UserDefaults are easily accessible on jailbroken devices.",
            "Hardcoded Password": "Hardcoded passwords can be extracted through reverse engineering.",
            "Weak PIN Check": "Weak PIN checks allow attackers to guess credentials easily.",
            "Token Logged": "Tokens logged can be read via ADB logcat, exposing user sessions.",
            "Token in URL Parameter": "Tokens in URLs can be leaked through browser history, server logs, and referrer headers.",
            "No Session Timeout": "Sessions without timeout remain valid indefinitely if compromised.",
            "Insecure Remember Me": "Remember-me tokens stored insecurely can be stolen.",
        }
        return impacts.get(finding_name, "This issue can compromise authentication security.")

    def _get_remediation(self, finding_name: str) -> str:
        """Get remediation guidance."""
        remediations = {
            "Password in SharedPreferences": "Use EncryptedSharedPreferences or Android Keystore.",
            "Password in UserDefaults": "Use Keychain Services with proper accessibility settings.",
            "Hardcoded Password": "Remove hardcoded passwords. Use secure input and storage.",
            "Weak PIN Check": "Implement secure PIN validation with lockout after failed attempts.",
            "Token Logged": "Remove token logging. Use ProGuard to strip debug logs.",
            "Token in URL Parameter": "Send tokens in Authorization header or POST body.",
            "No Session Timeout": "Implement appropriate session timeout (15-30 minutes for sensitive apps).",
            "Insecure Remember Me": "Store remember-me tokens securely with encryption.",
        }
        return remediations.get(finding_name, "Review and fix the authentication implementation.")

    def _get_cwe_id(self, finding_name: str) -> str:
        """Get CWE ID for finding."""
        cwe_ids = {
            "Password in SharedPreferences": "CWE-312",
            "Password in UserDefaults": "CWE-312",
            "Hardcoded Password": "CWE-798",
            "Weak PIN Check": "CWE-521",
            "Token Logged": "CWE-532",
            "Token in URL Parameter": "CWE-598",
            "No Session Timeout": "CWE-613",
            "Insecure Remember Me": "CWE-312",
        }
        return cwe_ids.get(finding_name, "")

    def _get_cwe_name(self, finding_name: str) -> str:
        """Get CWE name for finding."""
        cwe_names = {
            "Password in SharedPreferences": "Cleartext Storage of Sensitive Information",
            "Password in UserDefaults": "Cleartext Storage of Sensitive Information",
            "Hardcoded Password": "Use of Hard-coded Credentials",
            "Weak PIN Check": "Weak Password Requirements",
            "Token Logged": "Insertion of Sensitive Information into Log File",
            "Token in URL Parameter": "Use of GET Request Method With Sensitive Query Strings",
            "No Session Timeout": "Insufficient Session Expiration",
            "Insecure Remember Me": "Cleartext Storage of Sensitive Information",
        }
        return cwe_names.get(finding_name, "")

    def _get_poc_commands(self, finding_name: str, app: MobileApp) -> list[dict[str, str]]:
        """Get PoC commands for finding."""
        if "SharedPreferences" in finding_name:
            return [
                {"type": "adb", "command": f"adb backup -f backup.ab {app.package_name}", "description": "Create backup"},
                {"type": "bash", "command": "cat backup/apps/*/sp/*.xml | grep -i password", "description": "Search for passwords"},
            ]
        if "Token Logged" in finding_name:
            return [
                {"type": "adb", "command": f"adb logcat -d | grep -i token", "description": "Search logs for tokens"},
            ]
        return []
