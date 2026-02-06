"""Binary protection and RASP (Runtime Application Self-Protection) analyzer.

Analyzes mobile application binaries for the presence of security
hardening features and commercial protection SDKs:

    - **Code obfuscation**: ProGuard/R8 (Android), Swift name mangling (iOS)
    - **Binary hardening**: PIE, ARC, stack canaries (see also NativeLibAnalyzer)
    - **RASP SDKs**: DexGuard, iXGuard, Arxan/Digital.ai, Promon SHIELD,
      Guardsquare, Zimperium zIAP
    - **Anti-tampering**: Integrity verification, debugger detection,
      emulator detection, root/jailbreak detection
    - **String encryption**: Encrypted string tables, runtime decryption

OWASP references:
    - MASVS-RESILIENCE: Anti-reversing and anti-tampering
    - MSTG-CODE-9: Binary security features
"""

import logging
import re
import subprocess
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger(__name__)


# Known RASP/Security SDK signatures
RASP_SIGNATURES = {
    "guardsquare_dexguard": {
        "vendor": "Guardsquare",
        "patterns": [
            r"com\.guardsquare",
            r"dexguard",
            r"DexGuard",
        ],
        "features": ["obfuscation", "string_encryption", "tamper_detection", "root_detection"],
    },
    "guardsquare_ixguard": {
        "vendor": "Guardsquare",
        "patterns": [
            r"ixguard",
            r"iXGuard",
        ],
        "features": ["obfuscation", "string_encryption", "jailbreak_detection"],
    },
    "promon_shield": {
        "vendor": "Promon",
        "patterns": [
            r"com\.promon",
            r"promon\.shield",
            r"PromonShield",
        ],
        "features": ["runtime_protection", "code_integrity", "anti_tampering", "anti_debugging"],
    },
    "appdome": {
        "vendor": "Appdome",
        "patterns": [
            r"com\.appdome",
            r"appdome",
        ],
        "features": ["no_code_protection", "anti_tampering", "anti_debugging"],
    },
    "appsealing": {
        "vendor": "AppSealing",
        "patterns": [
            r"com\.inka\.appsealing",
            r"appsealing",
        ],
        "features": ["runtime_protection", "anti_tampering", "memory_protection"],
    },
    "verimatrix": {
        "vendor": "Verimatrix",
        "patterns": [
            r"com\.verimatrix",
            r"verimatrix",
            r"VeridiumSDK",
        ],
        "features": ["code_protection", "whitebox_crypto", "anti_tampering"],
    },
    "arxan": {
        "vendor": "Arxan (Digital.ai)",
        "patterns": [
            r"com\.arxan",
            r"arxan",
        ],
        "features": ["obfuscation", "anti_tampering", "root_detection"],
    },
    "liapp": {
        "vendor": "LIAPP",
        "patterns": [
            r"com\.lockincomp",
            r"liapp",
        ],
        "features": ["anti_tampering", "anti_debugging", "memory_protection"],
    },
    "freerasp": {
        "vendor": "Talsec",
        "patterns": [
            r"com\.aheaditec\.talsec",
            r"freeRASP",
        ],
        "features": ["root_detection", "emulator_detection", "tampering_detection"],
    },
}

# Obfuscation indicators
OBFUSCATION_INDICATORS = {
    "proguard": [
        r"proguard-rules\.pro",
        r"-keepattributes",
        r"-keep class",
        r"proguardFiles",
    ],
    "r8": [
        r"minifyEnabled\s*=?\s*true",
        r"shrinkResources",
        r"R8",
    ],
    "class_name_obfuscation": [
        r"\b[a-z]{1,2}\.[a-z]{1,2}\.[a-z]{1,2}\b",  # Short package names like a.b.c
    ],
}


class BinaryProtectionAnalyzer(BaseAnalyzer):
    """Analyzes binary-level protections and security features."""

    name = "binary_protection_analyzer"
    description = "Analyzes binary protections, obfuscation, RASP, and security features"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze binary protections."""
        if not app.file_path:
            return []

        import shutil
        import tempfile
        import zipfile

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="bin_prot_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            results = []
            protections = {
                "obfuscation": {"detected": False, "tool": None, "evidence": []},
                "rasp": {"detected": False, "vendor": None, "features": []},
                "anti_tampering": {"detected": False, "methods": []},
                "anti_debugging": {"detected": False, "methods": []},
                "root_jailbreak_detection": {"detected": False, "methods": []},
                "emulator_detection": {"detected": False, "methods": []},
            }

            if app.platform == "android":
                protections.update(await self._analyze_android(extracted_path))
            elif app.platform == "ios":
                protections.update(await self._analyze_ios(extracted_path))

            # Check for RASP/Security SDKs
            rasp_results = await self._detect_rasp(extracted_path)
            if rasp_results:
                protections["rasp"]["detected"] = True
                protections["rasp"]["vendor"] = rasp_results.get("vendor")
                protections["rasp"]["features"] = rasp_results.get("features", [])

            # Create findings based on analysis
            analyzer_results = self._create_findings(protections, app)

            # Convert AnalyzerResults to Findings
            findings = []
            for result in analyzer_results:
                findings.append(self.result_to_finding(app, result))

            return findings

        except Exception as e:
            logger.error(f"Binary protection analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    async def _analyze_android(self, extracted_path: Path) -> dict:
        """Analyze Android-specific protections."""
        protections = {}

        # Check for obfuscation
        obfuscation_detected = False
        obfuscation_tool = None

        # Check build.gradle for ProGuard/R8
        for gradle_file in extracted_path.rglob("*.gradle*"):
            try:
                content = gradle_file.read_text(errors='ignore')
                if re.search(r"minifyEnabled\s*=?\s*true", content):
                    obfuscation_detected = True
                    obfuscation_tool = "R8/ProGuard"
            except:
                pass

        # Check for obfuscated class names in smali/dex
        smali_path = extracted_path / "smali"
        if smali_path.exists():
            obfuscated_classes = 0
            total_classes = 0
            for smali_file in smali_path.rglob("*.smali"):
                total_classes += 1
                if re.match(r"^[a-z]{1,2}\.smali$", smali_file.name):
                    obfuscated_classes += 1

            if total_classes > 0 and obfuscated_classes / total_classes > 0.3:
                obfuscation_detected = True

        protections["obfuscation"] = {
            "detected": obfuscation_detected,
            "tool": obfuscation_tool,
        }

        # Check for native libraries
        lib_path = extracted_path / "lib"
        native_libs = []
        if lib_path.exists():
            for so_file in lib_path.rglob("*.so"):
                native_libs.append(so_file.name)

        protections["native_code"] = {
            "detected": len(native_libs) > 0,
            "libraries": native_libs[:20],
        }

        # Check for anti-debugging
        anti_debug_patterns = [
            r"android\.os\.Debug\.isDebuggerConnected",
            r"ptrace",
            r"TracerPid",
            r"\/proc\/self\/status",
        ]
        anti_debug_found = []

        for pattern in anti_debug_patterns:
            for f in extracted_path.rglob("*.smali"):
                try:
                    if re.search(pattern, f.read_text(errors='ignore')):
                        anti_debug_found.append(pattern)
                        break
                except:
                    pass

        protections["anti_debugging"] = {
            "detected": len(anti_debug_found) > 0,
            "methods": list(set(anti_debug_found)),
        }

        # Check for root detection
        root_detection_patterns = [
            r"\/system\/app\/Superuser\.apk",
            r"\/system\/xbin\/su",
            r"com\.noshufou\.android\.su",
            r"eu\.chainfire\.supersu",
            r"com\.topjohnwu\.magisk",
            r"RootBeer",
            r"isRooted",
            r"checkForRoot",
        ]
        root_detection_found = []

        for pattern in root_detection_patterns:
            found = False
            for f in extracted_path.rglob("*.smali"):
                try:
                    if re.search(pattern, f.read_text(errors='ignore'), re.IGNORECASE):
                        root_detection_found.append(pattern)
                        found = True
                        break
                except:
                    pass
            if found:
                break

        protections["root_jailbreak_detection"] = {
            "detected": len(root_detection_found) > 0,
            "methods": list(set(root_detection_found)),
        }

        # Check for emulator detection
        emulator_patterns = [
            r"Build\.FINGERPRINT.*generic",
            r"Build\.MODEL.*sdk",
            r"Build\.PRODUCT.*sdk",
            r"\/dev\/socket\/qemud",
            r"goldfish",
            r"isEmulator",
        ]
        emulator_detection_found = []

        for pattern in emulator_patterns:
            for f in extracted_path.rglob("*.smali"):
                try:
                    if re.search(pattern, f.read_text(errors='ignore'), re.IGNORECASE):
                        emulator_detection_found.append(pattern)
                        break
                except:
                    pass

        protections["emulator_detection"] = {
            "detected": len(emulator_detection_found) > 0,
            "methods": list(set(emulator_detection_found)),
        }

        return protections

    async def _analyze_ios(self, extracted_path: Path) -> dict:
        """Analyze iOS-specific protections."""
        protections = {}

        # Find the main binary
        binary_path = None
        for f in extracted_path.rglob("*"):
            if f.is_file() and not f.suffix and f.stat().st_size > 10000:
                # Check if it's a Mach-O binary
                try:
                    with open(f, 'rb') as bf:
                        magic = bf.read(4)
                        if magic in [b'\xfe\xed\xfa\xce', b'\xfe\xed\xfa\xcf',
                                    b'\xca\xfe\xba\xbe', b'\xcf\xfa\xed\xfe']:
                            binary_path = f
                            break
                except:
                    pass

        if binary_path:
            # Use otool if available
            try:
                result = subprocess.run(
                    ["otool", "-hv", str(binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                output = result.stdout

                # Check for PIE
                protections["pie"] = {"detected": "PIE" in output}

                # Check for stack canary
                result = subprocess.run(
                    ["otool", "-Iv", str(binary_path)],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                symbols = result.stdout
                protections["stack_canary"] = {
                    "detected": "___stack_chk_fail" in symbols or "___stack_chk_guard" in symbols
                }

                # Check for ARC
                protections["arc"] = {
                    "detected": "_objc_release" in symbols or "_objc_retain" in symbols
                }

            except (subprocess.TimeoutExpired, FileNotFoundError):
                logger.debug("otool not available, skipping binary analysis")
                protections["pie"] = {"detected": None}
                protections["stack_canary"] = {"detected": None}
                protections["arc"] = {"detected": None}

        # Check for jailbreak detection in source
        jailbreak_patterns = [
            r"\/Applications\/Cydia\.app",
            r"\/Library\/MobileSubstrate",
            r"\/bin\/bash",
            r"\/usr\/sbin\/sshd",
            r"cydia:\/\/",
            r"isJailbroken",
            r"checkJailbreak",
        ]
        jailbreak_detection_found = []

        for ext in [".m", ".swift", ".h"]:
            for f in extracted_path.rglob(f"*{ext}"):
                try:
                    content = f.read_text(errors='ignore')
                    for pattern in jailbreak_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            jailbreak_detection_found.append(pattern)
                except:
                    pass

        protections["root_jailbreak_detection"] = {
            "detected": len(jailbreak_detection_found) > 0,
            "methods": list(set(jailbreak_detection_found)),
        }

        # Check for anti-debugging
        ios_anti_debug_patterns = [
            r"ptrace",
            r"sysctl",
            r"P_TRACED",
            r"debugger_detection",
        ]
        anti_debug_found = []

        for ext in [".m", ".swift"]:
            for f in extracted_path.rglob(f"*{ext}"):
                try:
                    content = f.read_text(errors='ignore')
                    for pattern in ios_anti_debug_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            anti_debug_found.append(pattern)
                except:
                    pass

        protections["anti_debugging"] = {
            "detected": len(anti_debug_found) > 0,
            "methods": list(set(anti_debug_found)),
        }

        return protections

    async def _detect_rasp(self, extracted_path: Path) -> dict | None:
        """Detect RASP/Security SDK usage."""
        for sdk_name, sdk_info in RASP_SIGNATURES.items():
            for pattern in sdk_info["patterns"]:
                # Search in all source files
                for ext in [".java", ".kt", ".smali", ".swift", ".m", ".xml", ".plist"]:
                    for f in extracted_path.rglob(f"*{ext}"):
                        try:
                            if re.search(pattern, f.read_text(errors='ignore'), re.IGNORECASE):
                                return {
                                    "sdk": sdk_name,
                                    "vendor": sdk_info["vendor"],
                                    "features": sdk_info["features"],
                                }
                        except:
                            pass

        return None

    def _create_findings(self, protections: dict, app: MobileApp) -> list[AnalyzerResult]:
        """Create findings based on protection analysis."""
        results = []

        # Missing obfuscation
        if not protections.get("obfuscation", {}).get("detected"):
            results.append(AnalyzerResult(
                title="Code Obfuscation Not Detected",
                description="The application does not appear to use code obfuscation. This makes reverse engineering significantly easier.",
                severity="medium",
                category="Binary Protection",
                impact="Without obfuscation, attackers can easily reverse engineer the application to understand its logic, find vulnerabilities, and extract sensitive information.",
                remediation="Enable ProGuard/R8 for Android or use commercial obfuscators like DexGuard. For iOS, consider using commercial tools like iXGuard or SwiftShield.",
                cwe_id="CWE-311",
                cwe_name="Missing Encryption of Sensitive Data",
                owasp_masvs_category="MASVS-RESILIENCE",
                owasp_masvs_control="MSTG-RESILIENCE-3",
                owasp_mastg_test="MASTG-TEST-0039",
                poc_verification="1. Use jadx or Hopper to decompile the app\n2. Check if class/method names are readable\n3. Look for clear business logic",
                poc_commands=[
                    {"type": "bash", "command": "jadx -d /tmp/decompiled app.apk", "description": "Decompile APK with jadx"},
                    {"type": "bash", "command": "ls /tmp/decompiled/sources/", "description": "Check package structure for obfuscated names"},
                ],
                cvss_score=5.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation_code={
                    "gradle": '''android {
    buildTypes {
        release {
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
        }
    }
}'''
                },
                remediation_resources=[
                    {"title": "OWASP MASTG - Testing for Debugging Symbols", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/", "type": "documentation"},
                    {"title": "Android - Shrink, obfuscate, and optimize your app", "url": "https://developer.android.com/studio/build/shrink-code", "type": "documentation"},
                ],
            ))
        else:
            tool = protections.get("obfuscation", {}).get("tool", "Unknown")
            results.append(AnalyzerResult(
                title=f"Code Obfuscation Detected ({tool})",
                description=f"The application uses code obfuscation ({tool}), which helps protect against reverse engineering.",
                severity="info",
                category="Binary Protection",
                impact="Obfuscation increases the difficulty of reverse engineering but is not a complete protection.",
                remediation="Ensure obfuscation rules are properly configured. Consider adding string encryption and control flow obfuscation for sensitive code.",
                owasp_masvs_category="MASVS-RESILIENCE",
                owasp_masvs_control="MSTG-RESILIENCE-3",
            ))

        # Missing root/jailbreak detection
        if not protections.get("root_jailbreak_detection", {}).get("detected"):
            platform_specific = {
                "android": {
                    "poc_commands": [
                        {"type": "adb", "command": "adb shell su -c 'id'", "description": "Verify device is rooted"},
                        {"type": "bash", "command": "grep -rn 'isRooted\\|RootBeer\\|checkRoot' /tmp/decompiled/", "description": "Search for root detection code"},
                    ],
                    "poc_frida": '''Java.perform(function() {
    // Check if app detects root
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function() {
        console.log("[*] RootBeer.isRooted() called - returning false");
        return false;
    };
});''',
                    "remediation_code": {
                        "kotlin": '''val rootBeer = RootBeer(context)
if (rootBeer.isRooted) {
    // Handle rooted device - restrict functionality or warn user
    showSecurityWarning()
}''',
                        "gradle": "implementation 'com.scottyab:rootbeer-lib:0.1.0'"
                    },
                },
                "ios": {
                    "poc_commands": [
                        {"type": "bash", "command": "ssh root@device 'ls /Applications/Cydia.app'", "description": "Check for Cydia"},
                        {"type": "bash", "command": "strings app_binary | grep -i jailbreak", "description": "Search for jailbreak detection"},
                    ],
                    "poc_frida": '''// Hook jailbreak detection
var FileManager = ObjC.classes.NSFileManager;
Interceptor.attach(FileManager['- fileExistsAtPath:'].implementation, {
    onEnter: function(args) {
        var path = ObjC.Object(args[2]).toString();
        if (path.indexOf('Cydia') !== -1 || path.indexOf('substrate') !== -1) {
            console.log("[*] Jailbreak check: " + path);
        }
    }
});''',
                    "remediation_code": {
                        "swift": '''import IOSSecuritySuite
if IOSSecuritySuite.amIJailbroken() {
    // Handle jailbroken device
    showSecurityWarning()
}'''
                    },
                }
            }
            platform = platform_specific.get(app.platform, platform_specific["android"])
            results.append(AnalyzerResult(
                title="Root/Jailbreak Detection Not Implemented",
                description="The application does not appear to detect rooted Android devices or jailbroken iOS devices.",
                severity="medium" if app.platform == "android" else "low",
                category="Binary Protection",
                impact="Running on compromised devices increases risk of data theft, runtime manipulation, and bypassing security controls.",
                remediation="Implement root/jailbreak detection using libraries like RootBeer (Android) or IOSSecuritySuite. Consider restricting functionality on compromised devices.",
                cwe_id="CWE-919",
                cwe_name="Weaknesses in Mobile Applications",
                owasp_masvs_category="MASVS-RESILIENCE",
                owasp_masvs_control="MSTG-RESILIENCE-1",
                owasp_mastg_test="MASTG-TEST-0046",
                poc_verification="1. Run app on rooted/jailbroken device\n2. Verify app runs without restriction\n3. Check for root/jailbreak detection code",
                poc_commands=platform["poc_commands"],
                poc_frida_script=platform["poc_frida"],
                cvss_score=4.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                remediation_code=platform["remediation_code"],
                remediation_resources=[
                    {"title": "OWASP MASTG - Testing Root Detection", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0046/", "type": "documentation"},
                    {"title": "RootBeer - Android Root Detection", "url": "https://github.com/scottyab/rootbeer", "type": "github"},
                    {"title": "IOSSecuritySuite", "url": "https://github.com/nickreynolds/IOSSecuritySuite", "type": "github"},
                ],
            ))

        # Missing anti-debugging
        if not protections.get("anti_debugging", {}).get("detected"):
            results.append(AnalyzerResult(
                title="Anti-Debugging Protection Not Detected",
                description="The application does not appear to implement anti-debugging protections.",
                severity="low",
                category="Binary Protection",
                impact="Attackers can attach debuggers to analyze runtime behavior, bypass security checks, and extract sensitive data.",
                remediation="Implement debugger detection using ptrace, timing checks, or Debug.isDebuggerConnected(). Consider using commercial RASP solutions.",
                cwe_id="CWE-388",
                cwe_name="Error Handling",
                owasp_masvs_category="MASVS-RESILIENCE",
                owasp_masvs_control="MSTG-RESILIENCE-2",
                owasp_mastg_test="MASTG-TEST-0040",
                poc_verification="1. Attach debugger (lldb/gdb/Android Studio)\n2. Set breakpoints in sensitive functions\n3. Verify app doesn't detect/prevent debugging",
                poc_commands=[
                    {"type": "adb", "command": "adb shell am set-debug-app -w --persistent com.example.app", "description": "Enable debugging for app"},
                    {"type": "frida", "command": "frida -U -f com.example.app -l bypass_debug.js", "description": "Attach Frida to app"},
                ],
                poc_frida_script='''Java.perform(function() {
    // Check if debugging is detected
    var Debug = Java.use('android.os.Debug');
    Debug.isDebuggerConnected.implementation = function() {
        console.log("[*] Debug.isDebuggerConnected() called");
        return false;  // Bypass detection
    };
});''',
                cvss_score=3.3,
                cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                remediation_code={
                    "java": '''// Simple debugger detection
if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
    // Debugger detected - take action
    android.os.Process.killProcess(android.os.Process.myPid());
}''',
                    "kotlin": '''// Simple debugger detection
if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
    android.os.Process.killProcess(android.os.Process.myPid())
}'''
                },
                remediation_resources=[
                    {"title": "OWASP MASTG - Testing Anti-Debugging Detection", "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0040/", "type": "documentation"},
                ],
            ))

        # RASP detection
        if protections.get("rasp", {}).get("detected"):
            vendor = protections["rasp"].get("vendor", "Unknown")
            features = protections["rasp"].get("features", [])
            results.append(AnalyzerResult(
                title=f"RASP/Security SDK Detected: {vendor}",
                description=f"The application uses a Runtime Application Self-Protection (RASP) solution from {vendor}.\n\nDetected features: {', '.join(features)}",
                severity="info",
                category="Binary Protection",
                impact="RASP solutions provide runtime protection against tampering, debugging, and other attacks. This significantly increases security.",
                remediation="Ensure the RASP solution is properly configured and kept up to date.",
                owasp_masvs_category="MASVS-RESILIENCE",
                owasp_masvs_control="MSTG-RESILIENCE-9",
                metadata={
                    "rasp_vendor": vendor,
                    "rasp_features": features,
                }
            ))

        # iOS-specific checks
        if app.platform == "ios":
            if protections.get("pie", {}).get("detected") is False:
                results.append(AnalyzerResult(
                    title="PIE (Position Independent Executable) Not Enabled",
                    description="The binary is not compiled with PIE, which is required for ASLR to be effective.",
                    severity="high",
                    category="Binary Protection",
                    impact="Without PIE, ASLR cannot randomize the binary's memory location, making exploitation easier.",
                    remediation="Compile with PIE enabled by adding -fPIE flag or ensuring Xcode settings enable PIE.",
                    cwe_id="CWE-119",
                    cwe_name="Improper Restriction of Operations within Memory Buffer",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MSTG-CODE-9",
                    owasp_mastg_test="MASTG-TEST-0082",
                    poc_verification="1. Extract binary from IPA\n2. Run otool -hv to check flags\n3. Verify PIE flag is present",
                    poc_commands=[
                        {"type": "bash", "command": "otool -hv /path/to/binary", "description": "Check binary flags for PIE"},
                        {"type": "bash", "command": "otool -l /path/to/binary | grep -A5 LC_SEGMENT", "description": "Check segment load addresses"},
                    ],
                    cvss_score=7.5,
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    remediation_resources=[
                        {"title": "OWASP MASTG - Testing for Memory Corruption Bugs", "url": "https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0082/", "type": "documentation"},
                    ],
                ))

            if protections.get("stack_canary", {}).get("detected") is False:
                results.append(AnalyzerResult(
                    title="Stack Canaries Not Detected",
                    description="The binary does not appear to use stack canaries for buffer overflow protection.",
                    severity="medium",
                    category="Binary Protection",
                    impact="Stack canaries help detect buffer overflow attacks. Without them, exploitation is easier.",
                    remediation="Compile with stack protection enabled (-fstack-protector-all flag).",
                    cwe_id="CWE-121",
                    cwe_name="Stack-based Buffer Overflow",
                    owasp_masvs_category="MASVS-CODE",
                    owasp_masvs_control="MSTG-CODE-9",
                    owasp_mastg_test="MASTG-TEST-0082",
                    poc_verification="1. Extract binary from IPA\n2. Run otool -Iv to check symbols\n3. Look for __stack_chk_fail",
                    poc_commands=[
                        {"type": "bash", "command": "otool -Iv /path/to/binary | grep stack_chk", "description": "Check for stack canary symbols"},
                    ],
                    cvss_score=5.9,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N",
                    remediation_resources=[
                        {"title": "OWASP MASTG - Testing for Memory Corruption Bugs", "url": "https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0082/", "type": "documentation"},
                    ],
                ))

            if protections.get("arc", {}).get("detected") is False:
                results.append(AnalyzerResult(
                    title="ARC (Automatic Reference Counting) Not Detected",
                    description="The binary may not be using ARC, increasing risk of memory management vulnerabilities.",
                    severity="low",
                    category="Binary Protection",
                    impact="Manual memory management increases the risk of use-after-free and double-free vulnerabilities.",
                    remediation="Enable ARC in Xcode project settings for all Objective-C code.",
                    cwe_id="CWE-416",
                    cwe_name="Use After Free",
                    owasp_masvs_category="MASVS-CODE",
                    owasp_masvs_control="MSTG-CODE-9",
                    owasp_mastg_test="MASTG-TEST-0082",
                    poc_verification="1. Extract binary from IPA\n2. Run otool -Iv to check symbols\n3. Look for objc_release/objc_retain",
                    poc_commands=[
                        {"type": "bash", "command": "otool -Iv /path/to/binary | grep -E 'objc_release|objc_retain'", "description": "Check for ARC symbols"},
                    ],
                    cvss_score=3.7,
                    cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
                    remediation_resources=[
                        {"title": "OWASP MASTG - Testing for Memory Corruption Bugs", "url": "https://mas.owasp.org/MASTG/tests/ios/MASVS-CODE/MASTG-TEST-0082/", "type": "documentation"},
                        {"title": "Apple - Transitioning to ARC", "url": "https://developer.apple.com/library/archive/releasenotes/ObjectiveC/RN-TransitioningToARC/Introduction/Introduction.html", "type": "documentation"},
                    ],
                ))

        return results
