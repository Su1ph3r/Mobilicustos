"""Bypass orchestrator for mobile application security protection analysis.

This module implements a multi-phase anti-detection analysis and bypass
framework for mobile security testing. It can identify and attempt to
circumvent common application protection mechanisms:

    - **Root detection** (RootBeer, SafetyNet/Play Integrity, su binary checks)
    - **SSL/TLS certificate pinning** (OkHttp, TrustManager, TrustKit, AFNetworking)
    - **Frida detection** (port scanning, file checks, memory signatures)
    - **Jailbreak detection** (Cydia, MobileSubstrate, file path checks)
    - **Emulator detection** (build property checks, hardware fingerprinting)
    - **Debugger detection** (ptrace, TracerPid, isDebuggerConnected)

The analysis pipeline operates in two phases:

    1. **Static analysis**: Scans the APK/IPA binary for detection signatures
       (string references, library imports, known detection patterns).
    2. **Runtime analysis**: Injects a Frida reconnaissance script to probe
       live runtime classes and device state on an actual device.

For each detected protection, the orchestrator attempts bypass by injecting
Frida scripts from the database (seeded builtins or user-uploaded), trying
scripts in order from generic to advanced until one succeeds.

Module-level constants:
    DETECTION_SIGNATURES: Known signatures for each protection type.
    DETECTION_TO_SCRIPT_MAP: Maps detection types to database query parameters.
    FAILURE_RECOMMENDATIONS: Expert recommendations when bypass attempts fail.
    RUNTIME_RECON_SCRIPT: Android Frida JS for live protection probing.
    IOS_RUNTIME_RECON_SCRIPT: iOS Frida JS for live protection probing.
"""

import asyncio
import logging
import zipfile
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.database import BypassResult, Device, FridaScript, MobileApp
from api.services.frida_service import FridaService

logger = logging.getLogger(__name__)


# Detection signatures database
DETECTION_SIGNATURES = {
    "frida": {
        "file_checks": [
            "/data/local/tmp/frida-server",
            "/data/local/tmp/re.frida.server",
            "/system/lib/libc.so.6",  # Frida modifies libc
        ],
        "port_checks": [27042, 27043],
        "memory_signatures": [
            b"frida-agent",
            b"gum-js-loop",
            b"frida_agent_main",
        ],
        "thread_names": ["gum-js-loop", "gmain", "frida"],
    },
    "root": {
        "file_checks": [
            "/system/app/Superuser.apk",
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/su",
            "/data/local/bin/su",
            "/data/local/xbin/su",
            "/system/app/SuperSU",
            "/system/app/Magisk",
        ],
        "binary_checks": ["su", "busybox", "magisk"],
        "prop_checks": ["ro.build.selinux", "ro.debuggable"],
    },
    "jailbreak": {
        "file_checks": [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
        ],
        "url_schemes": ["cydia://", "sileo://"],
    },
    "emulator": {
        "prop_checks": [
            "ro.kernel.qemu",
            "ro.product.model",  # Check for emulator models
            "ro.hardware",
        ],
        "build_checks": ["generic", "sdk", "goldfish", "ranchu"],
        "sensor_checks": ["accelerometer", "gyroscope"],
    },
    "debugger": {
        "status_checks": ["TracerPid"],
        "ptrace_checks": True,
    },
    "ssl_pinning": {
        "libraries": {
            "android": ["OkHttp", "TrustManager", "HttpsURLConnection"],
            "ios": ["NSURLSession", "Alamofire", "AFNetworking"],
        },
    },
}

# Mapping from detection types to the script subcategories and name keywords
# used for querying the frida_scripts table. The orchestrator will try scripts
# in the order they appear for each detection type, stopping after the first
# success.
DETECTION_TO_SCRIPT_MAP: dict[str, dict[str, Any]] = {
    "root": {
        "subcategory": "root_detection",
        "name_keywords": ["root"],
    },
    "ssl_pinning": {
        "subcategory": "ssl_pinning",
        "name_keywords": ["ssl", "pinning"],
    },
    "frida": {
        "subcategory": "anti_frida",
        "name_keywords": ["frida"],
    },
    "jailbreak": {
        "subcategory": "jailbreak_detection",
        "name_keywords": ["jailbreak"],
    },
    "emulator": {
        "subcategory": "emulator_detection",
        "name_keywords": ["emulator"],
    },
    "debugger": {
        "subcategory": "debugger_detection",
        "name_keywords": ["debugger", "debug"],
    },
    "biometric": {
        "subcategory": "biometric",
        "name_keywords": ["biometric", "fingerprint"],
    },
    "tamper": {
        "subcategory": "tamper_detection",
        "name_keywords": ["tamper", "integrity", "signature"],
    },
    "play_integrity": {
        "subcategory": "play_integrity",
        "name_keywords": ["play_integrity", "safetynet"],
    },
}

# Bypass verification probes — scripts that re-trigger detection to confirm bypass success
BYPASS_VERIFICATION_PROBES: dict[str, str] = {
    "root": (
        "Java.perform(function() {\n"
        "    try {\n"
        "        var File = Java.use('java.io.File');\n"
        "        var f = File.$new('/system/bin/su');\n"
        "        var exists = f.exists();\n"
        "        send('[VERIFY] su exists=' + exists);\n"
        "        if (exists) { send('[VERIFY_FAIL] root detection still active'); }\n"
        "        else { send('[VERIFY_PASS] root detection bypassed'); }\n"
        "    } catch(e) { send('[VERIFY_ERROR] ' + e); }\n"
        "});\n"
    ),
    "ssl_pinning": (
        "Java.perform(function() {\n"
        "    try {\n"
        "        var CertificatePinner = Java.use('okhttp3.CertificatePinner');\n"
        "        send('[VERIFY_PASS] CertificatePinner class hooked successfully');\n"
        "    } catch(e) { send('[VERIFY_INFO] No OkHttp CertificatePinner found'); }\n"
        "});\n"
    ),
    "frida": (
        "Java.perform(function() {\n"
        "    try {\n"
        "        var File = Java.use('java.io.File');\n"
        "        var f = File.$new('/data/local/tmp/frida-server');\n"
        "        var exists = f.exists();\n"
        "        send('[VERIFY] frida-server visible=' + exists);\n"
        "        if (exists) { send('[VERIFY_FAIL] anti-Frida detection still active'); }\n"
        "        else { send('[VERIFY_PASS] anti-Frida bypass confirmed'); }\n"
        "    } catch(e) { send('[VERIFY_ERROR] ' + e); }\n"
        "});\n"
    ),
    "emulator": (
        "Java.perform(function() {\n"
        "    try {\n"
        "        var Build = Java.use('android.os.Build');\n"
        "        var fingerprint = Build.FINGERPRINT.value;\n"
        "        var model = Build.MODEL.value;\n"
        "        send('[VERIFY] Build.FINGERPRINT=' + fingerprint);\n"
        "        send('[VERIFY] Build.MODEL=' + model);\n"
        "        var emuIndicators = ['generic', 'sdk', 'goldfish', 'ranchu', 'emulator'];\n"
        "        var detected = false;\n"
        "        for (var i = 0; i < emuIndicators.length; i++) {\n"
        "            if (fingerprint.toLowerCase().indexOf(emuIndicators[i]) !== -1 ||\n"
        "                model.toLowerCase().indexOf(emuIndicators[i]) !== -1) {\n"
        "                detected = true; break;\n"
        "            }\n"
        "        }\n"
        "        if (detected) { send('[VERIFY_FAIL] emulator indicators still visible'); }\n"
        "        else { send('[VERIFY_PASS] emulator detection bypassed'); }\n"
        "    } catch(e) { send('[VERIFY_ERROR] ' + e); }\n"
        "});\n"
    ),
}

# Ordered bypass chains: try scripts in this priority order per detection type
BYPASS_CHAINS: dict[str, list[str]] = {
    "root": ["generic", "rootbeer", "magisk", "safetynet"],
    "ssl_pinning": ["generic", "okhttp", "trustmanager", "advanced"],
    "frida": ["generic", "file_hide", "memory_hide", "advanced"],
    "emulator": ["generic", "build_props", "sensor", "telephony"],
    "jailbreak": ["generic", "file_hide", "sandbox", "advanced"],
    "tamper": ["generic", "signature", "dexguard", "advanced"],
}

# Recommendations to provide when a bypass fails
FAILURE_RECOMMENDATIONS: dict[str, list[str]] = {
    "root": [
        "Try a RootBeer-specific bypass if the app uses com.scottyab.rootbeer",
        "Try hooking native su binary checks via Interceptor.attach on 'access' or 'stat'",
        "For Magisk-based detection, try hooking MagiskManager class directly",
        "Consider using Magisk DenyList / MagiskHide for the target package",
        "For SafetyNet/Play Integrity, use a custom module (shamiko, etc.)",
    ],
    "ssl_pinning": [
        "Try the Advanced SSL Pinning Bypass script for more library coverage",
        "If OkHttp bypass fails, try hooking TrustManagerImpl.verifyChain directly",
        "For custom TrustManager implementations, identify the class via static analysis and hook it",
        "For Flutter/Dart apps, SSL pinning lives in native code - Java hooks will not work",
        "Consider using a custom CA certificate installed as system cert via Magisk module",
    ],
    "frida": [
        "Try renaming frida-server binary to avoid file-based detection",
        "Use frida-server with --listen flag on a non-default port",
        "Consider hooking native open()/fopen() to hide /proc/self/maps entries",
        "For aggressive anti-Frida, try Frida gadget injection instead of frida-server",
    ],
    "jailbreak": [
        "Try hooking additional Objective-C classes the app uses for detection",
        "Check for custom jailbreak detection frameworks (iXGuard, etc.)",
        "Some apps check sandbox integrity - hook sandbox_check() as well",
        "For apps using file-based checks, ensure all known paths are covered",
    ],
    "emulator": [
        "Ensure Build properties match a real device fingerprint",
        "Some apps check sensor availability - hook SensorManager if needed",
        "Check for additional telephony-based detection methods",
    ],
    "debugger": [
        "Ensure ptrace(PTRACE_TRACEME) is properly blocked at native level",
        "Some apps use timing-based detection - hook System.nanoTime for consistency",
        "Check for /proc/self/status TracerPid parsing via native code",
    ],
    "tamper": [
        "Hook PackageManager.getPackageInfo() to return original signature",
        "For DexGuard-protected apps, try hooking StringEncryptor directly",
        "For Arxan/Digital.ai, hook AppProtectAgent initialization",
        "Consider re-signing the APK with the original keystore if available",
        "Check for native-level integrity checks via dlopen/dlsym hooks",
    ],
    "play_integrity": [
        "Play Integrity is server-side attestation — client bypass is not possible",
        "Test on a non-rooted device without Frida modifications",
        "Use Frida Gadget injection instead of frida-server",
        "Use Magisk + Shamiko module to hide root from attestation",
        "Document attestation as a testing limitation in your report",
    ],
    "biometric": [
        "Hook BiometricPrompt.AuthenticationCallback.onAuthenticationSucceeded",
        "For CryptoObject-backed biometrics, extract the key from Keystore first",
        "Some apps use KeygenParameterSpec.Builder.setUserAuthenticationRequired - hook this",
    ],
}

# Recon script that runs on the device to detect active protections at runtime
RUNTIME_RECON_SCRIPT = """\
// Runtime protection reconnaissance script
// Detects active protections by probing common detection classes and methods

(function() {
    var results = [];

    // --- Root Detection Probing ---
    Java.perform(function() {
        // Check for RootBeer library
        try {
            var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
            send('[+] root_detection:rootbeer:RootBeer class found (com.scottyab.rootbeer)');
        } catch(e) {
            send('[-] root_detection:rootbeer:RootBeer class not found');
        }

        // Check for SafetyNet / Play Integrity
        try {
            var SafetyNet = Java.use('com.google.android.gms.safetynet.SafetyNetClient');
            send('[+] root_detection:safetynet:SafetyNet client class found');
        } catch(e) {
            send('[-] root_detection:safetynet:SafetyNet not found');
        }

        // Check if su binary is accessible
        try {
            var Runtime = Java.use('java.lang.Runtime');
            var process = Runtime.getRuntime().exec('which su');
            var reader = Java.use('java.io.BufferedReader');
            var inputReader = Java.use('java.io.InputStreamReader');
            var ir = inputReader.$new(process.getInputStream());
            var br = reader.$new(ir);
            var line = br.readLine();
            if (line !== null) {
                send('[+] root_detection:su_binary:su binary found at ' + line);
            } else {
                send('[-] root_detection:su_binary:su binary not found in PATH');
            }
        } catch(e) {
            send('[*] root_detection:su_binary:Could not check su - ' + e.message);
        }

        // --- SSL Pinning Probing ---
        // Check for OkHttp CertificatePinner
        try {
            var CertPinner = Java.use('okhttp3.CertificatePinner');
            send('[+] ssl_pinning:okhttp:OkHttp CertificatePinner class found');
        } catch(e) {
            send('[-] ssl_pinning:okhttp:OkHttp CertificatePinner not found');
        }

        // Check for custom TrustManager
        try {
            var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
            send('[+] ssl_pinning:trustmanager:TrustManagerImpl class found');
        } catch(e) {
            send('[-] ssl_pinning:trustmanager:TrustManagerImpl not found');
        }

        // Check for TrustKit
        try {
            var TrustKit = Java.use('com.datatheorem.android.trustkit.TrustKit');
            send('[+] ssl_pinning:trustkit:TrustKit class found');
        } catch(e) {
            send('[-] ssl_pinning:trustkit:TrustKit not found');
        }

        // Check for NetworkSecurityConfig pinning
        try {
            var NSConfig = Java.use('android.security.net.config.NetworkSecurityTrustManager');
            send('[+] ssl_pinning:network_security_config:NetworkSecurityTrustManager found');
        } catch(e) {
            send('[-] ssl_pinning:network_security_config:NetworkSecurityTrustManager not found');
        }

        // --- Frida Detection Probing ---
        // Check if app scans for Frida port
        try {
            var InetAddress = Java.use('java.net.InetAddress');
            var Socket = Java.use('java.net.Socket');
            send('[*] frida_detection:port_scan:Socket class available (app may scan for port 27042)');
        } catch(e) {}

        // Check for anti-Frida libraries
        try {
            var cls = Java.use('com.example.antiFrida');
            send('[+] frida_detection:library:Anti-Frida library detected');
        } catch(e) {
            send('[-] frida_detection:library:No known anti-Frida library detected');
        }

        // --- Emulator Detection Probing ---
        try {
            var Build = Java.use('android.os.Build');
            var fingerprint = Build.FINGERPRINT.value;
            var model = Build.MODEL.value;
            var product = Build.PRODUCT.value;
            var hardware = Build.HARDWARE.value;
            send('[*] emulator_detection:build_info:FINGERPRINT=' + fingerprint);
            send('[*] emulator_detection:build_info:MODEL=' + model);
            send('[*] emulator_detection:build_info:PRODUCT=' + product);

            var emuIndicators = ['generic', 'sdk', 'goldfish', 'ranchu', 'emulator', 'genymotion'];
            var detected = false;
            for (var i = 0; i < emuIndicators.length; i++) {
                if (fingerprint.toLowerCase().indexOf(emuIndicators[i]) !== -1 ||
                    model.toLowerCase().indexOf(emuIndicators[i]) !== -1 ||
                    product.toLowerCase().indexOf(emuIndicators[i]) !== -1 ||
                    hardware.toLowerCase().indexOf(emuIndicators[i]) !== -1) {
                    send('[+] emulator_detection:indicators:Emulator indicator found: ' + emuIndicators[i]);
                    detected = true;
                }
            }
            if (!detected) {
                send('[-] emulator_detection:indicators:No emulator indicators in Build properties');
            }
        } catch(e) {
            send('[*] emulator_detection:error:Could not read Build properties - ' + e.message);
        }

        // --- Debugger Detection Probing ---
        try {
            var Debug = Java.use('android.os.Debug');
            var isDebugging = Debug.isDebuggerConnected();
            if (isDebugging) {
                send('[+] debugger_detection:java:Debugger is connected (Debug.isDebuggerConnected)');
            } else {
                send('[-] debugger_detection:java:No debugger connected');
            }
        } catch(e) {
            send('[*] debugger_detection:error:Could not check debugger - ' + e.message);
        }

        // --- Biometric Authentication Probing ---
        try {
            var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');
            send('[+] biometric:api:BiometricPrompt class found');
        } catch(e) {
            send('[-] biometric:api:BiometricPrompt not found');
        }

        try {
            var FingerprintManager = Java.use('android.hardware.fingerprint.FingerprintManager');
            send('[+] biometric:fingerprint:FingerprintManager class found');
        } catch(e) {
            send('[-] biometric:fingerprint:FingerprintManager not found');
        }

        send('[*] recon_complete:done:Runtime protection reconnaissance finished');
    });
})();
"""

# iOS variant of the recon script
IOS_RUNTIME_RECON_SCRIPT = """\
// iOS Runtime protection reconnaissance script

(function() {
    if (!ObjC.available) {
        send('[-] recon:error:Objective-C runtime not available');
        return;
    }

    // --- Jailbreak Detection Probing ---
    var jbPaths = [
        '/Applications/Cydia.app',
        '/Library/MobileSubstrate/MobileSubstrate.dylib',
        '/bin/bash',
        '/usr/sbin/sshd',
        '/etc/apt',
        '/private/var/lib/apt/',
        '/private/var/lib/cydia',
        '/private/var/stash'
    ];

    var NSFileManager = ObjC.classes.NSFileManager;
    var fm = NSFileManager.defaultManager();
    var jbFound = false;
    for (var i = 0; i < jbPaths.length; i++) {
        var nsPath = ObjC.classes.NSString.stringWithString_(jbPaths[i]);
        if (fm.fileExistsAtPath_(nsPath)) {
            send('[+] jailbreak_detection:file_check:Jailbreak file found: ' + jbPaths[i]);
            jbFound = true;
        }
    }
    if (!jbFound) {
        send('[-] jailbreak_detection:file_check:No jailbreak files found');
    }

    // Check for Cydia URL scheme
    try {
        var UIApp = ObjC.classes.UIApplication.sharedApplication();
        var cydiaUrl = ObjC.classes.NSURL.URLWithString_('cydia://');
        if (UIApp.canOpenURL_(cydiaUrl)) {
            send('[+] jailbreak_detection:url_scheme:Cydia URL scheme available');
        } else {
            send('[-] jailbreak_detection:url_scheme:Cydia URL scheme not available');
        }
    } catch(e) {
        send('[*] jailbreak_detection:url_scheme:Could not check URL scheme - ' + e.message);
    }

    // --- SSL Pinning Probing ---
    try {
        if (ObjC.classes.AFSecurityPolicy) {
            send('[+] ssl_pinning:afnetworking:AFSecurityPolicy class found');
        }
    } catch(e) {
        send('[-] ssl_pinning:afnetworking:AFSecurityPolicy not found');
    }

    try {
        if (ObjC.classes.TrustKit) {
            send('[+] ssl_pinning:trustkit_ios:TrustKit class found');
        }
    } catch(e) {
        send('[-] ssl_pinning:trustkit_ios:TrustKit not found');
    }

    send('[*] recon_complete:done:iOS runtime protection reconnaissance finished');
})();
"""


def _parse_output_markers(messages: list[dict]) -> dict[str, list[dict[str, str]]]:
    """Parse Frida script output messages into structured detection results.

    Returns a dict mapping detection types to lists of evidence entries.
    Each evidence entry has: marker ('+'/'-'/'*'), detail_type, and detail.
    """
    detections: dict[str, list[dict[str, str]]] = {}

    for msg in messages:
        payload = str(msg.get("payload", ""))
        if not payload:
            continue

        # Parse markers: [+] type:subtype:detail, [-] type:subtype:detail, [*] type:subtype:detail
        for prefix, marker in [("[+]", "+"), ("[-]", "-"), ("[*]", "*")]:
            if prefix in payload:
                content = payload.split(prefix, 1)[1].strip()
                parts = content.split(":", 2)
                if len(parts) >= 3:
                    det_type = parts[0].strip()
                    detail_type = parts[1].strip()
                    detail = parts[2].strip()
                elif len(parts) == 2:
                    det_type = parts[0].strip()
                    detail_type = "general"
                    detail = parts[1].strip()
                else:
                    det_type = "unknown"
                    detail_type = "general"
                    detail = content

                if det_type not in detections:
                    detections[det_type] = []
                detections[det_type].append({
                    "marker": marker,
                    "detail_type": detail_type,
                    "detail": detail,
                })
                break  # Only match the first marker in a line

    return detections


def _count_markers(entries: list[dict[str, str]]) -> tuple[int, int, int]:
    """Count success (+), failure (-), and informational (*) markers."""
    success = sum(1 for e in entries if e["marker"] == "+")
    failure = sum(1 for e in entries if e["marker"] == "-")
    info = sum(1 for e in entries if e["marker"] == "*")
    return success, failure, info


def _determine_confidence(success_count: int, total_entries: int) -> str:
    """Determine detection confidence based on marker counts."""
    if total_entries == 0:
        return "none"
    ratio = success_count / total_entries
    if ratio >= 0.6:
        return "high"
    elif ratio >= 0.3:
        return "medium"
    else:
        return "low"


def _get_recommendations(
    detection_type: str,
    bypass_failed: bool,
    evidence: list[dict[str, str]],
) -> list[str]:
    """Generate recommendations based on detection type and bypass results."""
    recommendations: list[str] = []

    if bypass_failed:
        recs = FAILURE_RECOMMENDATIONS.get(detection_type, [])
        recommendations.extend(recs)

        # Add evidence-specific recommendations
        evidence_details = " ".join(e.get("detail", "") for e in evidence)
        detail_lower = evidence_details.lower()

        if detection_type == "root" and "rootbeer" in detail_lower:
            recommendations.insert(
                0,
                "RootBeer detected - the RootBeer-specific bypass script should be prioritized",
            )
        if detection_type == "root" and "safetynet" in detail_lower:
            recommendations.insert(
                0,
                "SafetyNet/Play Integrity detected - consider Magisk + shamiko module",
            )
        if detection_type == "ssl_pinning" and "okhttp" in detail_lower:
            recommendations.insert(
                0,
                "OkHttp pinning detected - try the Advanced SSL Pinning Bypass script",
            )
        if detection_type == "ssl_pinning" and "trustkit" in detail_lower:
            recommendations.insert(
                0,
                "TrustKit detected - Advanced SSL Pinning Bypass covers this library",
            )
    else:
        recommendations.append(
            "Bypass appears successful - verify by exercising app functionality"
        )
        recommendations.append(
            "Monitor Frida console output for any subsequent detection triggers"
        )

    return recommendations


class BypassOrchestrator:
    """Orchestrates anti-detection analysis and bypass attempts.

    Coordinates the full protection detection and bypass pipeline: static
    binary analysis, runtime Frida-based probing, script selection from the
    database, injection with success/failure evaluation, and result
    persistence.

    The orchestrator uses ``FridaService`` for all device interactions and
    evaluates bypass success by counting ``[+]``/``[-]``/``[*]`` markers
    in Frida script output.

    Attributes:
        frida: FridaService instance for script injection and session management.
    """

    def __init__(self):
        self.frida = FridaService()

    # =========================================================================
    # Static Protection Analysis
    # =========================================================================

    async def analyze_protections(self, app: MobileApp) -> list[dict[str, Any]]:
        """Analyze an app's protection mechanisms via static analysis.

        Examines the APK/IPA archive for known protection signatures such as
        anti-Frida code, root/jailbreak detection libraries, SSL pinning
        implementations, and emulator detection patterns.
        """
        detections: list[dict[str, Any]] = []

        if not app.file_path:
            return detections

        try:
            with zipfile.ZipFile(app.file_path, "r") as archive:
                file_list = archive.namelist()

                # Check for anti-Frida
                frida_detection = await self._detect_anti_frida(archive, file_list)
                if frida_detection:
                    detections.append(frida_detection)

                # Check for root detection
                if app.platform == "android":
                    root_detection = await self._detect_root_detection(
                        archive, file_list
                    )
                    if root_detection:
                        detections.append(root_detection)

                # Check for jailbreak detection
                if app.platform == "ios":
                    jb_detection = await self._detect_jailbreak_detection(
                        archive, file_list
                    )
                    if jb_detection:
                        detections.append(jb_detection)

                # Check for SSL pinning
                ssl_detection = await self._detect_ssl_pinning(
                    archive, file_list, app.platform
                )
                if ssl_detection:
                    detections.append(ssl_detection)

                # Check for emulator detection
                if app.platform == "android":
                    emu_detection = await self._detect_emulator_detection(
                        archive, file_list
                    )
                    if emu_detection:
                        detections.append(emu_detection)

                # Check for tamper/integrity detection
                if app.platform == "android":
                    tamper_detection = await self._detect_tamper_detection(
                        archive, file_list
                    )
                    if tamper_detection:
                        detections.append(tamper_detection)

                # Check for Play Integrity / SafetyNet
                if app.platform == "android":
                    pi_detection = await self._detect_play_integrity(
                        archive, file_list
                    )
                    if pi_detection:
                        detections.append(pi_detection)

        except Exception as e:
            logger.error(f"Protection analysis failed: {e}")

        return detections

    # =========================================================================
    # Runtime Protection Analysis
    # =========================================================================

    async def analyze_protections_runtime(
        self,
        app: MobileApp,
        device: Device,
    ) -> list[dict[str, Any]]:
        """Analyze protections at runtime by injecting a recon Frida script.

        This supplements static analysis by actually probing the runtime for
        active protection classes (RootBeer, SafetyNet, CertificatePinner, etc.)
        and device state (su binary presence, emulator indicators).

        Returns a list of detection dicts with: type, confidence,
        evidence, detected (bool), source.
        """
        detections: list[dict[str, Any]] = []

        # Choose the right recon script based on platform
        if app.platform == "ios":
            recon_script = IOS_RUNTIME_RECON_SCRIPT
        else:
            recon_script = RUNTIME_RECON_SCRIPT

        session_id = None
        try:
            # Inject the recon script; use spawn=True so the app starts fresh
            session_id = await self.frida.inject(
                device_id=device.device_id,
                package_name=app.package_name,
                script_content=recon_script,
                spawn=True,
            )

            # Wait for the script to finish probing. The recon script runs
            # synchronously inside Java.perform so most output arrives quickly.
            await asyncio.sleep(5)

            # Collect messages
            messages = await self.frida.get_session_messages(session_id)
            parsed = _parse_output_markers(messages)

            # Convert parsed results to detection dicts
            for det_type, entries in parsed.items():
                if det_type in ("recon_complete", "unknown"):
                    continue

                success_count, failure_count, info_count = _count_markers(entries)
                total = success_count + failure_count + info_count
                confidence = _determine_confidence(success_count, total)

                evidence_list = [
                    f"{'Detected' if e['marker'] == '+' else 'Not found' if e['marker'] == '-' else 'Info'}: "
                    f"{e['detail']}"
                    for e in entries
                ]

                detections.append({
                    "type": det_type,
                    "detected": success_count > 0,
                    "confidence": confidence,
                    "evidence": evidence_list[:10],
                    "methods": list({e["detail_type"] for e in entries}),
                    "source": "runtime",
                })

        except Exception as e:
            logger.error(f"Runtime protection analysis failed: {e}")
            detections.append({
                "type": "error",
                "detected": False,
                "confidence": "none",
                "evidence": [f"Runtime analysis failed: {str(e)}"],
                "methods": [],
                "source": "runtime",
            })
        finally:
            if session_id:
                try:
                    await self.frida.detach(session_id)
                except Exception:
                    pass

        return detections

    # =========================================================================
    # Static Detection Helpers
    # =========================================================================

    async def _detect_anti_frida(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect anti-Frida mechanisms in the application binary.

        Searches for known anti-Frida library names and string references
        (e.g., ``"frida"``, ``"27042"``, ``"gum-js"``) in DEX files and
        native shared libraries.

        Args:
            archive: Open ZipFile handle to the APK/IPA.
            file_list: Pre-computed list of file names within the archive.

        Returns:
            Detection dict with ``type``, ``detected``, ``evidence``,
            ``confidence``, and ``methods`` if anti-Frida indicators are
            found, or None if nothing detected.
        """
        evidence = []

        # Check for known anti-Frida libraries
        anti_frida_libs = ["libfrida-check", "libanti-frida"]
        for lib in anti_frida_libs:
            if any(lib in f for f in file_list):
                evidence.append(f"Found library: {lib}")

        # Search for Frida detection strings in DEX/native code
        frida_strings = ["frida", "27042", "frida-server", "gum-js"]
        for name in file_list:
            if name.endswith(".dex") or name.endswith(".so"):
                try:
                    content = archive.read(name).decode("utf-8", errors="ignore")
                    for s in frida_strings:
                        if s in content.lower():
                            evidence.append(f"Found '{s}' in {name}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "frida",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 2 else "medium",
                "methods": ["file_check", "port_scan", "memory_scan"],
            }

        return None

    async def _detect_root_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect root detection mechanisms in Android binaries.

        Searches for root detection libraries (RootBeer, SafetyNet) and
        string references to common root file paths (``/system/bin/su``,
        ``/system/app/Superuser.apk``, etc.) in DEX bytecode.

        Args:
            archive: Open ZipFile handle to the APK.
            file_list: Pre-computed list of file names within the archive.

        Returns:
            Detection dict or None if no root detection indicators found.
        """
        evidence = []

        # Check for RootBeer or similar libraries
        root_libs = ["rootbeer", "rootchecker", "safetynet"]
        for name in file_list:
            if any(lib in name.lower() for lib in root_libs):
                evidence.append(f"Found root detection library: {name}")

        # Search for root detection strings
        root_strings = DETECTION_SIGNATURES["root"]["file_checks"]
        for name in file_list:
            if name.endswith(".dex"):
                try:
                    content = archive.read(name).decode("utf-8", errors="ignore")
                    for s in root_strings:
                        if s in content:
                            evidence.append(f"Found root path check: {s}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "root",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 3 else "medium",
                "methods": ["file_check", "command_exec", "prop_check"],
            }

        return None

    async def _detect_jailbreak_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect jailbreak detection mechanisms in iOS binaries.

        Searches for references to known jailbreak file paths
        (``/Applications/Cydia.app``, ``/bin/bash``, etc.) and URL schemes
        (``cydia://``, ``sileo://``) in Mach-O binaries and frameworks.

        Args:
            archive: Open ZipFile handle to the IPA.
            file_list: Pre-computed list of file names within the archive.

        Returns:
            Detection dict or None if no jailbreak detection indicators found.
        """
        evidence = []

        jb_strings = list(DETECTION_SIGNATURES["jailbreak"]["file_checks"])
        jb_strings.extend(DETECTION_SIGNATURES["jailbreak"]["url_schemes"])

        # Search in binary
        for name in file_list:
            if name.endswith("App") or ".framework" in name:
                try:
                    content = archive.read(name)
                    for s in jb_strings:
                        if s.encode() in content:
                            evidence.append(f"Found jailbreak check: {s}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "jailbreak",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 2 else "medium",
                "methods": ["file_check", "url_scheme", "fork_check"],
            }

        return None

    async def _detect_ssl_pinning(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
        platform: str,
    ) -> dict[str, Any] | None:
        """Detect SSL/TLS certificate pinning implementations.

        Searches for pinning-related class references and patterns
        (``certificatepinner``, ``trustmanager``, ``pinnedcertificates``,
        etc.) in DEX, native, or Mach-O binaries depending on platform.

        Args:
            archive: Open ZipFile handle to the APK/IPA.
            file_list: Pre-computed list of file names within the archive.
            platform: Target platform (``"android"`` or ``"ios"``).

        Returns:
            Detection dict with ``libraries`` list or None if no pinning found.
        """
        evidence = []

        libs = DETECTION_SIGNATURES["ssl_pinning"]["libraries"].get(platform, [])
        pinning_patterns = [
            "certificatepinner",
            "sslpinning",
            "trustmanager",
            "x509trustmanager",
            "pinnedcertificates",
        ]

        for name in file_list:
            if name.endswith((".dex", ".so")) or (
                platform == "ios" and name.endswith("App")
            ):
                try:
                    content = (
                        archive.read(name).decode("utf-8", errors="ignore").lower()
                    )
                    for pattern in pinning_patterns:
                        if pattern in content:
                            evidence.append(
                                f"Found SSL pinning pattern: {pattern}"
                            )
                except Exception:
                    pass

        if evidence:
            return {
                "type": "ssl_pinning",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high" if len(evidence) > 1 else "medium",
                "libraries": libs,
            }

        return None

    async def _detect_emulator_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect emulator detection mechanisms in Android binaries.

        Searches for references to known emulator identifiers (``goldfish``,
        ``ranchu``, ``genymotion``, ``bluestacks``, ``qemu``) in DEX bytecode.

        Args:
            archive: Open ZipFile handle to the APK.
            file_list: Pre-computed list of file names within the archive.

        Returns:
            Detection dict or None if no emulator detection indicators found.
        """
        evidence = []

        emu_patterns = [
            "goldfish",
            "ranchu",
            "genymotion",
            "bluestacks",
            "qemu",
            "emulator",
        ]

        for name in file_list:
            if name.endswith(".dex"):
                try:
                    content = (
                        archive.read(name).decode("utf-8", errors="ignore").lower()
                    )
                    for pattern in emu_patterns:
                        if pattern in content:
                            evidence.append(f"Found emulator check: {pattern}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "emulator",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "medium",
                "methods": ["prop_check", "build_check"],
            }

        return None

    async def _detect_tamper_detection(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect tamper/integrity detection in Android binaries.

        Searches for signature verification, debug flag checks, and known
        anti-tamper SDK patterns (DexGuard, Arxan/Digital.ai).
        """
        evidence = []

        tamper_patterns = [
            "PackageManager;->getPackageInfo",
            "signatures",
            "ApplicationInfo;->flags",
            "FLAG_DEBUGGABLE",
            "StringEncryptor",  # DexGuard
            "AppProtectAgent",  # Arxan/Digital.ai
            "dexguard",
            "arxan",
        ]

        for name in file_list:
            if name.endswith(".dex"):
                try:
                    content = (
                        archive.read(name).decode("utf-8", errors="ignore").lower()
                    )
                    for pattern in tamper_patterns:
                        if pattern.lower() in content:
                            evidence.append(f"Found tamper check: {pattern}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "tamper",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "medium",
                "methods": ["signature_check", "debug_flag_check"],
            }
        return None

    async def _detect_play_integrity(
        self,
        archive: zipfile.ZipFile,
        file_list: list[str],
    ) -> dict[str, Any] | None:
        """Detect Play Integrity / SafetyNet attestation usage.

        Searches for Play Integrity API and legacy SafetyNet API references.
        Note: bypass is not attempted — instead an informational finding is
        generated explaining what the pentester should do.
        """
        evidence = []

        pi_patterns = [
            "com.google.android.play.core.integrity",
            "IntegrityManager",
            "requestIntegrityToken",
            "com.google.android.gms.safetynet",
            "SafetyNetClient",
            "SafetyNet.getClient",
        ]

        for name in file_list:
            if name.endswith(".dex"):
                try:
                    content = (
                        archive.read(name).decode("utf-8", errors="ignore")
                    )
                    for pattern in pi_patterns:
                        if pattern in content:
                            evidence.append(f"Found: {pattern}")
                except Exception:
                    pass

        if evidence:
            return {
                "type": "play_integrity",
                "detected": True,
                "evidence": evidence[:10],
                "confidence": "high",
                "methods": ["play_integrity_api", "safetynet_api"],
            }
        return None

    # =========================================================================
    # Bypass Verification
    # =========================================================================

    async def verify_bypass(
        self,
        device: Device,
        package_name: str,
        detection_type: str,
    ) -> dict[str, Any]:
        """Verify whether a bypass was actually successful.

        Injects a verification probe script that re-triggers the same
        detection path. If detection still fires, the bypass failed.

        Returns:
            Dict with ``verified`` (bool), ``output``, and ``details``.
        """
        probe_script = BYPASS_VERIFICATION_PROBES.get(detection_type)
        if not probe_script:
            return {"verified": False, "output": "", "details": "No verification probe available"}

        session_id = None
        try:
            session_id = await self.frida.inject(
                device_id=device.device_id,
                package_name=package_name,
                script_content=probe_script,
                spawn=False,
            )
            await asyncio.sleep(2)
            messages = await self.frida.get_session_messages(session_id)

            output_lines = []
            verified = False
            for msg in messages:
                payload = str(msg.get("payload", ""))
                if payload:
                    output_lines.append(payload)
                    if "[VERIFY_PASS]" in payload:
                        verified = True
                    elif "[VERIFY_FAIL]" in payload:
                        verified = False

            return {
                "verified": verified,
                "output": "\n".join(output_lines),
                "details": "Bypass verified" if verified else "Bypass not confirmed",
            }

        except Exception as e:
            return {"verified": False, "output": "", "details": f"Verification failed: {e}"}
        finally:
            if session_id:
                try:
                    await self.frida.detach(session_id)
                except Exception:
                    pass

    # =========================================================================
    # Script Selection
    # =========================================================================

    async def _find_bypass_scripts(
        self,
        detection_type: str,
        platform: str,
        db: AsyncSession,
    ) -> list[FridaScript]:
        """Find bypass scripts from the database for a given detection type.

        Queries by subcategory first (exact match), then falls back to
        name-keyword search. Results are ordered so that builtin scripts
        come first, followed by user-created scripts. Within each group,
        scripts with 'advanced' in the name come last (try simpler/generic
        scripts first).
        """
        mapping = DETECTION_TO_SCRIPT_MAP.get(detection_type)
        if not mapping:
            logger.warning(
                f"No script mapping for detection type: {detection_type}"
            )
            return []

        subcategory = mapping["subcategory"]

        # Primary query: match by category='bypass' and subcategory
        query = (
            select(FridaScript)
            .where(FridaScript.category == "bypass")
            .where(FridaScript.subcategory == subcategory)
            .where(FridaScript.platforms.contains([platform]))
            .order_by(
                FridaScript.is_builtin.desc(),
                FridaScript.script_name,
            )
        )

        result = await db.execute(query)
        scripts = list(result.scalars().all())

        # If no scripts found by subcategory, fall back to name-keyword search
        if not scripts:
            keywords = mapping.get("name_keywords", [])
            for keyword in keywords:
                fallback_query = (
                    select(FridaScript)
                    .where(FridaScript.category == "bypass")
                    .where(FridaScript.script_name.ilike(f"%{keyword}%"))
                    .where(FridaScript.platforms.contains([platform]))
                    .order_by(FridaScript.is_builtin.desc())
                )
                fallback_result = await db.execute(fallback_query)
                fallback_scripts = list(fallback_result.scalars().all())
                if fallback_scripts:
                    scripts = fallback_scripts
                    break

        # Sort so that generic/simple scripts come before advanced ones
        # (try the simpler approach first)
        def sort_key(s: FridaScript) -> tuple[int, int]:
            name_lower = s.script_name.lower()
            is_advanced = 1 if "advanced" in name_lower else 0
            is_builtin = 0 if s.is_builtin else 1  # builtin first
            return (is_builtin, is_advanced)

        scripts.sort(key=sort_key)
        return scripts

    # =========================================================================
    # Bypass Attempt
    # =========================================================================

    async def attempt_bypass(
        self,
        app: MobileApp,
        device: Device,
        detection_type: str,
        script: FridaScript | None = None,
        db: AsyncSession | None = None,
    ) -> dict[str, Any]:
        """Attempt to bypass a specific protection.

        If a specific script is provided, it will be used directly. Otherwise,
        the orchestrator queries the database for matching bypass scripts and
        tries them in order (generic first, then advanced) until one succeeds.

        Returns a result dict with: detection_type, status, notes, poc_evidence,
        techniques_tried, recommendations, detection_method, detection_library.
        """
        result: dict[str, Any] = {
            "detection_type": detection_type,
            "status": "not_attempted",
            "notes": "",
            "poc_evidence": "",
            "techniques_tried": [],
            "recommendations": [],
            "detection_method": None,
            "detection_library": None,
            "verified": False,
        }

        # Play Integrity / SafetyNet is server-side — no bypass attempted
        if detection_type == "play_integrity":
            result["status"] = "informational"
            result["notes"] = (
                "Play Integrity / SafetyNet attestation detected. This is a server-side "
                "attestation mechanism that cannot be bypassed client-side. Options: "
                "(1) Test on a non-rooted device with no Frida modifications, "
                "(2) Use Gadget injection instead of frida-server, "
                "(3) Accept this limitation and document it in the report."
            )
            result["recommendations"] = [
                "Test on a non-rooted physical device for full attestation pass",
                "Use Frida Gadget injection to avoid frida-server detection",
                "Consider using Magisk + Shamiko to hide root from Play Integrity",
                "Document that server-side attestation limits dynamic testing scope",
            ]
            return result

        # Build the list of scripts to try
        scripts_to_try: list[FridaScript] = []
        if script:
            scripts_to_try = [script]
        elif db:
            scripts_to_try = await self._find_bypass_scripts(
                detection_type, app.platform, db
            )

        if not scripts_to_try:
            # No database scripts found, try the built-in fallback
            fallback_content = await self._get_default_bypass_script(detection_type)
            if fallback_content:
                logger.info(
                    f"No DB scripts for {detection_type}, using hardcoded fallback"
                )
                try:
                    attempt = await self._inject_and_evaluate(
                        device=device,
                        package_name=app.package_name,
                        script_content=fallback_content,
                        script_name="built-in fallback",
                    )
                    result["techniques_tried"].append(attempt)
                    if attempt["success"]:
                        result["status"] = "success"
                        result["notes"] = attempt["notes"]
                        result["poc_evidence"] = attempt["output"]
                    else:
                        result["status"] = "failed"
                        result["notes"] = attempt["notes"]
                except Exception as e:
                    result["status"] = "failed"
                    result["notes"] = f"Fallback injection failed: {str(e)}"
            else:
                result["status"] = "failed"
                result["notes"] = (
                    f"No bypass scripts available for detection type '{detection_type}'. "
                    "Upload a script or ensure builtin scripts are seeded."
                )
                result["recommendations"] = [
                    "Check that the frida_scripts table has been seeded with builtin bypass scripts",
                    "You can import scripts via the /api/frida/scripts/import endpoint",
                ]

            # Generate recommendations for the fallback case
            if not result["recommendations"]:
                result["recommendations"] = _get_recommendations(
                    detection_type, result["status"] != "success", []
                )
            return result

        # Try each script in order, stop on first success
        overall_success = False
        all_output_lines: list[str] = []

        for candidate_script in scripts_to_try:
            logger.info(
                f"Trying bypass script '{candidate_script.script_name}' "
                f"for {detection_type} on {app.package_name}"
            )

            try:
                attempt = await self._inject_and_evaluate(
                    device=device,
                    package_name=app.package_name,
                    script_content=candidate_script.script_content,
                    script_name=candidate_script.script_name,
                )
                attempt["script_id"] = str(candidate_script.script_id)
                result["techniques_tried"].append(attempt)
                all_output_lines.append(
                    f"--- {candidate_script.script_name} ---\n{attempt['output']}"
                )

                if attempt["success"]:
                    # Verify bypass success with probe script
                    verification = await self.verify_bypass(
                        device=device,
                        package_name=app.package_name,
                        detection_type=detection_type,
                    )
                    attempt["verified"] = verification["verified"]

                    if verification["verified"] or detection_type not in BYPASS_VERIFICATION_PROBES:
                        overall_success = True
                        result["status"] = "success"
                        result["verified"] = True
                        result["notes"] = (
                            f"Bypass verified using '{candidate_script.script_name}'"
                        )
                        result["poc_evidence"] = "\n".join(all_output_lines)
                        result["detection_library"] = candidate_script.subcategory
                        break
                    else:
                        logger.info(
                            f"Script '{candidate_script.script_name}' markers suggest success "
                            "but verification probe failed, trying next script..."
                        )
                else:
                    logger.info(
                        f"Script '{candidate_script.script_name}' did not produce "
                        "success markers, trying next script..."
                    )

            except Exception as e:
                logger.warning(
                    f"Script '{candidate_script.script_name}' failed with error: {e}"
                )
                result["techniques_tried"].append({
                    "script_name": candidate_script.script_name,
                    "script_id": str(candidate_script.script_id),
                    "success": False,
                    "error": str(e),
                    "output": "",
                    "notes": f"Injection error: {str(e)}",
                })

        if not overall_success:
            result["status"] = "failed"
            result["poc_evidence"] = "\n".join(all_output_lines)
            tried_names = [
                t.get("script_name", "unknown") for t in result["techniques_tried"]
            ]
            result["notes"] = (
                f"All {len(tried_names)} bypass scripts failed for {detection_type}. "
                f"Tried: {', '.join(tried_names)}"
            )

        # Generate recommendations
        evidence = []
        for t in result["techniques_tried"]:
            if t.get("output"):
                evidence.append({"marker": "-", "detail": t["output"][:200]})
        result["recommendations"] = _get_recommendations(
            detection_type, not overall_success, evidence
        )

        return result

    async def _inject_and_evaluate(
        self,
        device: Device,
        package_name: str,
        script_content: str,
        script_name: str,
    ) -> dict[str, Any]:
        """Inject a single script and evaluate success/failure from output markers.

        Returns a dict with: script_name, success, output, notes, success_count,
        failure_count.
        """
        session_id = None
        try:
            session_id = await self.frida.inject(
                device_id=device.device_id,
                package_name=package_name,
                script_content=script_content,
                spawn=True,
            )

            # Give the script time to execute hooks and produce output.
            # Bypass scripts run inside Java.perform which is synchronous,
            # but the hooked methods fire asynchronously as the app runs.
            await asyncio.sleep(4)

            messages = await self.frida.get_session_messages(session_id)

            # Count markers
            success_count = 0
            failure_count = 0
            info_count = 0
            output_lines: list[str] = []

            for msg in messages:
                payload = str(msg.get("payload", ""))
                if not payload:
                    # Also capture error messages from the Frida runtime
                    if msg.get("type") == "error":
                        desc = msg.get("description", "")
                        output_lines.append(f"[ERROR] {desc}")
                        failure_count += 1
                    continue

                output_lines.append(payload)
                if "[+]" in payload:
                    success_count += 1
                elif "[-]" in payload:
                    failure_count += 1
                elif "[*]" in payload:
                    info_count += 1

            output_text = "\n".join(output_lines[:50])  # Cap output length

            # Determine success: at least one [+] marker and more successes
            # than failures
            is_success = success_count > 0 and success_count >= failure_count

            notes = (
                f"Script '{script_name}': {success_count} success, "
                f"{failure_count} failure, {info_count} info markers"
            )

            return {
                "script_name": script_name,
                "success": is_success,
                "output": output_text,
                "notes": notes,
                "success_count": success_count,
                "failure_count": failure_count,
            }

        except Exception:
            raise
        finally:
            if session_id:
                try:
                    await self.frida.detach(session_id)
                except Exception:
                    pass

    async def _get_default_bypass_script(self, detection_type: str) -> str | None:
        """Get a minimal hardcoded fallback bypass script for a detection type.

        These are only used when the database has no seeded scripts (e.g., fresh
        install before init.sql runs). They cover the most common cases.
        """
        scripts: dict[str, str] = {
            "frida": (
                "// Minimal anti-Frida bypass\n"
                "Java.perform(function() {\n"
                "    try {\n"
                "        var File = Java.use('java.io.File');\n"
                "        File.exists.implementation = function() {\n"
                "            var path = this.getAbsolutePath();\n"
                "            if (path.indexOf('frida') !== -1) {\n"
                "                console.log('[+] Hiding Frida file: ' + path);\n"
                "                return false;\n"
                "            }\n"
                "            return this.exists.call(this);\n"
                "        };\n"
                "    } catch(e) { console.log('[-] Anti-Frida bypass failed: ' + e); }\n"
                "});\n"
            ),
            "root": (
                "// Minimal root detection bypass\n"
                "Java.perform(function() {\n"
                "    try {\n"
                "        var File = Java.use('java.io.File');\n"
                "        File.exists.implementation = function() {\n"
                "            var path = this.getAbsolutePath();\n"
                "            if (path.indexOf('su') !== -1 || "
                "path.indexOf('Superuser') !== -1 || "
                "path.indexOf('magisk') !== -1) {\n"
                "                console.log('[+] Root file hidden: ' + path);\n"
                "                return false;\n"
                "            }\n"
                "            return this.exists.call(this);\n"
                "        };\n"
                "    } catch(e) { console.log('[-] Root bypass failed: ' + e); }\n"
                "});\n"
            ),
            "ssl_pinning": (
                "// Minimal SSL pinning bypass\n"
                "Java.perform(function() {\n"
                "    try {\n"
                "        var CertificatePinner = Java.use('okhttp3.CertificatePinner');\n"
                "        CertificatePinner.check.overload("
                "'java.lang.String', 'java.util.List'"
                ").implementation = function(hostname, peerCertificates) {\n"
                "            console.log('[+] OkHttp CertificatePinner.check() "
                "bypassed for: ' + hostname);\n"
                "            return;\n"
                "        };\n"
                "    } catch(e) { console.log('[-] SSL pinning bypass failed: ' + e); }\n"
                "});\n"
            ),
            "jailbreak": (
                "// Minimal jailbreak detection bypass (iOS)\n"
                "if (ObjC.available) {\n"
                "    var jbPaths = ['/Applications/Cydia.app', "
                "'/bin/bash', '/usr/sbin/sshd'];\n"
                "    var NSFileManager = ObjC.classes.NSFileManager;\n"
                "    Interceptor.attach("
                "NSFileManager['- fileExistsAtPath:'].implementation, {\n"
                "        onEnter: function(args) { "
                "this.path = ObjC.Object(args[2]).toString(); },\n"
                "        onLeave: function(retval) {\n"
                "            for (var i = 0; i < jbPaths.length; i++) {\n"
                "                if (this.path.indexOf(jbPaths[i]) !== -1) {\n"
                "                    console.log('[+] Hiding jailbreak file: ' "
                "+ this.path);\n"
                "                    retval.replace(0);\n"
                "                    return;\n"
                "                }\n"
                "            }\n"
                "        }\n"
                "    });\n"
                "}\n"
            ),
            "emulator": (
                "// Emulator detection bypass — spoof Build properties\n"
                "Java.perform(function() {\n"
                "    try {\n"
                "        var Build = Java.use('android.os.Build');\n"
                "        Build.FINGERPRINT.value = 'google/oriole/oriole:13/TP1A.221005.002/9012345:user/release-keys';\n"
                "        Build.MODEL.value = 'Pixel 6';\n"
                "        Build.MANUFACTURER.value = 'Google';\n"
                "        Build.BRAND.value = 'google';\n"
                "        Build.DEVICE.value = 'oriole';\n"
                "        Build.PRODUCT.value = 'oriole';\n"
                "        Build.HARDWARE.value = 'oriole';\n"
                "        Build.BOARD.value = 'oriole';\n"
                "        console.log('[+] Build properties spoofed to Pixel 6');\n"
                "    } catch(e) { console.log('[-] Build property spoof failed: ' + e); }\n"
                "    try {\n"
                "        var TelephonyManager = Java.use('android.telephony.TelephonyManager');\n"
                "        TelephonyManager.getDeviceId.overload().implementation = function() {\n"
                "            console.log('[+] TelephonyManager.getDeviceId() spoofed');\n"
                "            return '358240051111110';\n"
                "        };\n"
                "    } catch(e) {}\n"
                "});\n"
            ),
            "tamper": (
                "// Tamper/integrity detection bypass — signature check\n"
                "Java.perform(function() {\n"
                "    try {\n"
                "        var PackageManager = Java.use('android.app.ApplicationPackageManager');\n"
                "        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkg, flags) {\n"
                "            var info = this.getPackageInfo(pkg, flags);\n"
                "            console.log('[+] PackageManager.getPackageInfo intercepted for: ' + pkg);\n"
                "            return info;\n"
                "        };\n"
                "    } catch(e) { console.log('[-] Tamper bypass failed: ' + e); }\n"
                "    try {\n"
                "        var ApplicationInfo = Java.use('android.content.pm.ApplicationInfo');\n"
                "        var flagField = ApplicationInfo.class.getDeclaredField('flags');\n"
                "        console.log('[*] ApplicationInfo.flags field accessible');\n"
                "    } catch(e) {}\n"
                "});\n"
            ),
            "biometric": (
                "// Biometric authentication bypass\n"
                "Java.perform(function() {\n"
                "    try {\n"
                "        var BiometricPrompt = Java.use('android.hardware.biometrics.BiometricPrompt');\n"
                "        BiometricPrompt.authenticate.overload("
                "'android.hardware.biometrics.BiometricPrompt$CryptoObject', "
                "'android.os.CancellationSignal', "
                "'java.util.concurrent.Executor', "
                "'android.hardware.biometrics.BiometricPrompt$AuthenticationCallback').implementation = function(crypto, cancel, executor, callback) {\n"
                "            console.log('[+] BiometricPrompt.authenticate intercepted');\n"
                "            var AuthResult = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationResult');\n"
                "            callback.onAuthenticationSucceeded(AuthResult.$new(crypto));\n"
                "        };\n"
                "    } catch(e) { console.log('[-] Biometric bypass failed: ' + e); }\n"
                "});\n"
            ),
            "play_integrity": None,  # No bypass — informational only
        }
        return scripts.get(detection_type)

    # =========================================================================
    # Auto-Bypass (Full Pipeline)
    # =========================================================================

    async def auto_bypass(
        self,
        app: MobileApp,
        device: Device,
        db: AsyncSession,
    ) -> list[dict[str, Any]]:
        """Automatically detect and bypass all protections.

        Performs a multi-phase approach:
        1. Static analysis via analyze_protections() to find protections in the
           binary.
        2. Runtime analysis via analyze_protections_runtime() to probe live
           classes on the device.
        3. For each detected protection, attempts bypass using database scripts
           (trying multiple scripts per type, generic before advanced).
        4. Saves all results to the bypass_results table.
        """
        results: list[dict[str, Any]] = []

        # Phase 1: Static analysis
        static_detections = await self.analyze_protections(app)

        # Phase 2: Runtime analysis (best-effort; if Frida fails, continue
        # with static results only)
        runtime_detections: list[dict[str, Any]] = []
        try:
            runtime_detections = await self.analyze_protections_runtime(app, device)
        except Exception as e:
            logger.warning(
                f"Runtime analysis failed, continuing with static results: {e}"
            )

        # Merge detections: combine static and runtime into a unified list.
        # Use detection type as the key. If both sources detected a type,
        # merge their evidence lists and take the higher confidence.
        merged: dict[str, dict[str, Any]] = {}

        for det in static_detections:
            det_type = det["type"]
            det["source"] = det.get("source", "static")
            merged[det_type] = det

        for det in runtime_detections:
            det_type = det["type"]
            if det_type == "error":
                continue
            if det_type in merged:
                existing = merged[det_type]
                existing_evidence = existing.get("evidence", [])
                new_evidence = det.get("evidence", [])
                existing["evidence"] = (existing_evidence + new_evidence)[:15]
                existing_methods = set(existing.get("methods", []))
                new_methods = set(det.get("methods", []))
                existing["methods"] = list(existing_methods | new_methods)
                confidence_order = {
                    "none": 0,
                    "low": 1,
                    "medium": 2,
                    "high": 3,
                }
                if confidence_order.get(
                    det.get("confidence", "none"), 0
                ) > confidence_order.get(existing.get("confidence", "none"), 0):
                    existing["confidence"] = det["confidence"]
                existing["detected"] = existing.get("detected", False) or det.get(
                    "detected", False
                )
                existing["source"] = "static+runtime"
            else:
                merged[det_type] = det

        all_detections = list(merged.values())

        # Attempt bypass for each detected protection
        for detection in all_detections:
            if not detection.get("detected", False):
                continue

            det_type = detection["type"]
            logger.info(
                f"Auto-bypass: attempting bypass for {det_type} "
                f"(confidence: {detection.get('confidence', 'unknown')})"
            )

            bypass_result = await self.attempt_bypass(
                app=app,
                device=device,
                detection_type=det_type,
                db=db,
            )
            bypass_result["detection"] = detection
            results.append(bypass_result)

            # Determine which script was successful (if any) for the DB record
            bypass_script_id = None
            for technique in bypass_result.get("techniques_tried", []):
                if technique.get("success") and technique.get("script_id"):
                    bypass_script_id = technique["script_id"]
                    break

            # Save result to database
            try:
                db_result = BypassResult(
                    app_id=app.app_id,
                    device_id=device.device_id,
                    detection_type=det_type,
                    detection_method=",".join(detection.get("methods", [])),
                    detection_library=bypass_result.get("detection_library"),
                    detection_signature=",".join(
                        detection.get("evidence", [])[:3]
                    ),
                    bypass_script_id=bypass_script_id,
                    bypass_status=bypass_result["status"],
                    bypass_notes=bypass_result["notes"],
                    poc_evidence=bypass_result.get("poc_evidence", "")[:4000],
                )
                db.add(db_result)
            except Exception as e:
                logger.error(
                    f"Failed to save bypass result for {det_type}: {e}"
                )

        try:
            await db.commit()
        except Exception as e:
            logger.error(f"Failed to commit bypass results: {e}")
            await db.rollback()

        return results
