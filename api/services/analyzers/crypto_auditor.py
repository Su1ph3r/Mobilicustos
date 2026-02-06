"""Cryptographic audit analyzer for mobile application security.

Performs comprehensive static analysis of cryptographic operations found
in decompiled mobile application source code. Detects weak algorithms,
hardcoded cryptographic keys, insecure random number generation, and
improper initialization vector (IV) usage.

Security checks performed:
    - **Weak Algorithm Detection**: Identifies deprecated or broken
      algorithms (DES, 3DES, RC2, RC4, MD5, SHA1, ECB mode) and
      insufficient RSA key sizes (< 2048 bits).
    - **Hardcoded Key Detection**: Finds cryptographic keys embedded
      as hex strings, Base64 strings, or byte array literals.
    - **Insecure Random Number Generation**: Detects use of
      java.util.Random, Math.random(), and other non-cryptographic
      PRNGs in security-sensitive contexts.
    - **IV/Nonce Issues**: Identifies static or zero-value IVs in
      symmetric encryption operations (IvParameterSpec, GCMParameterSpec).

OWASP references:
    - MASVS-CRYPTO: Cryptography Requirements
    - MSTG-CRYPTO-1 through MSTG-CRYPTO-6
    - CWE-327: Use of a Broken or Risky Cryptographic Algorithm
    - CWE-321: Use of Hard-coded Cryptographic Key
    - CWE-330: Use of Insufficiently Random Values
    - CWE-329: Generation of Predictable IV with CBC Mode

Platform support:
    - Android: javax.crypto, java.security, Android KeyStore patterns
    - iOS: CommonCrypto, Security.framework, CryptoKit patterns
    - Cross-platform: JavaScript/TypeScript, Dart (Flutter) patterns
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult

logger = logging.getLogger(__name__)


@dataclass
class CryptoOperation:
    """Represents a cryptographic operation found in code."""
    operation_type: str  # encryption, hashing, signing, key_generation
    algorithm: str
    file_path: str
    line_number: int | None
    code_snippet: str
    is_weak: bool = False
    weakness_reason: str | None = None
    key_size: int | None = None


# Weak/Deprecated algorithms
WEAK_ALGORITHMS = {
    # Symmetric encryption
    "DES": {"severity": "high", "reason": "56-bit key is trivially breakable"},
    "3DES": {"severity": "medium", "reason": "Deprecated, vulnerable to Sweet32 attack"},
    "RC2": {"severity": "high", "reason": "Deprecated, known vulnerabilities"},
    "RC4": {"severity": "high", "reason": "Multiple vulnerabilities, prohibited in TLS"},
    "Blowfish": {"severity": "low", "reason": "64-bit block size, prefer AES"},

    # Hashing
    "MD2": {"severity": "high", "reason": "Cryptographically broken"},
    "MD4": {"severity": "high", "reason": "Cryptographically broken"},
    "MD5": {"severity": "high", "reason": "Collision attacks practical, not for security"},
    "SHA1": {"severity": "medium", "reason": "Collision attacks demonstrated, deprecated"},

    # Asymmetric (weak key sizes)
    "RSA-512": {"severity": "critical", "reason": "Can be factored in hours"},
    "RSA-768": {"severity": "critical", "reason": "Can be factored with sufficient resources"},
    "RSA-1024": {"severity": "high", "reason": "Below recommended minimum of 2048 bits"},

    # Modes
    "ECB": {"severity": "high", "reason": "Deterministic encryption, reveals patterns"},
}

# Algorithm detection patterns
CRYPTO_PATTERNS = {
    "android": {
        "cipher_getInstance": [
            r'Cipher\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ],
        "messagedigest": [
            r'MessageDigest\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ],
        "mac": [
            r'Mac\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ],
        "signature": [
            r'Signature\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ],
        "keygenerator": [
            r'KeyGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ],
        "keypairgenerator": [
            r'KeyPairGenerator\.getInstance\s*\(\s*["\']([^"\']+)["\']',
        ],
        "secretkeyspec": [
            r'SecretKeySpec\s*\([^,]+,\s*["\']([^"\']+)["\']',
        ],
    },
    "ios": {
        "commoncrypto": [
            r'kCCAlgorithm(\w+)',
            r'CCCrypt\s*\([^,]*,\s*kCCAlgorithm(\w+)',
        ],
        "security_framework": [
            r'SecKey\w+\s*\([^)]*algorithm:\s*\.(\w+)',
            r'kSecAttrKeyType(\w+)',
        ],
        "cryptokit": [
            r'AES\.GCM',
            r'ChaChaPoly',
            r'SHA256',
            r'SHA384',
            r'SHA512',
            r'P256',
            r'P384',
            r'P521',
        ],
    },
}

# Hardcoded key patterns
HARDCODED_KEY_PATTERNS = [
    # Hex keys
    r'(?:key|secret|password|iv|salt)\s*[:=]\s*["\']([0-9a-fA-F]{16,})["\']',
    # Base64 keys
    r'(?:key|secret|aes|des)\s*[:=]\s*["\']([A-Za-z0-9+/]{16,}={0,2})["\']',
    # Byte arrays
    r'(?:byte|Byte)\[\]\s+(?:key|secret|iv)\s*=\s*\{([^}]+)\}',
    r'new\s+byte\[\]\s*\{([^}]+)\}',
    # String to bytes
    r'\.getBytes\s*\(\s*\)\s*.*(?:key|secret|iv)',
]

# Insecure random patterns
INSECURE_RANDOM_PATTERNS = [
    r'java\.util\.Random\b',
    r'Math\.random\s*\(',
    r'arc4random\s*\(',  # iOS - actually secure, but check context
    r'rand\s*\(\s*\)',
    r'random\s*\(\s*\)',
]

# IV/Nonce issues
IV_PATTERNS = [
    # Static/hardcoded IV
    r'IvParameterSpec\s*\(\s*["\']',
    r'IvParameterSpec\s*\(\s*new\s+byte\[\]\s*\{[^}]+\}',
    # Zero IV
    r'new\s+byte\[16\]',  # Uninitialized = zeros
]


class CryptoAuditor(BaseAnalyzer):
    """Audits cryptographic implementations for security vulnerabilities.

    Extracts the application archive, scans all source files for
    cryptographic API usage, evaluates algorithm strength, detects
    hardcoded key material, identifies insecure random number generators,
    and checks for static or predictable initialization vectors.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        description: Human-readable description of analyzer purpose.
    """

    name = "crypto_auditor"
    description = "Analyzes cryptographic operations for weak algorithms and implementation issues"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze cryptographic operations in the application.

        Extracts the application archive to a temporary directory, scans
        source files for cryptographic API calls, evaluates each operation
        against known-weak algorithms and implementation anti-patterns, and
        produces categorized findings.

        Args:
            app: The mobile application to analyze, with file_path pointing
                to the APK or IPA archive.

        Returns:
            A list of Finding objects covering weak algorithms, hardcoded
            keys, insecure random usage, IV/nonce issues, and a summary
            of all detected cryptographic operations.
        """
        if not app.file_path:
            return []

        import shutil
        import tempfile
        import zipfile

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="crypto_audit_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            results = []
            operations: list[CryptoOperation] = []
            hardcoded_keys = []
            insecure_random = []
            iv_issues = []

            # Determine source extensions based on platform
            if app.platform == "android":
                extensions = [".java", ".kt", ".smali"]
                patterns = CRYPTO_PATTERNS["android"]
            else:
                extensions = [".swift", ".m", ".mm", ".h"]
                patterns = CRYPTO_PATTERNS["ios"]

            # Add common extensions
            extensions.extend([".js", ".ts", ".dart"])

            for ext in extensions:
                for source_file in extracted_path.rglob(f"*{ext}"):
                    try:
                        content = source_file.read_text(errors='ignore')
                        rel_path = str(source_file.relative_to(extracted_path))

                        # Find crypto operations
                        for op_type, op_patterns in patterns.items():
                            for pattern in op_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    algo = match.group(1) if match.lastindex else match.group(0)
                                    line_num = content[:match.start()].count('\n') + 1
                                    snippet = self._extract_snippet(content, match.start())

                                    op = CryptoOperation(
                                        operation_type=op_type,
                                        algorithm=algo,
                                        file_path=rel_path,
                                        line_number=line_num,
                                        code_snippet=snippet,
                                    )
                                    self._check_weakness(op)
                                    operations.append(op)

                        # Check for hardcoded keys
                        for pattern in HARDCODED_KEY_PATTERNS:
                            matches = re.finditer(pattern, content, re.IGNORECASE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                hardcoded_keys.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "snippet": self._extract_snippet(content, match.start()),
                                })

                        # Check for insecure random
                        for pattern in INSECURE_RANDOM_PATTERNS:
                            if re.search(pattern, content):
                                matches = re.finditer(pattern, content)
                                for match in matches:
                                    line_num = content[:match.start()].count('\n') + 1
                                    insecure_random.append({
                                        "file": rel_path,
                                        "line": line_num,
                                        "pattern": match.group(0),
                                    })

                        # Check for IV issues
                        for pattern in IV_PATTERNS:
                            matches = re.finditer(pattern, content)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                iv_issues.append({
                                    "file": rel_path,
                                    "line": line_num,
                                    "snippet": self._extract_snippet(content, match.start()),
                                })

                    except Exception as e:
                        logger.debug(f"Error analyzing {source_file}: {e}")

            # Create findings
            weak_ops = [op for op in operations if op.is_weak]
            if weak_ops:
                results.extend(self._create_weak_algorithm_findings(weak_ops, app))

            if hardcoded_keys:
                results.append(self._create_hardcoded_key_finding(hardcoded_keys, app))

            if insecure_random:
                results.append(self._create_insecure_random_finding(insecure_random, app))

            if iv_issues:
                results.append(self._create_iv_finding(iv_issues, app))

            # Summary finding
            if operations:
                results.append(self._create_summary_finding(operations, app))

            # Convert AnalyzerResults to Findings
            findings = []
            for result in results:
                findings.append(self.result_to_finding(app, result))

            return findings

        except Exception as e:
            logger.error(f"Crypto audit failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    def _extract_snippet(self, content: str, position: int, context_lines: int = 2) -> str:
        """Extract a code snippet with surrounding context lines.

        Args:
            content: Full file content to extract from.
            position: Character offset of the match in the content.
            context_lines: Number of lines to include above and below
                the matched line. Defaults to 2.

        Returns:
            A string containing the matched line plus surrounding
            context lines.
        """
        lines = content.split('\n')
        line_num = content[:position].count('\n')

        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)

        return '\n'.join(lines[start:end])

    def _check_weakness(self, op: CryptoOperation):
        """Check if a crypto operation uses weak algorithms and mark it.

        Evaluates the operation's algorithm against the WEAK_ALGORITHMS
        lookup table, checks for ECB mode usage, and inspects RSA key
        sizes extracted from surrounding code context. Sets is_weak and
        weakness_reason on the CryptoOperation in-place.

        Args:
            op: The CryptoOperation dataclass to evaluate and mutate.
        """
        algo_upper = op.algorithm.upper()

        # Check direct matches
        for weak_algo, info in WEAK_ALGORITHMS.items():
            if weak_algo.upper() in algo_upper:
                op.is_weak = True
                op.weakness_reason = info["reason"]
                return

        # Check for ECB mode
        if "/ECB/" in algo_upper or algo_upper.endswith("/ECB"):
            op.is_weak = True
            op.weakness_reason = WEAK_ALGORITHMS["ECB"]["reason"]
            return

        # Check for weak RSA key sizes
        if "RSA" in algo_upper:
            # Try to extract key size from context
            key_size_match = re.search(r'(\d{3,4})', op.code_snippet)
            if key_size_match:
                key_size = int(key_size_match.group(1))
                op.key_size = key_size
                if key_size < 2048:
                    op.is_weak = True
                    op.weakness_reason = f"RSA key size {key_size} is below recommended 2048 bits"

    def _create_weak_algorithm_findings(
        self,
        operations: list[CryptoOperation],
        app: MobileApp
    ) -> list[AnalyzerResult]:
        """Create findings for weak cryptographic algorithms.

        Groups weak operations by their base algorithm name and produces
        one AnalyzerResult per unique algorithm, including occurrence
        counts, file locations, and OWASP/CWE classification.

        Args:
            operations: List of CryptoOperation instances flagged as weak.
            app: The mobile application being analyzed.

        Returns:
            A list of AnalyzerResult instances, one per weak algorithm.
        """
        results = []

        # Group by algorithm
        by_algo = {}
        for op in operations:
            algo_key = op.algorithm.split('/')[0].upper()
            if algo_key not in by_algo:
                by_algo[algo_key] = []
            by_algo[algo_key].append(op)

        for algo, ops in by_algo.items():
            # Determine severity
            severity = "medium"
            for weak_algo, info in WEAK_ALGORITHMS.items():
                if weak_algo.upper() in algo:
                    severity = info.get("severity", "medium")
                    break

            locations = "\n".join([
                f"- {op.file_path}:{op.line_number or '?'}"
                for op in ops[:5]
            ])

            reason = ops[0].weakness_reason or "Algorithm has known weaknesses"

            results.append(AnalyzerResult(
                title=f"Weak Cryptographic Algorithm: {algo}",
                description=f"The application uses the weak cryptographic algorithm {algo}.\n\n**Reason:** {reason}\n\n**Found in:**\n{locations}",
                severity=severity,
                category="Cryptography",
                impact="Using weak cryptographic algorithms can lead to data exposure, forgery, or complete compromise of encrypted data.",
                remediation=self._get_remediation(algo),
                file_path=ops[0].file_path,
                line_number=ops[0].line_number,
                code_snippet=ops[0].code_snippet,
                cwe_id="CWE-327",
                cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                owasp_masvs_category="MASVS-CRYPTO",
                owasp_masvs_control="MSTG-CRYPTO-4",
                poc_verification=f"1. Search codebase for {algo}\n2. Review usage context\n3. Verify if used for security-sensitive operations",
                metadata={
                    "algorithm": algo,
                    "occurrences": len(ops),
                    "files": list(set(op.file_path for op in ops)),
                }
            ))

        return results

    def _get_remediation(self, algorithm: str) -> str:
        """Get remediation advice for a weak algorithm.

        Args:
            algorithm: The algorithm name (e.g., "MD5", "DES", "ECB").

        Returns:
            A remediation string with recommended replacement algorithms.
        """
        algo_upper = algorithm.upper()

        if any(x in algo_upper for x in ["MD5", "MD4", "MD2", "SHA1"]):
            return "Replace with SHA-256 or SHA-3 for hashing. For password storage, use bcrypt, scrypt, or Argon2."

        if any(x in algo_upper for x in ["DES", "3DES", "RC2", "RC4"]):
            return "Replace with AES-256-GCM for encryption. Ensure proper key management and unique IVs."

        if "ECB" in algo_upper:
            return "Use CBC, CTR, or preferably GCM mode. ECB mode is deterministic and leaks information."

        if "RSA" in algo_upper:
            return "Use RSA with at least 2048-bit keys, preferably 4096-bit. Consider using ECDSA for signatures."

        return "Replace with modern, well-reviewed cryptographic algorithms. Consult NIST guidelines for recommendations."

    def _create_hardcoded_key_finding(self, keys: list[dict], app: MobileApp) -> AnalyzerResult:
        """Create a critical finding for hardcoded cryptographic key material.

        Generates a detailed AnalyzerResult including platform-specific
        PoC commands for key extraction, Frida scripts for runtime key
        interception, and remediation code samples for Android KeyStore
        and iOS Keychain.

        Args:
            keys: List of dicts with 'file', 'line', and 'snippet' keys
                indicating where hardcoded keys were found.
            app: The mobile application being analyzed.

        Returns:
            An AnalyzerResult with CWE-321 classification and detailed
            remediation guidance.
        """
        locations = "\n".join([
            f"- {k['file']}:{k['line']}"
            for k in keys[:10]
        ])

        poc_cmds = [
            {
                "type": "bash",
                "command": "jadx -d decompiled app.apk" if app.platform == "android" else "class-dump -H -o headers binary",
                "description": "Decompile application to extract source",
            },
            {
                "type": "bash",
                "command": "grep -rn 'key\\|secret\\|password\\|AES\\|DES' decompiled/",
                "description": "Search for hardcoded key material",
            },
            {
                "type": "bash",
                "command": "strings app.apk | grep -E '[A-Za-z0-9+/]{32,}' | head -20" if app.platform == "android" else "strings binary | grep -E '[A-Za-z0-9+/]{32,}'",
                "description": "Extract potential Base64-encoded keys",
            },
        ]

        frida_script = f'''// Hook crypto key initialization to extract keys
Java.perform(function() {{
    // Hook SecretKeySpec constructor
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {{
        console.log("[*] SecretKeySpec created");
        console.log("    Algorithm: " + algo);
        console.log("    Key (hex): " + bytesToHex(key));
        return this.$init(key, algo);
    }};

    function bytesToHex(bytes) {{
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {{
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }}
        return hex.join('');
    }}
}});
''' if app.platform == "android" else '''// Hook CommonCrypto key operations
Interceptor.attach(Module.findExportByName(null, 'CCCrypt'), {{
    onEnter: function(args) {{
        console.log("[*] CCCrypt called");
        console.log("    Key length: " + args[4]);
        console.log("    Key: " + hexdump(args[3], {{ length: args[4].toInt32() }}));
    }}
}});
'''

        return AnalyzerResult(
            title=f"Hardcoded Cryptographic Keys Detected ({len(keys)} instances)",
            description=f"Cryptographic keys appear to be hardcoded in the source code:\n\n{locations}",
            severity="critical",
            category="Cryptography",
            impact="Hardcoded keys can be extracted through reverse engineering, compromising all data encrypted with these keys. Attackers can decrypt sensitive data, forge signatures, or impersonate the application.",
            remediation="1. Store keys in secure storage (Android KeyStore, iOS Keychain)\n2. Use key derivation from user credentials\n3. Fetch keys from secure backend\n4. Implement proper key rotation",
            file_path=keys[0]["file"],
            line_number=keys[0]["line"],
            code_snippet=keys[0]["snippet"],
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            cvss_score=9.1,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-1",
            owasp_mastg_test="MASTG-TEST-0013",
            poc_verification="jadx -d decompiled app.apk && grep -rn 'SecretKeySpec\\|key =' decompiled/",
            poc_commands=poc_cmds,
            poc_frida_script=frida_script,
            remediation_commands=[
                {
                    "type": "android",
                    "command": "KeyGenerator keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, \"AndroidKeyStore\");",
                    "description": "Generate key in Android KeyStore instead of hardcoding",
                },
            ] if app.platform == "android" else [
                {
                    "type": "ios",
                    "command": "SecKeyCreateRandomKey(attributes, &error)",
                    "description": "Generate key in Secure Enclave instead of hardcoding",
                },
            ],
            remediation_code={
                "kotlin": '''// Use Android KeyStore
val keyGenerator = KeyGenerator.getInstance(
    KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
)
keyGenerator.init(
    KeyGenParameterSpec.Builder("my_key",
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .build()
)
val secretKey = keyGenerator.generateKey()''',
                "swift": '''// Use iOS Keychain
let attributes: [String: Any] = [
    kSecAttrKeyType as String: kSecAttrKeyTypeAES,
    kSecAttrKeySizeInBits as String: 256,
    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave
]
var error: Unmanaged<CFError>?
guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
    throw error!.takeRetainedValue() as Error
}''',
            },
            remediation_resources=[
                {
                    "title": "OWASP MASTG - Testing for Hardcoded Cryptographic Keys",
                    "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0013/",
                    "type": "documentation",
                },
                {
                    "title": "Android KeyStore System",
                    "url": "https://developer.android.com/training/articles/keystore",
                    "type": "documentation",
                },
                {
                    "title": "Apple - Storing Keys in the Keychain",
                    "url": "https://developer.apple.com/documentation/security/certificate_key_and_trust_services/keys/storing_keys_in_the_keychain",
                    "type": "documentation",
                },
            ],
            metadata={
                "instances": len(keys),
                "files": list(set(k["file"] for k in keys)),
            }
        )

    def _create_insecure_random_finding(self, instances: list[dict], app: MobileApp) -> AnalyzerResult:
        """Create a finding for insecure random number generation.

        Generates a high-severity AnalyzerResult with Frida scripts for
        hooking random functions at runtime and platform-specific
        remediation code using SecureRandom (Android) or
        SecRandomCopyBytes (iOS).

        Args:
            instances: List of dicts with 'file', 'line', and 'pattern'
                indicating insecure PRNG usage locations.
            app: The mobile application being analyzed.

        Returns:
            An AnalyzerResult with CWE-330 classification.
        """
        locations = "\n".join([
            f"- {i['file']}:{i['line']} - {i['pattern']}"
            for i in instances[:10]
        ])

        frida_script = '''// Hook insecure random calls to demonstrate predictability
Java.perform(function() {
    var Random = Java.use('java.util.Random');
    Random.nextInt.overload().implementation = function() {
        var result = this.nextInt();
        console.log("[!] java.util.Random.nextInt() called - INSECURE");
        console.log("    Result: " + result);
        console.log("    Stack: " + Java.use("android.util.Log").getStackTraceString(
            Java.use("java.lang.Exception").$new()));
        return result;
    };

    var SecureRandom = Java.use('java.security.SecureRandom');
    SecureRandom.nextInt.overload().implementation = function() {
        var result = this.nextInt();
        console.log("[+] SecureRandom.nextInt() called - SECURE");
        return result;
    };
});
''' if app.platform == "android" else '''// Hook random functions on iOS
Interceptor.attach(Module.findExportByName(null, 'arc4random'), {
    onLeave: function(retval) {
        console.log("[+] arc4random() = " + retval + " (secure)");
    }
});
Interceptor.attach(Module.findExportByName(null, 'rand'), {
    onLeave: function(retval) {
        console.log("[!] rand() = " + retval + " (INSECURE!)");
    }
});
'''

        return AnalyzerResult(
            title=f"Insecure Random Number Generator ({len(instances)} instances)",
            description=f"The application uses predictable random number generators:\n\n{locations}\n\nThese generators are not cryptographically secure and produce predictable sequences.",
            severity="high",
            category="Cryptography",
            impact="Predictable random values used for security purposes (keys, tokens, nonces) can be guessed by attackers. This can lead to session hijacking, token prediction, or weak encryption.",
            remediation="Use cryptographically secure random generators:\n- Android: SecureRandom\n- iOS: SecRandomCopyBytes\n- General: crypto.getRandomValues() in JS",
            file_path=instances[0]["file"],
            line_number=instances[0]["line"],
            cwe_id="CWE-330",
            cwe_name="Use of Insufficiently Random Values",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-6",
            owasp_mastg_test="MASTG-TEST-0016",
            poc_verification="grep -rn 'java.util.Random\\|Math.random' decompiled/",
            poc_commands=[
                {
                    "type": "bash",
                    "command": "grep -rn 'Random()\\|Math.random\\|rand()' decompiled/",
                    "description": "Search for insecure random usage in decompiled source",
                },
                {
                    "type": "frida",
                    "command": f"frida -U -f {app.package_name} -l random_hook.js",
                    "description": "Hook random functions to observe usage at runtime",
                },
            ],
            poc_frida_script=frida_script,
            remediation_commands=[
                {
                    "type": "android",
                    "command": "SecureRandom random = new SecureRandom();",
                    "description": "Replace java.util.Random with SecureRandom",
                },
            ] if app.platform == "android" else [
                {
                    "type": "ios",
                    "command": "SecRandomCopyBytes(kSecRandomDefault, count, &bytes)",
                    "description": "Use SecRandomCopyBytes for cryptographic random",
                },
            ],
            remediation_code={
                "kotlin": '''// Use SecureRandom for cryptographic operations
val secureRandom = SecureRandom()
val randomBytes = ByteArray(32)
secureRandom.nextBytes(randomBytes)''',
                "java": '''// Use SecureRandom for cryptographic operations
SecureRandom secureRandom = new SecureRandom();
byte[] randomBytes = new byte[32];
secureRandom.nextBytes(randomBytes);''',
                "swift": '''// Use SecRandomCopyBytes
var bytes = [UInt8](repeating: 0, count: 32)
let status = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
guard status == errSecSuccess else { throw CryptoError.randomGenerationFailed }''',
            },
            remediation_resources=[
                {
                    "title": "OWASP MASTG - Testing Random Number Generation",
                    "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0016/",
                    "type": "documentation",
                },
                {
                    "title": "Android SecureRandom Documentation",
                    "url": "https://developer.android.com/reference/java/security/SecureRandom",
                    "type": "documentation",
                },
            ],
            metadata={
                "instances": len(instances),
            }
        )

    def _create_iv_finding(self, issues: list[dict], app: MobileApp) -> AnalyzerResult:
        """Create a finding for initialization vector (IV) and nonce issues.

        Generates a high-severity AnalyzerResult with Frida scripts for
        monitoring IV creation at runtime and remediation code showing
        proper GCM nonce generation.

        Args:
            issues: List of dicts with 'file', 'line', and 'snippet'
                indicating static or predictable IV usage.
            app: The mobile application being analyzed.

        Returns:
            An AnalyzerResult with CWE-329 classification.
        """
        locations = "\n".join([
            f"- {i['file']}:{i['line']}"
            for i in issues[:10]
        ])

        frida_script = '''// Monitor IV/Nonce usage in encryption operations
Java.perform(function() {
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log("[*] IvParameterSpec created");
        console.log("    IV (hex): " + bytesToHex(iv));
        console.log("    IV length: " + iv.length + " bytes");

        // Check for zeros (uninitialized)
        var allZeros = true;
        for (var i = 0; i < iv.length; i++) {
            if (iv[i] !== 0) { allZeros = false; break; }
        }
        if (allZeros) {
            console.log("    [!] WARNING: IV is all zeros!");
        }

        return this.$init(iv);
    };

    var GCMParameterSpec = Java.use('javax.crypto.spec.GCMParameterSpec');
    GCMParameterSpec.$init.overload('int', '[B').implementation = function(tagLen, nonce) {
        console.log("[*] GCMParameterSpec created");
        console.log("    Nonce (hex): " + bytesToHex(nonce));
        console.log("    Tag length: " + tagLen + " bits");
        return this.$init(tagLen, nonce);
    };

    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }
});
''' if app.platform == "android" else '''// Monitor IV usage in CommonCrypto
Interceptor.attach(Module.findExportByName(null, 'CCCrypt'), {
    onEnter: function(args) {
        var ivPtr = args[5];
        if (!ivPtr.isNull()) {
            console.log("[*] CCCrypt IV:");
            console.log(hexdump(ivPtr, { length: 16 }));
        }
    }
});
'''

        return AnalyzerResult(
            title=f"Potential IV/Nonce Issues ({len(issues)} instances)",
            description=f"Potential issues with initialization vectors (IV) or nonces detected:\n\n{locations}\n\nStatic or predictable IVs compromise the security of encryption.",
            severity="high",
            category="Cryptography",
            impact="Reusing IVs or using predictable IVs can lead to plaintext recovery attacks, especially with stream ciphers and CTR mode. With GCM mode, nonce reuse completely breaks the authentication and can reveal the key.",
            remediation="1. Generate fresh random IV for each encryption operation\n2. Use SecureRandom for IV generation\n3. For GCM mode, never reuse nonce with same key\n4. Store IV with ciphertext (IV is not secret)",
            file_path=issues[0]["file"],
            line_number=issues[0]["line"],
            code_snippet=issues[0]["snippet"],
            cwe_id="CWE-329",
            cwe_name="Generation of Predictable IV with CBC Mode",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-6",
            owasp_mastg_test="MASTG-TEST-0014",
            poc_verification="grep -rn 'IvParameterSpec\\|new byte\\[16\\]' decompiled/",
            poc_commands=[
                {
                    "type": "bash",
                    "command": "grep -rn 'IvParameterSpec\\|GCMParameterSpec' decompiled/",
                    "description": "Search for IV initialization in decompiled code",
                },
                {
                    "type": "frida",
                    "command": f"frida -U -f {app.package_name} -l iv_hook.js",
                    "description": "Hook IV creation to check for reuse/predictability",
                },
            ],
            poc_frida_script=frida_script,
            remediation_commands=[
                {
                    "type": "android",
                    "command": "SecureRandom random = new SecureRandom(); byte[] iv = new byte[12]; random.nextBytes(iv);",
                    "description": "Generate random IV using SecureRandom",
                },
            ],
            remediation_code={
                "kotlin": '''// Proper IV generation for GCM
val cipher = Cipher.getInstance("AES/GCM/NoPadding")
val secureRandom = SecureRandom()
val nonce = ByteArray(12)  // 12 bytes for GCM nonce
secureRandom.nextBytes(nonce)

val gcmSpec = GCMParameterSpec(128, nonce)  // 128-bit tag
cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec)

// Store nonce with ciphertext
val ciphertext = cipher.doFinal(plaintext)
val combined = nonce + ciphertext  // Prepend nonce''',
                "swift": '''// Proper IV generation for AES-GCM
var nonce = [UInt8](repeating: 0, count: 12)
let status = SecRandomCopyBytes(kSecRandomDefault, nonce.count, &nonce)

let sealedBox = try AES.GCM.seal(
    plaintext,
    using: key,
    nonce: AES.GCM.Nonce(data: nonce)
)''',
            },
            remediation_resources=[
                {
                    "title": "OWASP MASTG - Testing for Weak IVs",
                    "url": "https://mas.owasp.org/MASTG/tests/android/MASVS-CRYPTO/MASTG-TEST-0014/",
                    "type": "documentation",
                },
                {
                    "title": "NIST SP 800-38D - GCM Mode",
                    "url": "https://csrc.nist.gov/publications/detail/sp/800-38d/final",
                    "type": "documentation",
                },
            ],
            metadata={
                "instances": len(issues),
            }
        )

    def _create_summary_finding(self, operations: list[CryptoOperation], app: MobileApp) -> AnalyzerResult:
        """Create an informational summary of all detected crypto operations.

        Aggregates operations by type, counts weak vs. strong algorithms,
        and lists all unique algorithms found.

        Args:
            operations: All detected CryptoOperation instances.
            app: The mobile application being analyzed.

        Returns:
            An info-severity AnalyzerResult summarizing the cryptographic
            landscape of the application.
        """
        # Count by type
        by_type = {}
        for op in operations:
            if op.operation_type not in by_type:
                by_type[op.operation_type] = 0
            by_type[op.operation_type] += 1

        # Count weak vs strong
        weak_count = len([op for op in operations if op.is_weak])
        strong_count = len(operations) - weak_count

        type_summary = "\n".join([f"- {t}: {c} operations" for t, c in by_type.items()])

        # Unique algorithms
        algorithms = list(set(op.algorithm for op in operations))

        return AnalyzerResult(
            title=f"Cryptographic Operations Summary ({len(operations)} total)",
            description=f"**Operations by type:**\n{type_summary}\n\n**Algorithms used:** {', '.join(algorithms[:10])}\n\n**Weak algorithms:** {weak_count}\n**Strong algorithms:** {strong_count}",
            severity="info",
            category="Cryptography",
            impact="Review all cryptographic operations to ensure proper implementation.",
            remediation="Ensure all crypto operations use modern algorithms with proper parameters.",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-1",
            metadata={
                "total_operations": len(operations),
                "weak_count": weak_count,
                "strong_count": strong_count,
                "algorithms": algorithms,
                "by_type": by_type,
            }
        )
