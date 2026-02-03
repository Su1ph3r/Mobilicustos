"""Cryptographic Audit Analyzer.

Comprehensive analysis of cryptographic operations including
weak algorithms, hardcoded keys, improper IV usage, and more.
"""

import logging
import re
from dataclasses import dataclass
from pathlib import Path

from api.models.database import MobileApp
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
    """Audits cryptographic implementations for security issues."""

    name = "crypto_auditor"
    description = "Analyzes cryptographic operations for weak algorithms and implementation issues"

    async def analyze(self, app: MobileApp, extracted_path: Path) -> list[AnalyzerResult]:
        """Analyze cryptographic operations."""
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

        return results

    def _extract_snippet(self, content: str, position: int, context_lines: int = 2) -> str:
        """Extract code snippet around a position."""
        lines = content.split('\n')
        line_num = content[:position].count('\n')

        start = max(0, line_num - context_lines)
        end = min(len(lines), line_num + context_lines + 1)

        return '\n'.join(lines[start:end])

    def _check_weakness(self, op: CryptoOperation):
        """Check if a crypto operation uses weak algorithms."""
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
        """Create findings for weak cryptographic algorithms."""
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
        """Get remediation advice for a weak algorithm."""
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
        """Create finding for hardcoded cryptographic keys."""
        locations = "\n".join([
            f"- {k['file']}:{k['line']}"
            for k in keys[:10]
        ])

        return AnalyzerResult(
            title=f"Hardcoded Cryptographic Keys Detected ({len(keys)} instances)",
            description=f"Cryptographic keys appear to be hardcoded in the source code:\n\n{locations}",
            severity="critical",
            category="Cryptography",
            impact="Hardcoded keys can be extracted through reverse engineering, compromising all data encrypted with these keys.",
            remediation="1. Store keys in secure storage (Android KeyStore, iOS Keychain)\n2. Use key derivation from user credentials\n3. Fetch keys from secure backend\n4. Implement proper key rotation",
            file_path=keys[0]["file"],
            line_number=keys[0]["line"],
            code_snippet=keys[0]["snippet"],
            cwe_id="CWE-321",
            cwe_name="Use of Hard-coded Cryptographic Key",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-1",
            poc_verification="1. Decompile the application\n2. Search for key-related strings\n3. Extract and verify the key",
            poc_commands=[
                "jadx -d output app.apk" if app.platform == "android" else "otool -l binary",
                f"grep -rn 'key\\|secret\\|password' .",
            ],
            metadata={
                "instances": len(keys),
                "files": list(set(k["file"] for k in keys)),
            }
        )

    def _create_insecure_random_finding(self, instances: list[dict], app: MobileApp) -> AnalyzerResult:
        """Create finding for insecure random number generation."""
        locations = "\n".join([
            f"- {i['file']}:{i['line']} - {i['pattern']}"
            for i in instances[:10]
        ])

        return AnalyzerResult(
            title=f"Insecure Random Number Generator ({len(instances)} instances)",
            description=f"The application uses predictable random number generators:\n\n{locations}",
            severity="high",
            category="Cryptography",
            impact="Predictable random values used for security purposes (keys, tokens, nonces) can be guessed by attackers.",
            remediation="Use cryptographically secure random generators:\n- Android: SecureRandom\n- iOS: SecRandomCopyBytes\n- General: crypto.getRandomValues() in JS",
            file_path=instances[0]["file"],
            line_number=instances[0]["line"],
            cwe_id="CWE-330",
            cwe_name="Use of Insufficiently Random Values",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-6",
            metadata={
                "instances": len(instances),
            }
        )

    def _create_iv_finding(self, issues: list[dict], app: MobileApp) -> AnalyzerResult:
        """Create finding for IV/nonce issues."""
        locations = "\n".join([
            f"- {i['file']}:{i['line']}"
            for i in issues[:10]
        ])

        return AnalyzerResult(
            title=f"Potential IV/Nonce Issues ({len(issues)} instances)",
            description=f"Potential issues with initialization vectors (IV) or nonces detected:\n\n{locations}\n\nStatic or predictable IVs compromise the security of encryption.",
            severity="high",
            category="Cryptography",
            impact="Reusing IVs or using predictable IVs can lead to plaintext recovery attacks, especially with stream ciphers and CTR mode.",
            remediation="1. Generate fresh random IV for each encryption operation\n2. Use SecureRandom for IV generation\n3. For GCM mode, never reuse nonce with same key\n4. Store IV with ciphertext (IV is not secret)",
            file_path=issues[0]["file"],
            line_number=issues[0]["line"],
            code_snippet=issues[0]["snippet"],
            cwe_id="CWE-329",
            cwe_name="Generation of Predictable IV with CBC Mode",
            owasp_masvs_category="MASVS-CRYPTO",
            owasp_masvs_control="MSTG-CRYPTO-6",
            metadata={
                "instances": len(issues),
            }
        )

    def _create_summary_finding(self, operations: list[CryptoOperation], app: MobileApp) -> AnalyzerResult:
        """Create summary of all crypto operations."""
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
