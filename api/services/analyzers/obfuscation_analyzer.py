"""Obfuscation analyzer for Android application reverse engineering resilience.

Evaluates the level of code obfuscation applied to Android applications
by examining build configuration, class name entropy, string encryption
patterns, and reflection-based dynamic loading techniques.

Security checks performed:
    - **ProGuard/R8 Configuration**: Scans Gradle build files for
      minifyEnabled, shrinkResources, proguardFiles directives, and
      checks for a mapping.txt file indicating obfuscation was applied.
    - **Class Name Entropy Analysis**: Calculates Shannon entropy of
      class names in smali/source directories to estimate obfuscation
      coverage (short 1-2 char names indicate obfuscated classes).
    - **String Encryption Detection**: Identifies runtime string
      decryption patterns such as .decrypt(), .deobfuscate(),
      StringDecryptor, StringFog, and XOR-based deobfuscation.
    - **Reflection Usage Analysis**: Detects heavy use of Java
      reflection (Class.forName, getDeclaredMethod, invoke) and
      dynamic class loading (DexClassLoader, InMemoryDexClassLoader)
      which may indicate obfuscation or anti-analysis techniques.

Obfuscation scoring:
    - < 30% obfuscated classes with no ProGuard: "No Obfuscation" (medium)
    - ProGuard enabled but < 50% coverage: "Partial Obfuscation" (low)
    - >= 50% obfuscated classes: "Obfuscation Detected" (info)

OWASP references:
    - MASVS-RESILIENCE: Resiliency Against Reverse Engineering
    - MASVS-RESILIENCE-3: Code Obfuscation
    - MASTG-TEST-0039: Testing Obfuscation
    - CWE-693: Protection Mechanism Failure
"""

import logging
import math
import re
import shutil
import tempfile
import zipfile
from collections import Counter
from pathlib import Path

from api.models.database import Finding, MobileApp
from api.services.analyzers.base_analyzer import BaseAnalyzer

logger = logging.getLogger(__name__)

# ProGuard/R8 indicators
PROGUARD_INDICATORS = [
    r"proguard-rules\.pro",
    r"-keepattributes",
    r"-keep\s+class",
    r"proguardFiles",
    r"minifyEnabled\s*=?\s*true",
    r"shrinkResources\s*=?\s*true",
]

# String encryption patterns
STRING_ENCRYPTION_PATTERNS = [
    r"\.decrypt\s*\(",
    r"\.deobfuscate\s*\(",
    r"StringDecryptor",
    r"StringFog",
    r"\.xor\s*\(",
    r"Base64\.decode\s*\([^)]+\)\s*.*new\s+String",
]

# Reflection usage patterns
REFLECTION_PATTERNS = [
    r"Class\.forName\s*\(",
    r"\.getDeclaredMethod\s*\(",
    r"\.getDeclaredField\s*\(",
    r"\.getMethod\s*\(",
    r"\.invoke\s*\(",
    r"Method\.invoke\s*\(",
    r"DexClassLoader",
    r"PathClassLoader",
    r"InMemoryDexClassLoader",
]


class ObfuscationAnalyzer(BaseAnalyzer):
    """Analyzes code obfuscation level and reverse engineering resilience.

    Extracts the application archive and evaluates obfuscation coverage
    by checking ProGuard/R8 configuration, computing class name entropy
    scores, detecting string encryption patterns, and quantifying
    reflection-based dynamic loading usage.

    Attributes:
        name: Analyzer identifier used by the scan orchestrator.
        platform: Target platform ("android").
    """

    name = "obfuscation_analyzer"
    platform = "android"

    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze obfuscation state of the application.

        Runs ProGuard configuration checks, class name entropy analysis,
        string encryption detection, and reflection usage analysis.
        Produces findings categorized by obfuscation coverage level.

        Args:
            app: The mobile application to analyze.

        Returns:
            A list of Finding objects covering obfuscation level,
            string encryption, and reflection usage.
        """
        if not app.file_path:
            return []

        extracted_path = None
        try:
            extracted_path = Path(tempfile.mkdtemp(prefix="obfuscation_"))
            with zipfile.ZipFile(app.file_path, "r") as archive:
                archive.extractall(extracted_path)

            findings = []

            # Check build configuration for ProGuard/R8
            proguard_enabled = await self._check_proguard_config(extracted_path)

            # Analyze class name entropy in smali/dex
            obfuscation_score, class_stats = await self._analyze_class_names(extracted_path)

            # Check for string encryption
            string_encryption = await self._check_string_encryption(extracted_path)

            # Check for reflection usage
            reflection_usage = await self._check_reflection_usage(extracted_path)

            # Create findings based on analysis
            if not proguard_enabled and obfuscation_score < 0.3:
                findings.append(self.create_finding(
                    app=app,
                    title="No Code Obfuscation Detected",
                    description=(
                        "The application does not appear to use code obfuscation (ProGuard/R8). "
                        f"Class name analysis shows an obfuscation score of {obfuscation_score:.1%} "
                        f"({class_stats.get('obfuscated', 0)} of {class_stats.get('total', 0)} classes "
                        "have short/obfuscated names).\n\n"
                        "Without obfuscation, reverse engineering the application is significantly easier."
                    ),
                    severity="medium",
                    category="Code Protection",
                    impact=(
                        "Attackers can easily decompile and understand the application logic, "
                        "extract business rules, find vulnerabilities, and create modified versions."
                    ),
                    remediation=(
                        "Enable ProGuard/R8 in build.gradle:\n"
                        "  buildTypes {\n"
                        "      release {\n"
                        "          minifyEnabled true\n"
                        "          proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'\n"
                        "      }\n"
                        "  }\n\n"
                        "For stronger protection, consider commercial tools like DexGuard or iXGuard."
                    ),
                    cwe_id="CWE-693",
                    cwe_name="Protection Mechanism Failure",
                    cvss_score=5.3,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-3",
                    owasp_mastg_test="MASTG-TEST-0039",
                    poc_commands=[
                        {"type": "bash", "command": "jadx -d /tmp/decompiled app.apk", "description": "Decompile APK to check readability"},
                        {"type": "bash", "command": "ls /tmp/decompiled/sources/", "description": "Check if package/class names are readable"},
                    ],
                ))

            elif proguard_enabled and obfuscation_score < 0.5:
                findings.append(self.create_finding(
                    app=app,
                    title="Partial Code Obfuscation Detected",
                    description=(
                        f"ProGuard/R8 appears to be configured but obfuscation coverage is partial. "
                        f"Only {obfuscation_score:.1%} of classes show obfuscated names. "
                        "Many classes may be excluded via -keep rules."
                    ),
                    severity="low",
                    category="Code Protection",
                    impact=(
                        "Partial obfuscation leaves significant portions of the code readable, "
                        "reducing the effectiveness of reverse engineering protection."
                    ),
                    remediation=(
                        "Review ProGuard/R8 rules to minimize -keep directives. "
                        "Only keep classes that must be accessed via reflection (e.g., JNI, serialization). "
                        "Consider adding string encryption and control flow obfuscation."
                    ),
                    cwe_id="CWE-693",
                    cwe_name="Protection Mechanism Failure",
                    cvss_score=3.3,
                    cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-3",
                ))

            else:
                findings.append(self.create_finding(
                    app=app,
                    title="Code Obfuscation Detected",
                    description=(
                        f"The application uses code obfuscation with an estimated coverage of {obfuscation_score:.1%}. "
                        f"{class_stats.get('obfuscated', 0)} of {class_stats.get('total', 0)} classes "
                        "have obfuscated names."
                    ),
                    severity="info",
                    category="Code Protection",
                    impact="Obfuscation increases reverse engineering difficulty but is not a complete protection.",
                    remediation="Maintain obfuscation configuration. Consider adding string encryption for sensitive strings.",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-3",
                ))

            # String encryption finding
            if string_encryption:
                findings.append(self.create_finding(
                    app=app,
                    title="String Encryption Detected",
                    description=(
                        f"String encryption patterns detected in {len(string_encryption)} locations. "
                        "This indicates the app uses runtime string decryption to hide sensitive strings."
                    ),
                    severity="info",
                    category="Code Protection",
                    impact="String encryption makes it harder to extract hardcoded strings through static analysis.",
                    remediation="Ensure encryption keys used for string protection are not easily extractable.",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-3",
                ))

            # Reflection usage finding
            if len(reflection_usage) > 10:
                findings.append(self.create_finding(
                    app=app,
                    title=f"Heavy Reflection Usage Detected ({len(reflection_usage)} instances)",
                    description=(
                        "The application makes extensive use of Java reflection. "
                        "While this can indicate obfuscation or dynamic loading, "
                        "it can also introduce security risks if reflection targets are controllable."
                    ),
                    severity="info",
                    category="Code Protection",
                    impact=(
                        "Reflection can bypass access controls and may indicate "
                        "dynamic code loading which could be exploited."
                    ),
                    remediation="Review reflection usage to ensure targets are not user-controllable.",
                    cwe_id="CWE-693",
                    owasp_masvs_category="MASVS-RESILIENCE",
                    owasp_masvs_control="MASVS-RESILIENCE-3",
                ))

            return findings

        except Exception as e:
            logger.error(f"Obfuscation analysis failed: {e}")
            return []
        finally:
            if extracted_path and extracted_path.exists():
                try:
                    shutil.rmtree(extracted_path)
                except Exception:
                    pass

    async def _check_proguard_config(self, extracted_path: Path) -> bool:
        """Check for ProGuard/R8 configuration in Gradle build files.

        Scans all .gradle files for ProGuard indicator patterns and
        checks for the presence of a mapping.txt output file.

        Args:
            extracted_path: Root directory of the extracted APK.

        Returns:
            True if ProGuard/R8 configuration indicators were found.
        """
        for gradle_file in extracted_path.rglob("*.gradle*"):
            try:
                content = gradle_file.read_text(errors='ignore')
                for pattern in PROGUARD_INDICATORS:
                    if re.search(pattern, content):
                        return True
            except Exception:
                pass

        # Check for proguard mapping file
        if (extracted_path / "mapping.txt").exists():
            return True

        return False

    async def _analyze_class_names(self, extracted_path: Path) -> tuple[float, dict]:
        """Analyze class name entropy to estimate obfuscation level.

        Examines smali and source directories for class name patterns
        that indicate obfuscation (1-2 character lowercase names,
        single uppercase letters, short high-entropy names).

        Args:
            extracted_path: Root directory of the extracted APK.

        Returns:
            A tuple of (obfuscation_score, stats_dict) where the score
            is the ratio of obfuscated to total classes (0.0-1.0) and
            stats contains 'total', 'obfuscated', and 'score' keys.
        """
        total_classes = 0
        obfuscated_classes = 0

        # Check smali directory for class names
        smali_dirs = list(extracted_path.glob("smali*"))
        for smali_dir in smali_dirs:
            for smali_file in smali_dir.rglob("*.smali"):
                total_classes += 1
                class_name = smali_file.stem

                # Obfuscated class names are typically 1-2 lowercase chars
                if re.match(r'^[a-z]{1,2}$', class_name):
                    obfuscated_classes += 1
                # Or single uppercase letter
                elif re.match(r'^[A-Z]$', class_name):
                    obfuscated_classes += 1
                # Short random-looking names
                elif len(class_name) <= 3 and self._calculate_entropy(class_name) > 2.0:
                    obfuscated_classes += 1

        # Also check source directory if available
        sources_dir = extracted_path / "sources"
        if sources_dir.exists():
            for java_file in sources_dir.rglob("*.java"):
                total_classes += 1
                class_name = java_file.stem
                if re.match(r'^[a-z]{1,2}$', class_name):
                    obfuscated_classes += 1
                elif re.match(r'^[A-Z]$', class_name):
                    obfuscated_classes += 1

        score = obfuscated_classes / total_classes if total_classes > 0 else 0.0
        stats = {
            "total": total_classes,
            "obfuscated": obfuscated_classes,
            "score": score,
        }

        return score, stats

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string.

        Args:
            text: The string to compute entropy for.

        Returns:
            Shannon entropy in bits. Returns 0.0 for empty strings.
        """
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            prob = count / length
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    async def _check_string_encryption(self, extracted_path: Path) -> list[dict]:
        """Check for string encryption patterns in source code.

        Scans for .decrypt(), .deobfuscate(), StringDecryptor, StringFog,
        XOR-based operations, and Base64 decode-to-String patterns.

        Args:
            extracted_path: Root directory of the extracted APK.

        Returns:
            A list of dicts with 'file', 'line', and 'pattern' keys.
        """
        results = []

        for ext in [".java", ".kt", ".smali"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    for pattern in STRING_ENCRYPTION_PATTERNS:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            results.append({
                                "file": str(source_file.relative_to(extracted_path)),
                                "line": line_num,
                                "pattern": match.group(0),
                            })
                except Exception:
                    pass

        return results

    async def _check_reflection_usage(self, extracted_path: Path) -> list[dict]:
        """Check for reflection-based calls and dynamic class loading.

        Detects Class.forName, getDeclaredMethod, invoke, DexClassLoader,
        PathClassLoader, and InMemoryDexClassLoader usage.

        Args:
            extracted_path: Root directory of the extracted APK.

        Returns:
            A list of dicts with 'file' and 'pattern' keys.
        """
        results = []

        for ext in [".java", ".kt", ".smali"]:
            for source_file in extracted_path.rglob(f"*{ext}"):
                try:
                    content = source_file.read_text(errors='ignore')
                    for pattern in REFLECTION_PATTERNS:
                        if re.search(pattern, content):
                            results.append({
                                "file": str(source_file.relative_to(extracted_path)),
                                "pattern": pattern,
                            })
                            break  # One per file per pattern is enough
                except Exception:
                    pass

        return results
