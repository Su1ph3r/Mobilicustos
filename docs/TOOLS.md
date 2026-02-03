# Tool Integration Guide

This document describes the security analyzers integrated into Mobilicustos and how to add new ones.

## Built-in Analyzers

### Static Analysis

| Analyzer | Target | Description |
|----------|--------|-------------|
| **manifest_analyzer** | Android | Analyzes AndroidManifest.xml for security misconfigurations, dangerous permissions, exported components |
| **plist_analyzer** | iOS | Analyzes Info.plist for App Transport Security, URL schemes, privacy settings |
| **entitlements_analyzer** | iOS | Checks entitlements for overly permissive capabilities |
| **dex_analyzer** | Android | Analyzes DEX bytecode for insecure patterns, deprecated APIs |
| **crypto_auditor** | Both | Detects weak cryptography, hardcoded keys, insecure random |
| **secret_scanner** | Both | Finds hardcoded secrets, API keys, credentials |
| **binary_protection_analyzer** | Both | Checks for obfuscation, anti-tampering, root/jailbreak detection |
| **native_lib_analyzer** | Both | Analyzes native libraries for security flags (PIE, stack canaries) |
| **network_security_config_analyzer** | Android | Reviews Network Security Config for certificate pinning, cleartext |
| **webview_auditor** | Android | Checks WebView configuration for JavaScript interfaces, file access |
| **ipc_scanner** | Both | Analyzes inter-process communication for injection vulnerabilities |
| **privacy_analyzer** | Both | Reviews privacy-related code for tracking, data collection |
| **dependency_analyzer** | Both | Identifies third-party libraries and known CVEs via OSV/NVD |
| **secure_storage_analyzer** | Both | Checks data storage practices (SharedPreferences, Keychain) |
| **api_endpoint_extractor** | Both | Extracts API endpoints and checks for security issues |
| **resource_analyzer** | Both | Scans resources for sensitive data |
| **ssl_pinning_analyzer** | Both | Detects SSL/TLS certificate pinning (OkHttp, TrustKit, NSC) |
| **code_quality_analyzer** | Both | SQL injection, command injection, path traversal, XSS detection |
| **firebase_analyzer** | Both | Firebase misconfiguration detection (exposed config, insecure rules) |
| **authentication_analyzer** | Both | Biometric auth usage, credential storage, session management |
| **data_leakage_analyzer** | Both | Clipboard, screenshot prevention, keyboard cache, backup exposure |

### Framework-Specific

| Analyzer | Framework | Description |
|----------|-----------|-------------|
| **flutter_analyzer** | Flutter | Uses Blutter to decompile Dart code and analyze Flutter-specific patterns |
| **react_native_analyzer** | React Native | Decompiles Hermes bytecode, extracts JavaScript bundle |

### CVE Detection

| Component | Purpose |
|-----------|---------|
| **LibraryFingerprinter** | Detects native libraries, SDKs, and frameworks via signatures |
| **CPEMatcher** | Maps libraries to CPE identifiers for NVD queries |
| **OSVClient** | Queries Open Source Vulnerabilities database |
| **NVDClient** | Queries NIST National Vulnerability Database |
| **CVEDetector** | Orchestrates fingerprinting and CVE lookups |

Supported library detection:
- **Native**: OpenSSL, SQLite, curl, FFmpeg, zlib, libpng, libjpeg
- **SDKs**: OkHttp, Retrofit, Firebase, Gson, Jackson, Glide, Picasso
- **Frameworks**: Flutter engine, React Native JSC/Hermes, Cordova, Xamarin, Unity

### Attack Path Analysis

| Component | Purpose |
|-----------|---------|
| **GraphBuilder** | Constructs attack graph from findings |
| **Pathfinder** | DFS/BFS/Dijkstra algorithms for path discovery |
| **ImpactAssessor** | Calculates CIA triad impact scores |
| **EdgeDefinitions** | 60+ mobile attack pattern definitions |

### Dynamic Analysis

| Tool | Purpose |
|------|---------|
| **Frida** | Runtime instrumentation for hooking, bypassing |
| **Objection** | Mobile exploration toolkit for runtime analysis |

---

## External Tools

Mobilicustos uses these external tools during analysis:

### JADX
Android DEX to Java decompiler.

**Location:** `/opt/jadx/bin/jadx`

**Usage:** Decompiles APK to readable Java source for code analysis.

### APKTool
APK reverse engineering tool.

**Location:** `/usr/local/bin/apktool`

**Usage:** Decodes resources, manifest, and smali code.

### Blutter
Flutter reverse engineering tool.

**Location:** `/opt/blutter/blutter.py`

**Usage:** Extracts and decompiles Flutter Dart code from libapp.so.

### Hermes-dec
React Native Hermes bytecode decompiler.

**Location:** `/opt/hermes-dec/hbc_decompiler.py`

**Usage:** Decompiles Hermes bytecode to readable JavaScript.

---

## Adding a New Analyzer

### 1. Create Analyzer Class

Create a new file in `api/services/analyzers/`:

```python
"""Example security analyzer."""

from typing import Any
from api.services.analyzers.base_analyzer import BaseAnalyzer, AnalyzerResult
from api.models.database import MobileApp
from api.models.schemas import Finding


class ExampleAnalyzer(BaseAnalyzer):
    """Analyzes apps for example vulnerabilities."""

    name = "example_analyzer"
    platforms = ["android", "ios"]  # or just one

    async def analyze(self, app: MobileApp, **kwargs) -> AnalyzerResult:
        """Run analysis on the application.

        Args:
            app: The mobile app to analyze
            **kwargs: Additional options

        Returns:
            AnalyzerResult with findings list
        """
        findings = []

        # Your analysis logic here
        # ...

        if vulnerability_found:
            findings.append(Finding(
                finding_id=self.generate_finding_id(app, "example-vuln"),
                scan_id=kwargs.get("scan_id"),
                app_id=app.app_id,
                tool=self.name,
                platform=app.platform,
                severity="high",
                status="open",
                category="Example Category",
                title="Example Vulnerability",
                description="Detailed description of the issue.",
                impact="What attackers can do with this vulnerability.",
                remediation="How to fix the issue.",
                file_path="path/to/file.java",
                line_number=42,
                code_snippet="vulnerable code here",
                cwe_id="CWE-XXX",
                cvss_score=7.5,
                owasp_masvs_category="MASVS-XXX",
                owasp_masvs_control="MSTG-XXX-X",
            ))

        return AnalyzerResult(
            findings=findings,
            metadata={"analyzed_files": 10}
        )
```

### 2. Register the Analyzer

Add to `api/services/analyzers/__init__.py`:

```python
from .example_analyzer import ExampleAnalyzer

ANALYZERS = {
    # ... existing analyzers
    "example_analyzer": ExampleAnalyzer,
}
```

### 3. Add to Scan Profiles (Optional)

Update scan profiles in `api/config.py` if the analyzer should be included by default:

```python
SCAN_PROFILES = {
    "static": [
        # ... existing analyzers
        "example_analyzer",
    ],
}
```

### 4. Write Tests

Create tests in `api/tests/test_services_analyzers.py`:

```python
class TestExampleAnalyzer:
    @pytest.fixture
    def analyzer(self):
        return ExampleAnalyzer()

    async def test_detects_vulnerability(self, analyzer, mock_app):
        result = await analyzer.analyze(mock_app)
        assert len(result.findings) > 0
        assert result.findings[0].severity == "high"
```

---

## Analyzer Best Practices

### Finding Quality

1. **Be specific** - Include exact file paths and line numbers
2. **Provide evidence** - Include code snippets demonstrating the issue
3. **Explain impact** - Describe what attackers can achieve
4. **Give remediation** - Provide actionable fix guidance
5. **Map to standards** - Include CWE, CVSS, MASVS references

### Performance

1. **Batch operations** - Read files once, analyze multiple patterns
2. **Early exit** - Skip analysis if prerequisites not met
3. **Limit scope** - Only analyze relevant file types
4. **Cache results** - Reuse decompiled code across analyzers

### Error Handling

1. **Graceful degradation** - Continue if one file fails
2. **Log errors** - Record failures for debugging
3. **Timeout handling** - Set reasonable timeouts
4. **Partial results** - Return findings even if analysis incomplete

---

## Tool Configuration

Tool paths are configured in `api/config.py`:

```python
class Settings(BaseSettings):
    # Tool paths
    jadx_path: str = "/opt/jadx/bin/jadx"
    apktool_path: str = "/usr/local/bin/apktool"
    blutter_path: str = "/opt/blutter/blutter.py"
    hermes_dec_path: str = "/opt/hermes-dec/hbc_decompiler.py"
```

Override via environment variables:
```bash
JADX_PATH=/custom/path/jadx
```

---

## Debugging Analyzers

### Enable Debug Logging

```python
import logging
logging.getLogger("api.services.analyzers").setLevel(logging.DEBUG)
```

### Run Single Analyzer

```python
from api.services.analyzers.example_analyzer import ExampleAnalyzer

analyzer = ExampleAnalyzer()
result = await analyzer.analyze(app, scan_id="test")
print(f"Found {len(result.findings)} findings")
```

### Test Without Database

Use the `--dry-run` flag in tests to skip database operations.
