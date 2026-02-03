# Changelog

All notable changes to Mobilicustos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-02-03

### Added

#### Core Platform
- **Findings View** - Unified findings display with expandable details
  - Severity quick-filter buttons with counts
  - Expandable table rows showing full finding details
  - Code snippets with syntax highlighting
  - OWASP MASVS/MASTG mapping
  - Remediation guidance with code examples
- **Device Management**
  - Physical Android device support
  - Android emulator support
  - Genymotion emulator detection and integration
  - Corellium virtual device support
- **Application Analysis**
  - APK upload and static analysis
  - IPA upload and analysis
  - Framework detection (Native, Flutter, React Native, Xamarin, Cordova)
- **Scan Management**
  - Static analysis profiles
  - Dynamic analysis profiles
  - Full analysis profiles
  - Scan history and progress tracking

#### Known Findings Database (New)
- Centralized YAML-based finding definitions with rich metadata
- 69 pre-defined findings across Android, iOS, and cross-platform categories
- Full OWASP MASVS/MASTG control mapping
- CVSS scoring and CWE identifiers
- PoC commands and Frida scripts included
- Categories: Manifest, Crypto, Storage, Network, WebView, Binary, Secrets

#### CVE Detection System (New)
- Library fingerprinting for native libraries (.so files)
- SDK detection via package patterns and signatures
- Framework version extraction (Flutter, React Native, Cordova, Xamarin)
- CPE mapping with 70+ library-to-CPE definitions
- OSV (Open Source Vulnerabilities) API integration
- NVD (National Vulnerability Database) API integration
- Signature-based detection for:
  - OpenSSL, SQLite, curl, FFmpeg, zlib (native)
  - OkHttp, Retrofit, Firebase, Gson, Jackson (SDKs)
  - Flutter engine, React Native JSC, Cordova (frameworks)

#### New Security Analyzers (MobSF Parity)
- **ssl_pinning_analyzer** - Detect SSL/TLS certificate pinning implementation
  - OkHttp CertificatePinner detection
  - TrustKit (iOS) detection
  - Network Security Config pinning
  - Missing pinning warnings
- **code_quality_analyzer** - Detect injection vulnerabilities
  - SQL injection patterns (rawQuery, execSQL)
  - Command injection (Runtime.exec)
  - Path traversal detection
  - XSS in WebView (evaluateJavascript)
- **firebase_analyzer** - Firebase-specific misconfigurations
  - Exposed Firebase configuration
  - Insecure Realtime Database rules
  - Cloud Messaging token exposure
- **authentication_analyzer** - Authentication implementation patterns
  - Biometric authentication usage
  - Credential storage analysis
  - Session management review
- **data_leakage_analyzer** - Data leakage vectors
  - Clipboard access patterns
  - Screenshot prevention checks
  - Keyboard cache analysis
  - Backup data exposure

#### Attack Path System (New)
- Graph-based attack path analysis with proper pathfinding
- 60+ edge definitions for mobile attack patterns
- Entry point detection (exported components, deep links, WebViews)
- Target type mapping (data theft, code execution, credential theft)
- Confidence scoring based on exploitability
- CIA triad impact assessment
- MITRE ATT&CK Mobile technique mapping
- DFS/BFS/Dijkstra pathfinding algorithms

#### API & Frontend
- RESTful API with FastAPI
- OpenAPI/Swagger documentation
- Findings export (CSV)
- Vue.js 3 with Composition API
- PrimeVue component library
- Dark mode support
- Responsive design

### Security
- Path traversal protection on all file operations
- Input validation on all API endpoints
- Credential redaction in findings
- Sandboxed analysis environments

---

## [Unreleased]

### Planned
- Automated app store monitoring
- CI/CD pipeline integration
- SARIF export format
- Slack/Teams notifications
- Multi-tenancy support
