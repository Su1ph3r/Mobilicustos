# Changelog

All notable changes to Mobilicustos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.2] - 2026-02-06

### Added

#### New Analyzers & SAST
- **Semgrep Analyzer** — Semgrep SAST integration with custom YAML rule sets
  - 16 bundled rules across Android (WebView, crypto), iOS (NSUserDefaults), and common (HTTP) categories
  - MASVS category mapping from rule metadata
  - Zip Slip protection on archive extraction
- **Firebase Live Validation** — Probes Firebase RTDB and Firestore for misconfigured security rules
  - Read-only GET requests to detect open databases
  - Integrated into existing firebase_analyzer pipeline

#### Enhanced Analyzers
- **Runtime Analyzer** — iOS runtime hooks achieving feature parity with Android
  - 16+ iOS-specific API hooks via ObjC.classes and Interceptor.attach
  - NSFileManager, UIApplication, SecItemAdd, NSUserDefaults, CCCrypt, LAContext, UIPasteboard
- **Network Analyzer** — iOS network traffic hooks for SSL pinning and URL loading
- **Flutter Analyzer** — Dart SAST patterns and pub.dev vulnerability scanning
  - SharedPreferences without encryption, HTTP client without TLS, dart:developer imports
  - OSV advisory database integration for pub.dev dependencies
  - Shared archive extraction for performance (single extract shared across sub-analyzers)
- **API Endpoint Extractor** — GraphQL introspection and gRPC/Protobuf detection
- **Dependency Analyzer** — SwiftPM (Package.resolved), yarn.lock, SDK fingerprinting
- **Secret Scanner** — Live validation of S3 buckets and Google API keys
  - S3 bucket listing probe (checks for ListBucketResult)
  - Google Maps Static API key scope validation

#### Bypass Framework
- **Tamper Detection** — Signature verification and integrity check bypass
- **Play Integrity** — Play Integrity / SafetyNet detection with informational status
  - Server-side attestation correctly flagged as non-bypassable client-side

#### New API Endpoints
- `GET /api/scans/registry/analyzers` — Analyzer registry with metadata for all 34 analyzers
- `GET /api/scans/{scan_id}/mastg-coverage` — OWASP MASTG test coverage mapping
- `GET /api/scans/{scan_id}/export/burp` — Burp Suite XML sitemap export
- `GET /api/scans/{scan_id}/export/har` — HAR format export for discovered endpoints

#### Services
- **Gadget Injection Service** — APK/IPA repackaging with frida-gadget
  - Android: apktool decompile, gadget injection, apksigner
  - iOS: insert_dylib + codesign workflow

#### Infrastructure
- **Dockerfile** — Added JDK, apktool 2.9.3, Android SDK build-tools 34.0.0, Docker CLI, ADB platform-tools, drozer agent APK
- **requirements.txt** — Added semgrep>=1.50.0
- **Semgrep Rules** — 4 custom YAML rule files (16 rules total)

### Fixed
- Bypass auto-bypass summary now counts `informational` status (was missing, causing incorrect totals)
- Zip Slip protection added to semgrep_analyzer archive extraction
- Semgrep rule paths resolved as absolute paths (fixes Docker CWD mismatch)
- Content-Disposition headers properly quoted per RFC 6266
- Semgrep exit code handling corrected (only accept 0; code 1 indicates errors)
- Burp XML export uses `urllib.parse.urlparse` instead of fragile string splitting
- Dockerfile apktool URL corrected to official iBotPeaches source
- Dockerfile Android SDK build-tools installation uses sdkmanager instead of direct download
- Dockerfile removed `|| true` that silently swallowed sdkmanager errors
- Flutter analyzer shared extraction eliminates redundant double-extraction

---

## [0.1.1] - 2026-02-06

### Added

#### Dynamic Analysis Framework
- **Frida Integration** — TCP tunnel architecture for Docker-to-device communication
  - Script injection with asyncio timeouts and session management
  - 17 built-in Frida scripts (bypass, monitoring, exploitation, reconnaissance)
  - Real-time output parsing with structured markers
- **Runtime Analyzer** — Frida-based runtime instrumentation for dynamic analysis
- **Network Analyzer** — Network traffic monitoring during dynamic analysis
- **Drozer Integration** — Android IPC security testing with session management
  - Module execution, quick actions (attack surface, SQLi, traversal)
- **Objection Integration** — Runtime mobile exploration
  - Command execution, file/SQL/plist operations, quick bypass actions
- **Bypass Orchestrator** — Automated security bypass pipeline
  - 7 detection types: root, jailbreak, Frida, SSL pinning, emulator, debugger, biometric
  - Auto-bypass with script chaining and result persistence

#### New Analyzers
- **binary_protection_analyzer** — Anti-debug, root detection, emulator detection in native code
- **crypto_auditor** — Weak cipher, hardcoded IV/key, insecure random detection
- **dependency_analyzer** — Third-party library fingerprinting and version extraction
- **ipc_scanner** — Intent, content provider, broadcast, and deep link security
- **privacy_analyzer** — Tracking SDK, advertising ID, IDFA, device fingerprinting detection
- **secure_storage_analyzer** — SharedPreferences, SQLite, file storage security
- **webview_auditor** — JavaScript interface, mixed content, file access, URL loading
- **obfuscation_analyzer** — ProGuard/R8, string encryption, reflection, native obfuscation
- **deeplink_analyzer** — URI scheme, App Links, Universal Links, intent filter analysis
- **backup_analyzer** — Backup allowance, auto-backup, key-value backup configuration
- **component_security_analyzer** — Exported activity, service, receiver, provider security
- **logging_analyzer** — Log.d/Log.v, NSLog, print, BuildConfig.DEBUG detection
- **permissions_analyzer** — Dangerous permission usage, custom permissions, protection levels

#### New Frontend Views
- **Bypass View** — Protection analysis, bypass attempts, auto-bypass dashboard
- **API Endpoints View** — Discovered endpoints with export (Burp, Postman, OpenAPI, CSV)
- **ML Models View** — Extracted machine learning model analysis
- **Scheduled Scans** — Cron-based recurring scan management
- **Webhooks** — Event-driven notifications with signature verification
- **Burp Suite Integration** — Connection management, scan control, issue import
- **Drozer/Objection Views** — Session management and command execution UIs

#### Infrastructure
- **Scheduled Scans** — Cron-based recurring scans with pause/resume
- **Webhooks** — Event-driven notifications for scan completion, findings, etc.
- **Burp Suite Integration** — REST API connection, scan orchestration, proxy history import
- **MCP Server** — Model Context Protocol server for LLM integration with 19 tools

### Changed

#### API Endpoint Extractor (Rewritten)
- Structured endpoint data stored as JSON in `poc_evidence` field (was non-persistent metadata)
- Raw URL extraction restricted to DEX bytecode only — source files use HTTP method pattern matching
- Firebase domain filter replaced from greedy `firebase.*\.com` to specific `firebaseio.com`, `firebase.google.com`, `firebaseapp.com`
- Analytics/tracking/telemetry skip patterns now domain-anchored (no longer match substrings)
- Bare-domain URL filter removed (these can be valid API base URLs)
- Endpoint list expanded from 15 to 50 in summary findings
- JSON key renamed from `source_file` to `file` to match downstream parser

#### Secret Scanner (Improved)
- Shannon entropy check rejects low-entropy matches (< 3.0 bits) for generic patterns
- False positive exclusion list filters placeholder values (example, test, dummy, etc.)
- Known SDK/library files skipped (google-services.json, build.gradle, lock files)
- Confidence-based severity: provider-prefixed patterns (AKIA, ghp_, sk_live_) keep original severity; generic matches downgraded by one level
- Entropy and false positive checks use innermost capture group (actual secret value)

#### Scan Orchestrator
- `findings_count` updated after each analyzer completes (was only set at scan end)
- Error handler now commits after rollback to prevent session desync

#### Analyzer Pipeline
- All analyzers enriched with PoC evidence: `code_snippet`, `poc_evidence`, `poc_verification`, `poc_commands`
- Binary protection analyzer optimized to single-pass file scanning
- Obfuscation analyzer merged duplicate file reads into `_check_code_patterns`
- Null byte stripping on all DEX bytecode reads (prevents PostgreSQL encoding errors)
- CPU freeze prevention with timeouts and resource limits

### Fixed
- **Compliance KeyError** — Added missing `info` severity key to MASVS findings counter
- **Bypass 422 errors** — Fixed `attemptBypass` to send query parameters instead of POST body (frontend, MCP client, and test suite)
- **Shell injection** — All PoC curl/jadx commands now use `shlex.quote()` for user-controlled values
- **Path leakage** — PoC commands use `Path().name` instead of full server-side file paths
- **Scan progress** — Users now see live finding counts during scan instead of zeros until completion

### Security
- Command injection prevention in all generated PoC shell commands
- Server path information no longer exposed in finding PoC evidence
- Secret scanner false positive rate significantly reduced
- Entropy-based validation prevents reporting of placeholder/test credentials

---

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
