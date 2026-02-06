# Mobilicustos Architecture

Technical architecture reference for the Mobilicustos mobile security
penetration testing platform.

---

## 1. System Overview

Mobilicustos is a containerized platform that performs static and dynamic
security analysis of Android (APK) and iOS (IPA) mobile applications. The
system combines automated scanning with interactive tooling (Frida, Drozer,
Objection) and an anti-detection bypass framework to produce actionable
findings mapped to OWASP MASVS/MASTG controls.

```
                          +-----------------------+
                          |      Browser/UI       |
                          |  (Vue 3 + PrimeVue)   |
                          +-----------+-----------+
                                      |  :3000 (nginx)
                                      v
+-----------------------------------------------------------------------+
|                     Docker Compose Network                            |
|                     (mobilicustos bridge)                             |
|                                                                       |
|   +----------------+       +------------------+                       |
|   |   Frontend     | ----> |     API          |                       |
|   |   nginx :80    |       |  FastAPI :8000   |                       |
|   +----------------+       +--------+---------+                       |
|                                     |                                 |
|              +----------------------+----------------------+          |
|              |                      |                      |          |
|              v                      v                      v          |
|   +------------------+   +------------------+   +------------------+  |
|   |   PostgreSQL     |   |     Neo4j        |   |     Redis        |  |
|   |   :5432          |   |  :7474 / :7687   |   |     :6379        |  |
|   |                  |   |                  |   |                  |  |
|   | Apps, Scans,     |   | Attack path      |   | Cache, sessions  |  |
|   | Findings,        |   | graphs,          |   |                  |  |
|   | Secrets, Devices |   | component deps   |   |                  |  |
|   +------------------+   +------------------+   +------------------+  |
|                                                                       |
|   +-------------------+                                               |
|   | Report Processor  |  (reads findings, normalizes, maps MASVS)     |
|   +-------------------+                                               |
|                                                                       |
+------------------------------+----------------------------------------+
                               |
                    host.docker.internal
                               |
              +----------------+------------------+
              |  ADB server :5037                 |
              |  adb forward tcp:27042 tcp:27042  |
              +----------------+------------------+
                               |  USB
                               v
                  +------------------------+
                  |  Android / iOS Device  |
                  |  frida-server 16.5.9   |
                  |  (TCP :27042)          |
                  +------------------------+
```

---

## 2. Service Architecture

### 2.1 Docker Compose Services

| Service              | Image / Build               | Container Name                | Port(s)               | Purpose                              |
|----------------------|-----------------------------|-------------------------------|------------------------|--------------------------------------|
| `postgres`           | `postgres:15.6-alpine`      | `mobilicustos-postgres`       | `5432:5432`            | Primary relational store             |
| `neo4j`              | `neo4j:5.26-community`      | `mobilicustos-neo4j`          | `7474:7474, 7687:7687` | Graph DB for attack paths            |
| `redis`              | `redis:7.4-alpine`          | `mobilicustos-redis`          | `6379:6379`            | Cache and session store              |
| `api`                | `./api/Dockerfile`          | `mobilicustos-api`            | `8000:8000`            | FastAPI backend                      |
| `frontend`           | `./frontend/Dockerfile`     | `mobilicustos-frontend`       | `3000:80`              | Vue 3 SPA (nginx)                    |
| `report-processor`   | `./report-processor/Dockerfile` | `mobilicustos-report-processor` | (none)           | Finding normalization worker         |

All services join the `mobilicustos` bridge network. The API container
additionally mounts:

- `./api:/app/api:ro` -- source code (read-only; rebuild for changes)
- `./uploads:/app/uploads` -- uploaded APK/IPA files
- `./reports:/app/reports` -- generated PDF/JSON reports
- `/tmp/mobilicustos_analyzer:/tmp/mobilicustos_analyzer` -- shared temp for
  analyzer containers
- Docker socket -- so the API can spawn analyzer containers on demand via
  `DockerExecutor`

### 2.2 Network Topology

```
Container Network (mobilicustos bridge)
  api  <-->  postgres (postgresql+asyncpg)
  api  <-->  neo4j   (bolt://neo4j:7687)
  api  <-->  redis   (redis://redis:6379)
  api  ---> host.docker.internal:5037   (ADB server, via ADB_SERVER_SOCKET)
  api  ---> host.docker.internal:27042  (frida-server, via FRIDA_SERVER_HOST)
  frontend --> api (reverse proxy /api -> :8000)
```

### 2.3 Key Environment Variables

Defined in `docker-compose.yml` and loaded by `api/config.py`
(`pydantic_settings.BaseSettings`):

| Variable                | Default                       | Description                                   |
|-------------------------|-------------------------------|-----------------------------------------------|
| `POSTGRES_HOST`         | `postgres`                    | PostgreSQL hostname                           |
| `NEO4J_URI`             | `bolt://neo4j:7687`          | Neo4j Bolt endpoint                           |
| `REDIS_URL`             | `redis://redis:6379`         | Redis connection URL                          |
| `ADB_SERVER_SOCKET`     | `tcp:host.docker.internal:5037` | ADB server socket from inside Docker       |
| `FRIDA_SERVER_HOST`     | `host.docker.internal:27042` | Frida TCP tunnel endpoint                     |
| `ANALYZER_TEMP_PATH`    | `/tmp/mobilicustos_analyzer` | Shared temp dir for analyzer containers       |
| `SECRET_KEY`            | (must change)                 | JWT signing key                               |
| `FRIDA_SERVER_VERSION`  | `16.5.9`                     | Pinned Frida version (16.x only -- see sec 6) |

Source: `api/config.py` -- `Settings` class.

---

## 3. Backend Architecture

### 3.1 FastAPI Application Structure

Entry point: `api/main.py`

```
api/
  main.py              # FastAPI app, lifespan, CORS, router registration
  config.py            # Settings (pydantic_settings.BaseSettings)
  database.py          # AsyncEngine, async_session_factory, get_db()
  models/
    database.py        # SQLAlchemy ORM models (11 tables)
  routers/             # 33 APIRouter modules (one per feature)
  services/            # Business logic layer
    analyzers/         # 33 analyzer modules + base_analyzer.py
    scan_orchestrator.py
    bypass_orchestrator.py
    frida_service.py
    device_manager.py
    docker_executor.py
    ...                # 20+ additional service modules
  data/
    frida_scripts/     # Built-in Frida scripts, seeded on startup
    known_findings/    # Finding template registry
```

#### Lifespan

On startup (`lifespan()` in `main.py`), the app seeds built-in Frida bypass
scripts into the `frida_scripts` table via `seed_builtin_scripts()`. Shutdown
is clean with no special teardown.

#### CORS

Currently allows all origins (`allow_origins=["*"]`). Must be restricted for
production deployments.

### 3.2 Router Organization

All routers are registered in `api/main.py`. Prefixes follow the `/api/`
convention:

| Router                | Prefix                  | Tag               |
|-----------------------|-------------------------|-------------------|
| `health`              | `/` (no prefix)         | Health            |
| `apps`                | `/api/apps`             | Apps              |
| `scans`               | `/api/scans`            | Scans             |
| `findings`            | `/api/findings`         | Findings          |
| `devices`             | `/api/devices`          | Devices           |
| `frida`               | `/api/frida`            | Frida             |
| `drozer`              | `/api/drozer`           | Drozer            |
| `objection`           | `/api/objection`        | Objection         |
| `bypass`              | `/api/bypass`           | Bypass            |
| `ml_models`           | `/api/ml-models`        | ML Models         |
| `secrets`             | `/api/secrets`          | Secrets           |
| `attack_paths`        | `/api/attack-paths`     | Attack Paths      |
| `compliance`          | `/api/compliance`       | Compliance        |
| `exports`             | `/api/exports`          | Exports           |
| `ios`                 | `/api/ios`              | iOS               |
| `scheduled_scans`     | `/api`                  | Scheduled Scans   |
| `webhooks`            | `/api`                  | Webhooks          |
| `burp`                | `/api`                  | Burp Suite        |
| `issue_tracker`       | `/api`                  | Issue Tracker     |
| `dashboard`           | `/api`                  | Dashboard         |
| `reports`             | `/api`                  | Reports           |
| `teams`               | `/api`                  | Teams             |
| `finding_workflow`    | `/api`                  | Finding Workflow  |
| `siem`                | `/api`                  | SIEM/SOAR         |
| `app_stores`          | `/api`                  | App Stores        |
| `network_traffic`     | `/api`                  | Network Traffic   |
| `runtime_monitor`     | `/api`                  | Runtime Monitor   |
| `fuzzing`             | `/api`                  | Fuzzing           |
| `screenshot`          | `/api`                  | Screen Capture    |
| `corellium`           | `/api`                  | Corellium         |
| `api_endpoints`       | `/api/api-endpoints`    | API Endpoints     |
| `settings`            | `/api/settings`         | Settings          |

### 3.3 Service Layer Pattern

Routers delegate to service classes in `api/services/`. Each service receives
a database session via FastAPI dependency injection (`get_db()`). Key services:

| Service                      | File                              | Responsibility                                 |
|------------------------------|-----------------------------------|-------------------------------------------------|
| `ScanOrchestrator`           | `scan_orchestrator.py`            | Coordinates scan execution                      |
| `BypassOrchestrator`         | `bypass_orchestrator.py`          | Anti-detection analysis & bypass                |
| `FridaService`               | `frida_service.py`                | Script injection, session management            |
| `DeviceManager`              | `device_manager.py`               | ADB/iOS device discovery & management           |
| `DockerExecutor`             | `docker_executor.py`              | Spawns analyzer containers via Docker socket    |
| `AppParser`                  | `app_parser.py`                   | APK/IPA parsing & metadata extraction           |
| `FrameworkDetector`          | `framework_detector.py`           | Flutter/RN/Xamarin detection                    |
| `ReportService`              | `report_service.py`               | PDF/JSON report generation                      |
| `DashboardService`           | `dashboard_service.py`            | Aggregated metrics                              |
| `SecretValidator`            | `secret_validator.py`             | Validates discovered secrets                    |
| `AttackPathAnalyzer`         | `attack_path_analyzer.py`         | Neo4j-backed attack graph generation            |
| `CorelliumClient`            | `corellium_service.py`            | Corellium virtual device API                    |
| `DrozerService`              | `drozer_service.py`               | Drozer session management                       |
| `ObjectionService`           | `objection_service.py`            | Objection session management                    |
| `WebhookService`             | `webhook_service.py`              | Outbound webhook delivery                       |
| `ScheduledScanService`       | `scheduled_scan_service.py`       | Cron-based scan scheduling                      |

### 3.4 Database Models (PostgreSQL)

Defined in `api/models/database.py` using SQLAlchemy 2.0 mapped columns with
`asyncpg` driver.

| Table                   | Primary Key          | Description                                      |
|-------------------------|----------------------|--------------------------------------------------|
| `mobile_apps`           | `app_id` (str)       | Uploaded apps with metadata, framework detection  |
| `scans`                 | `scan_id` (UUID)     | Scan records with status, progress, timing        |
| `findings`              | `id` (auto), `finding_id` (unique str) | Rich findings with PoC, CVSS, CWE, OWASP mapping |
| `attack_paths`          | `path_id` (UUID)     | Attack chains linking findings, with Neo4j ref    |
| `ml_models`             | `model_id` (UUID)    | Extracted ML models (TFLite, CoreML, etc.)        |
| `secrets`               | `secret_id` (UUID)   | Detected secrets/credentials (redacted values)    |
| `devices`               | `device_id` (str)    | Physical/emulator/Corellium device registry       |
| `frida_scripts`         | `script_id` (UUID)   | Frida script library (builtin + user-created)     |
| `bypass_results`        | `result_id` (UUID)   | Anti-detection bypass attempt tracking            |
| `drozer_sessions`       | `session_id` (UUID)  | Drozer session state                              |
| `drozer_results`        | `result_id` (UUID)   | Drozer module execution results                   |
| `objection_sessions`    | `session_id` (UUID)  | Objection session state + command history         |
| `cve_cache`             | `cve_id` (str)       | Cached CVE data with TTL                          |
| `library_fingerprints`  | `id` (auto)          | Library identification hashes and symbols         |

Key relationships:

```
MobileApp  1---*  Scan
MobileApp  1---*  Finding
MobileApp  1---*  Secret
MobileApp  1---*  MLModel
Scan       1---*  Finding
Device     1---*  BypassResult
FridaScript 1---* BypassResult
```

JSONB columns are used extensively for flexible schema: `findings_count`,
`analyzer_errors`, `poc_commands`, `remediation_code`, `input_tensors`,
`framework_details`, `signing_info`, etc.

### 3.5 Neo4j Graph Database

Used for attack path analysis. The `AttackPath` model stores a
`neo4j_path_id` reference linking the relational record to the graph
representation.

Graph structure:
- **Nodes**: Findings, Components, Permissions, Data Stores
- **Edges**: "leads_to", "exposes", "requires", "accesses"

Queries are executed via the `neo4j` Python driver (Bolt protocol on port
7687). The APOC plugin is enabled for advanced graph operations.

### 3.6 Redis Usage

Connection: `redis://redis:6379`

Used for:
- **Caching**: Dashboard metrics, CVE lookup results, compliance scores
- **Session management**: Scan progress tracking
- **Rate limiting**: API rate control

---

## 4. Analyzer Pipeline

### 4.1 BaseAnalyzer Pattern

All analyzers inherit from `BaseAnalyzer` (`api/services/analyzers/base_analyzer.py`):

```python
class BaseAnalyzer(ABC):
    name: str = "base"
    platform: str = "cross-platform"

    @abstractmethod
    async def analyze(self, app: MobileApp) -> list[Finding]:
        """Analyze an app and return findings."""
        pass
```

Key methods provided by `BaseAnalyzer`:

| Method                     | Purpose                                                   |
|----------------------------|-----------------------------------------------------------|
| `create_finding()`         | Creates a `Finding` ORM object with deterministic hash ID |
| `result_to_finding()`      | Converts `AnalyzerResult` dataclass to `Finding`          |
| `create_finding_from_known()` | Creates finding from a pre-defined template registry   |
| `_generate_canonical_id()` | Generates dedup key from category + title + app_id        |

#### Finding ID Generation

```python
# Deterministic hash from app, tool, title, description, location
finding_hash = sha256(f"{app_id}:{tool}:{title}:{desc}:{path}:{line}").hexdigest()[:16]
finding_id = f"{tool_name}-{finding_hash}"
```

The `ScanOrchestrator` then appends the scan_id prefix to prevent collisions
across scans:

```python
finding.finding_id = f"{finding.finding_id}-{str(scan.scan_id)[:8]}"
```

#### Canonical ID for Deduplication

```python
# Normalized: category_title_app_id_platform
canonical_id = f"{category}_{normalized_title}_{app_id}_{platform}"
# Hashed to SHA-256[:32] if > 200 chars
```

### 4.2 Static Analyzers (Android)

Defined in `STATIC_ANALYZERS["android"]` in `scan_orchestrator.py`:

| #  | Analyzer                          | Class                        | Focus Area                              |
|----|-----------------------------------|------------------------------|-----------------------------------------|
| 1  | `manifest_analyzer`               | `ManifestAnalyzer`           | AndroidManifest.xml security review     |
| 2  | `dex_analyzer`                    | `DexAnalyzer`                | DEX bytecode analysis                   |
| 3  | `network_security_config_analyzer`| `NetworkSecurityConfigAnalyzer` | Network security config XML          |
| 4  | `native_lib_analyzer`             | `NativeLibAnalyzer`          | Native .so library analysis             |
| 5  | `resource_analyzer`               | `ResourceAnalyzer`           | Resource file security review           |
| 6  | `secret_scanner`                  | `SecretScanner`              | Hardcoded secrets/API keys              |
| 7  | `ssl_pinning_analyzer`            | `SSLPinningAnalyzer`         | SSL/TLS certificate pinning             |
| 8  | `code_quality_analyzer`           | `CodeQualityAnalyzer`        | SQLi, command injection, path traversal |
| 9  | `firebase_analyzer`               | `FirebaseAnalyzer`           | Firebase misconfiguration               |
| 10 | `authentication_analyzer`         | `AuthenticationAnalyzer`     | Biometric & credential patterns         |
| 11 | `data_leakage_analyzer`           | `DataLeakageAnalyzer`        | Clipboard, screenshot, keyboard leaks   |
| 12 | `api_endpoint_extractor`          | `APIEndpointExtractor`       | URL/endpoint extraction                 |
| 13 | `binary_protection_analyzer`      | `BinaryProtectionAnalyzer`   | Binary hardening (PIE, stack canary)    |
| 14 | `crypto_auditor`                  | `CryptoAuditor`              | Cryptographic implementation review     |
| 15 | `dependency_analyzer`             | `DependencyAnalyzer`         | Library CVE detection (OSV/NVD)         |
| 16 | `ipc_scanner`                     | `IPCScanner`                 | Inter-process communication security    |
| 17 | `privacy_analyzer`                | `PrivacyAnalyzer`            | Privacy-sensitive API usage             |
| 18 | `secure_storage_analyzer`         | `SecureStorageAnalyzer`      | Data-at-rest storage patterns           |
| 19 | `webview_auditor`                 | `WebViewAuditor`             | WebView security (JS interface, etc.)   |
| 20 | `obfuscation_analyzer`            | `ObfuscationAnalyzer`        | Code obfuscation assessment             |
| 21 | `deeplink_analyzer`               | `DeeplinkAnalyzer`           | Deep link / app link validation         |
| 22 | `backup_analyzer`                 | `BackupAnalyzer`             | Backup configuration security           |
| 23 | `component_security_analyzer`     | `ComponentSecurityAnalyzer`  | Exported component security             |
| 24 | `logging_analyzer`                | `LoggingAnalyzer`            | Sensitive data in logs                  |
| 25 | `permissions_analyzer`            | `PermissionsAnalyzer`        | Permission usage analysis               |

### 4.3 Static Analyzers (iOS)

Defined in `STATIC_ANALYZERS["ios"]`:

| Analyzer                   | Class                   | Focus Area                           |
|---------------------------|-------------------------|--------------------------------------|
| `plist_analyzer`          | `PlistAnalyzer`         | Info.plist analysis                  |
| `ios_binary_analyzer`     | `iOSBinaryAnalyzer`     | Mach-O binary analysis               |
| `entitlements_analyzer`   | `EntitlementsAnalyzer`  | Entitlements review                  |
| `secret_scanner`          | `SecretScanner`         | Hardcoded secrets                    |
| `ssl_pinning_analyzer`    | `SSLPinningAnalyzer`    | SSL pinning detection                |
| `code_quality_analyzer`   | `CodeQualityAnalyzer`   | Code quality issues                  |
| `firebase_analyzer`       | `FirebaseAnalyzer`      | Firebase misconfiguration            |
| `authentication_analyzer` | `AuthenticationAnalyzer`| Auth patterns                        |
| `data_leakage_analyzer`   | `DataLeakageAnalyzer`   | Data leakage patterns                |
| `api_endpoint_extractor`  | `APIEndpointExtractor`  | URL extraction                       |
| `crypto_auditor`          | `CryptoAuditor`         | Crypto review                        |
| `dependency_analyzer`     | `DependencyAnalyzer`    | Library CVEs                         |
| `privacy_analyzer`        | `PrivacyAnalyzer`       | Privacy analysis                     |

### 4.4 Cross-Platform Analyzers

Added when the app framework is detected as Flutter, React Native, Xamarin, or
MAUI:

| Analyzer                 | Class                  | Focus Area                        |
|--------------------------|------------------------|-----------------------------------|
| `flutter_analyzer`       | `FlutterAnalyzer`      | Dart/Flutter-specific issues      |
| `react_native_analyzer`  | `ReactNativeAnalyzer`  | RN bridge & Hermes analysis       |
| `ml_model_analyzer`      | `MLModelAnalyzer`      | TFLite/CoreML model extraction    |

### 4.5 Dynamic Analyzers

| Analyzer             | Class               | Focus Area                      |
|----------------------|---------------------|---------------------------------|
| `runtime_analyzer`   | `RuntimeAnalyzer`   | Runtime behavior via Frida      |
| `network_analyzer`   | `NetworkAnalyzer`   | Network traffic interception    |

### 4.6 Scan Orchestrator Flow

Source: `api/services/scan_orchestrator.py` -- `ScanOrchestrator.execute_scan()`

```
1. run_scan(scan_id) called as background task
   |
2. Create fresh DB engine + session (background tasks need own connection)
   |
3. Load Scan + MobileApp from database
   |
4. Set scan.status = "running", scan.started_at = now()
   |
5. _get_analyzers(scan, app):
   |   scan_type == "dynamic"  --> ["runtime_analyzer", "network_analyzer"]
   |   scan_type == "static"   --> platform analyzers + cross-platform if applicable
   |   scan_type == "full"     --> static + dynamic analyzers
   |   scan.analyzers_enabled  --> use explicit list if provided
   |
6. For each analyzer (sequential):
   |   a. Update scan.current_analyzer, scan.progress
   |   b. _run_analyzer(name, app) -- dynamic import + analyzer.analyze(app)
   |   c. For each finding:
   |      - Set finding.scan_id
   |      - Append scan_id[:8] to finding_id (collision prevention)
   |      - db.add(finding)
   |   d. db.flush() (for foreign key constraints)
   |   e. If secret_scanner: create Secret entries from findings
   |   f. On error: db.rollback(), record in scan.analyzer_errors, continue
   |
7. Set scan.status = "completed", scan.progress = 100
   Update scan.findings_count = {critical: N, high: N, ...}
   Update app.status = "completed", app.last_analyzed = now()
   |
8. db.commit()
```

If any analyzer fails, the error is recorded in `scan.analyzer_errors` (JSONB
array) and execution continues with the next analyzer. A complete scan failure
rolls back and sets `scan.status = "failed"`.

---

## 5. Security Bypass System

### 5.1 Overview

The bypass system (`api/services/bypass_orchestrator.py` --
`BypassOrchestrator`) detects and attempts to bypass anti-tampering protections
in mobile apps. It operates in three phases:

1. **Static analysis** -- scan the APK/IPA archive for protection signatures
2. **Runtime analysis** -- inject a Frida recon script to probe live classes
3. **Bypass attempts** -- inject bypass scripts, evaluate success via output
   markers

### 5.2 Detection Types

| Detection Type   | Platform    | What It Detects                                          |
|------------------|-------------|----------------------------------------------------------|
| `root`           | Android     | Root detection (RootBeer, SafetyNet, su binary checks)   |
| `jailbreak`      | iOS         | Jailbreak detection (Cydia, file checks, URL schemes)    |
| `frida`          | Both        | Anti-Frida mechanisms (port scan, memory scan, file check)|
| `ssl_pinning`    | Both        | SSL certificate pinning (OkHttp, TrustManager, AFNetworking) |
| `emulator`       | Android     | Emulator detection (Build props, sensor checks)          |
| `debugger`       | Both        | Debugger detection (ptrace, TracerPid, timing)           |
| `biometric`      | Both        | Biometric authentication bypass                          |

### 5.3 Static Detection

`analyze_protections(app)` opens the APK/IPA as a ZIP archive and searches
for:

- Known library names (e.g., `rootbeer`, `libanti-frida`)
- String signatures in DEX/SO files (e.g., `frida-server`, `27042`)
- SSL pinning patterns (e.g., `certificatepinner`, `trustmanager`)
- Root/jailbreak file path strings
- Emulator indicator strings (e.g., `goldfish`, `genymotion`)

### 5.4 Runtime Detection

`analyze_protections_runtime(app, device)` injects a platform-specific recon
script:

- **Android**: `RUNTIME_RECON_SCRIPT` -- uses `Java.perform()` to probe for
  RootBeer, SafetyNet, CertificatePinner, TrustManagerImpl, TrustKit,
  emulator Build properties, debugger status, BiometricPrompt
- **iOS**: `IOS_RUNTIME_RECON_SCRIPT` -- uses Objective-C runtime to check
  jailbreak file paths, Cydia URL scheme, AFSecurityPolicy, TrustKit

Output is parsed via `_parse_output_markers()` using a `[+]`/`[-]`/`[*]`
marker protocol:
- `[+]` -- detection confirmed (protection found)
- `[-]` -- not detected
- `[*]` -- informational

### 5.5 Script Selection and Chaining

`_find_bypass_scripts(detection_type, platform, db)`:

1. Query `frida_scripts` table: `category='bypass'`, match `subcategory`
   from `DETECTION_TO_SCRIPT_MAP`
2. Fallback: name-keyword search if subcategory yields no results
3. Sort order: builtin scripts first, generic before advanced
4. Try scripts sequentially until one succeeds (success = more `[+]` than
   `[-]` markers)

If no database scripts exist, a hardcoded fallback is used for `root`,
`ssl_pinning`, `frida`, and `jailbreak`.

### 5.6 Auto-Bypass Pipeline

`auto_bypass(app, device, db)`:

```
1. Static analysis --> list of detected protections
2. Runtime analysis --> list of runtime-detected protections
3. Merge detections (combine evidence, take highest confidence)
4. For each detected protection:
   a. attempt_bypass(app, device, detection_type, db=db)
   b. Try each matching script (generic first, then advanced)
   c. Evaluate success via [+]/[-] marker counting
   d. Save BypassResult to database
5. Return list of results with:
   - detection info (type, confidence, evidence)
   - bypass status (success/failed)
   - techniques_tried (each script attempt)
   - recommendations (context-aware suggestions)
```

### 5.7 Result Tracking

Each bypass attempt is persisted as a `BypassResult` row:

| Field                | Source                                              |
|----------------------|-----------------------------------------------------|
| `detection_type`     | "root", "ssl_pinning", "frida", etc.               |
| `detection_method`   | Comma-joined methods from detection evidence        |
| `detection_library`  | Subcategory of successful script                    |
| `bypass_script_id`   | FK to `frida_scripts` (the script that succeeded)   |
| `bypass_status`      | "success" / "failed" / "not_attempted"              |
| `poc_evidence`       | Captured Frida output (capped at 4000 chars)        |

---

## 6. Frida Integration

### 6.1 TCP Tunnel Architecture

Frida cannot use USB device access from inside Docker. The platform uses a TCP
tunnel:

```
+------------------+     TCP :27042      +-------------------+    USB     +---------+
|  API Container   | ----------------->  |   Host Machine    | -------> | Device  |
| (frida client    |  host.docker.       | adb forward       |          | frida-  |
|  16.5.x)         |  internal:27042     | tcp:27042         |          | server  |
+------------------+                     | tcp:27042         |          | 16.5.9  |
                                         +-------------------+          +---------+
```

Setup:
1. `frida-server` 16.5.9 runs on device at `0.0.0.0:27042`
2. `adb forward tcp:27042 tcp:27042` on host tunnels the port
3. API container connects via `FRIDA_SERVER_HOST=host.docker.internal:27042`
4. Dynamic analyzers (`runtime_analyzer`, `network_analyzer`) use
   `frida.get_device_manager().add_remote_device(frida_host)` instead of
   `get_usb_device()`

### 6.2 Script Injection Flow

Source: `api/services/frida_service.py` -- `FridaService`

```python
async def inject(device_id, package_name, script_content, spawn=True) -> str:
    # 1. Get device (USB or remote TCP based on device_id format)
    # 2. spawn + attach + resume  OR  attach to running process
    # 3. session.create_script(script_content)
    # 4. Register message handler (captures [+]/[-]/[*] output)
    # 5. script.load()
    # 6. Store in _active_sessions dict, return session_id (UUID)
```

All Frida operations use `asyncio.wait_for()` with 30-second timeouts to
prevent hangs.

### 6.3 Session Management

Active sessions are tracked in a module-level dict `_active_sessions`:

```python
_active_sessions[session_id] = {
    "session_id": str,
    "device_id": str,
    "package_name": str,
    "session": frida.core.Session,
    "script": frida.core.Script,
    "messages": list[dict],   # All received messages
    "status": "active" | "detached",
}
```

Available operations:
- `inject()` -- create session, inject script
- `detach()` -- unload script, detach session, remove from dict
- `list_sessions()` -- enumerate active sessions
- `get_session_messages()` -- retrieve captured messages
- `send_rpc()` -- call exported RPC method on loaded script
- `list_processes()` / `list_apps()` -- enumerate device processes/apps

### 6.4 FridaScriptBuilder

A helper class for programmatically constructing Frida scripts:

```python
builder = FridaScriptBuilder()
builder.add_java_hook("com.example.App", "isRooted", "return false;")
builder.add_native_hook("libc.so", "open", on_enter="...", on_leave="...")
script_content = builder.build()  # Wraps hooks in Java.perform()
```

### 6.5 Version Compatibility (Critical)

- **frida-server 17.x crashes** with SIGABRT on Pixel 3 XL / Android 11
  during spawn/attach operations
- **frida-server 16.5.9** is stable -- pinned via `FRIDA_SERVER_VERSION`
  setting and `frida>=16.5.9,<17.0.0` in requirements
- Client/server major versions **must match** (16.x client with 16.x server)
- `enumerate_processes()` works across version mismatches; `spawn()`/`attach()`
  do not
- Docker must use `add_remote_device()` (TCP), never `get_usb_device()`

---

## 7. Frontend Architecture

### 7.1 Technology Stack

- **Vue 3** with Composition API (`<script setup>`)
- **TypeScript** throughout
- **PrimeVue** component library (buttons, tables, dialogs, etc.)
- **Pinia** for state management
- **Vue Router** with `createWebHistory`
- **Axios** for HTTP client
- Built and served via **nginx** in production container

Source: `frontend/`

### 7.2 Router Structure

Defined in `frontend/src/router/index.ts`. All routes use lazy-loaded
components:

| Path                  | View Component           | Feature                    |
|-----------------------|--------------------------|----------------------------|
| `/`                   | `DashboardView`          | Security posture dashboard |
| `/apps`               | `AppsView`               | App list and upload        |
| `/apps/:id`           | `AppDetailView`          | App details and scan launch|
| `/scans`              | `ScansView`              | Scan list                  |
| `/scans/:id`          | `ScanDetailView`         | Scan progress and results  |
| `/findings`           | `FindingsView`           | Finding list with filters  |
| `/findings/:id`       | `FindingDetailView`      | Finding detail + PoC       |
| `/devices`            | `DevicesView`            | Device management          |
| `/frida`              | `FridaView`              | Frida script editor        |
| `/compliance`         | `ComplianceView`         | MASVS compliance matrix    |
| `/attack-paths`       | `AttackPathsView`        | Attack path visualization  |
| `/secrets`            | `SecretsView`            | Detected secrets           |
| `/drozer`             | `DrozerView`             | Drozer session console     |
| `/objection`          | `ObjectionView`          | Objection session console  |
| `/scheduled-scans`    | `ScheduledScansView`     | Cron-based scan config     |
| `/webhooks`           | `WebhooksView`           | Webhook management         |
| `/burp`               | `BurpView`               | Burp Suite integration     |
| `/bypass`             | `BypassView`             | Bypass orchestration UI    |
| `/api-endpoints`      | `APIEndpointsView`       | Extracted API endpoints    |
| `/settings`           | `SettingsView`           | Platform settings          |

### 7.3 Pinia Stores

Located in `frontend/src/stores/`:

| Store        | File          | State                                     |
|--------------|---------------|-------------------------------------------|
| Apps         | `apps.ts`     | App list, current app, upload state        |
| Scans        | `scans.ts`    | Scan list, progress polling                |
| Findings     | `findings.ts` | Finding list, filters, summary             |
| Devices      | `devices.ts`  | Device list, connection state              |

### 7.4 API Service Layer

`frontend/src/services/api.ts` provides typed API clients using Axios:

- `appsApi` -- CRUD + upload + stats
- `scansApi` -- CRUD + progress + purge + bulk operations
- `findingsApi` -- list + filters + status workflow + bulk operations
- `devicesApi` -- discovery + registration + Frida management
- `fridaApi` -- script CRUD + injection + session management
- `bypassApi` -- protection analysis + bypass attempts + auto-bypass
- `drozerApi` -- session management + module execution + quick actions
- `objectionApi` -- session management + file/SQL/plist operations
- `mlModelsApi` -- extraction + security analysis
- `secretsApi` -- listing + validation
- `attackPathsApi` -- generation + graph visualization
- `complianceApi` -- MASVS mapping + report generation
- `exportsApi` -- findings/report export (PDF, JSON, CSV, SARIF)
- `burpApi` -- connection management + scan integration + proxy history
- `scheduledScansApi` -- cron config + trigger + history
- `webhooksApi` -- CRUD + test + delivery history
- `apiEndpointsApi` -- listing + export + probing
- `settingsApi` -- platform status and configuration

Authentication is handled via Bearer tokens stored in `localStorage`. The
Axios request interceptor attaches the `Authorization` header automatically.
401 responses trigger token removal.

### 7.5 Layout and Navigation

`frontend/src/components/AppLayout.vue` provides:

- Collapsible sidebar (260px expanded, 64px collapsed)
- Mobile-responsive layout (hamburger menu below 768px)
- Dark mode toggle (persisted to `localStorage`)
- Keyboard shortcuts (Alt+D for Dashboard, Alt+S for Scans, etc.)
- PrimeVue icon-based navigation with active state highlighting

---

## 8. Data Flow

### 8.1 Upload -> Parse -> Store

```
Browser                    API                           PostgreSQL
  |                         |                               |
  |-- POST /api/apps ------>|                               |
  |   (multipart file)      |                               |
  |                         |-- validate size/type          |
  |                         |-- save to /app/uploads/       |
  |                         |-- AppParser.parse(file)       |
  |                         |   (extract manifest/plist,    |
  |                         |    signing info, SDK versions)|
  |                         |-- FrameworkDetector.detect()  |
  |                         |   (Flutter/RN/Xamarin/native) |
  |                         |-- INSERT mobile_apps -------->|
  |                         |                               |
  |<-- 201 {app_id, ...} --|                               |
```

### 8.2 Scan -> Analyze -> Findings

```
Browser                    API                           PostgreSQL
  |                         |                               |
  |-- POST /api/scans ----->|                               |
  |   {app_id, scan_type}   |                               |
  |                         |-- INSERT scans (pending) ---->|
  |<-- 202 {scan_id} ------|                               |
  |                         |                               |
  |                    [Background Task]                    |
  |                         |                               |
  |                     ScanOrchestrator.execute_scan()     |
  |                         |                               |
  |                     For each analyzer:                  |
  |                         |-- UPDATE scans (progress) --->|
  |                         |-- analyzer.analyze(app)       |
  |                         |-- INSERT findings ----------->|
  |                         |-- INSERT secrets (if any) --->|
  |                         |                               |
  |                         |-- UPDATE scans (completed) -->|
  |                         |-- UPDATE mobile_apps -------->|
  |                         |                               |
  |-- GET /api/scans/:id -->|                               |
  |   (poll for progress)   |-- SELECT scans -------------->|
  |<-- {status, progress} --|                               |
```

### 8.3 Dynamic Analysis Flow

```
API Container            Host Machine              Android Device
  |                         |                          |
  |-- FRIDA_SERVER_HOST --->|                          |
  |   (TCP :27042)          |-- adb forward ---------->|
  |                         |                          |
  | FridaService.inject():  |                          |
  |  add_remote_device()    |                          |
  |  device.spawn(pkg)      |------------------------->| spawn process
  |  device.attach(pid)     |------------------------->| attach
  |  device.resume(pid)     |------------------------->| resume
  |  script.load()          |------------------------->| inject JS
  |                         |                          |
  |  <--- messages ---------|<-------------------------| [+]/[-] markers
  |                         |                          |
  | Evaluate results:       |                          |
  |  parse markers          |                          |
  |  create findings        |                          |
  |                         |                          |
  | FridaService.detach():  |                          |
  |  script.unload()        |------------------------->| cleanup
  |  session.detach()       |------------------------->|
```

### 8.4 Export Flow

```
Browser                    API                           PostgreSQL
  |                         |                               |
  |-- GET /api/exports/ --->|                               |
  |   /findings/{app_id}    |                               |
  |   ?format=pdf           |                               |
  |                         |-- SELECT findings ----------->|
  |                         |-- SELECT app metadata ------->|
  |                         |                               |
  |                         |-- ReportService.generate()    |
  |                         |   (fpdf2 for PDF,             |
  |                         |    json.dumps for JSON,       |
  |                         |    csv.writer for CSV,        |
  |                         |    SARIF format)              |
  |                         |                               |
  |<-- blob (file download)-|                               |
```

Supported export formats:
- **PDF** -- generated via fpdf2 (pure Python, no C dependencies)
- **JSON** -- structured finding data
- **CSV** -- tabular format
- **SARIF** -- Static Analysis Results Interchange Format

---

## 9. Security Considerations

### 9.1 Command Injection Prevention

`api/services/device_manager.py` -- `_validate_device_id()`:

```python
VALID_DEVICE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9.:_-]+$')

def _validate_device_id(device_id: str) -> str:
    if not device_id or len(device_id) > 128:
        raise ValueError("Invalid device ID length")
    if not VALID_DEVICE_ID_PATTERN.match(device_id):
        raise ValueError(f"Invalid device ID format: {device_id}")
    return device_id
```

This function is called **before every ADB/idevice subprocess call** to
prevent shell injection via crafted device IDs. Package names are similarly
validated with `re.match(r'^[a-zA-Z0-9._]+$', package_name)`.

All subprocess calls use list-form arguments (no `shell=True`) with explicit
timeouts.

### 9.2 Input Validation

- **Pydantic models** validate all API request bodies
- **File uploads** checked against `max_apk_size_mb` (500 MB) and
  `max_ipa_size_mb` (1000 MB)
- **Path traversal** prevented on file operations
- **JSONB fields** accept arbitrary structures but are validated at the
  application layer

### 9.3 Authentication

- JWT-based Bearer token authentication
- Configured via `SECRET_KEY`, `JWT_ALGORITHM` (HS256), `JWT_EXPIRATION_HOURS`
  (24h)
- Frontend stores token in `localStorage`
- Axios interceptor attaches `Authorization: Bearer <token>` to all requests
- 401 responses trigger automatic token removal and re-authentication

### 9.4 Container Security

- API source code mounted as `:ro` (read-only) -- changes require container
  rebuild
- Analyzer containers spawned on-demand via Docker socket with:
  - Memory limits (`4g` default)
  - Execution timeouts (`3600s` default)
  - Isolated network
- Sensitive environment variables (passwords, API keys) loaded from `.env` file,
  not hardcoded

### 9.5 Data Protection

- Secrets in findings are stored with redacted values (`secret_value_redacted`)
- Original secret values are hashed, never stored in plaintext
- Credentials are never logged (logger output sanitized)
- Neo4j and PostgreSQL credentials passed via environment variables

---

## 10. Directory Structure

```
mobilicustos/
  docker-compose.yml            # Service orchestration
  init.sql                      # PostgreSQL schema initialization
  .env                          # Environment configuration
  api/
    main.py                     # FastAPI application entry point
    config.py                   # Settings (pydantic_settings)
    database.py                 # AsyncEngine, session factory
    Dockerfile                  # API container image
    models/
      database.py               # SQLAlchemy ORM models (14 tables)
    routers/                    # 33 APIRouter modules
      apps.py, scans.py, findings.py, devices.py, frida.py,
      bypass.py, drozer.py, objection.py, compliance.py,
      exports.py, dashboard.py, reports.py, ...
    services/                   # Business logic
      scan_orchestrator.py      # Scan pipeline coordinator
      bypass_orchestrator.py    # Anti-detection bypass framework
      frida_service.py          # Frida injection & session mgmt
      device_manager.py         # ADB/iOS device management
      docker_executor.py        # Analyzer container spawning
      app_parser.py             # APK/IPA metadata extraction
      framework_detector.py     # Flutter/RN/Xamarin detection
      report_service.py         # PDF/JSON report generation
      ml_analyzer.py            # ML model extraction & analysis
      secret_validator.py       # Secret validation service
      attack_path_analyzer.py   # Neo4j attack graph generation
      corellium_service.py      # Corellium virtual device API
      drozer_service.py         # Drozer session management
      objection_service.py      # Objection session management
      webhook_service.py        # Outbound webhook delivery
      ...
      analyzers/                # 33 security analyzer modules
        base_analyzer.py        # Abstract base class
        manifest_analyzer.py    # AndroidManifest.xml
        dex_analyzer.py         # DEX bytecode
        secret_scanner.py       # Hardcoded secrets
        flutter_analyzer.py     # Flutter-specific
        runtime_analyzer.py     # Dynamic runtime analysis
        network_analyzer.py     # Network traffic analysis
        ...
    data/
      frida_scripts/            # Built-in Frida scripts (seeded on startup)
      known_findings/           # Finding template registry
  frontend/
    Dockerfile                  # Frontend container (nginx)
    src/
      main.ts                   # Vue app entry point
      App.vue                   # Root component
      router/index.ts           # Vue Router configuration (20 routes)
      services/api.ts           # Axios-based API client (18 API modules)
      stores/                   # Pinia state management
        apps.ts, scans.ts, findings.ts, devices.ts
      views/                    # Page-level components
      components/               # Reusable UI components
        AppLayout.vue           # Sidebar layout + navigation
      composables/              # Vue composables (keyboard shortcuts, etc.)
      types/                    # TypeScript type definitions
  report-processor/
    Dockerfile
    ...                         # Finding normalization & MASVS mapping
  knowledge-base/               # Remediation content library
  reports/                      # Generated report output
  uploads/                      # Uploaded APK/IPA files
  docs/
    ARCHITECTURE.md             # This document
```
