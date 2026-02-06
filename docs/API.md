# Mobilicustos API Reference

Comprehensive REST API documentation for the Mobilicustos mobile security assessment platform. Built with FastAPI, the API provides interactive documentation at:

- **Swagger UI**: `http://localhost:8000/docs`
- **ReDoc**: `http://localhost:8000/redoc`

---

## Table of Contents

- [Base URL](#base-url)
- [Authentication](#authentication)
- [Pagination](#pagination)
- [Error Responses](#error-responses)
- [Rate Limiting](#rate-limiting)
- [Apps](#apps)
- [Scans](#scans)
- [Findings](#findings)
- [Devices](#devices)
- [Frida](#frida)
- [Compliance](#compliance)
- [Attack Paths](#attack-paths)
- [Secrets](#secrets)
- [Bypass](#bypass)
- [Exports](#exports)
- [Drozer](#drozer)
- [Objection](#objection)
- [Scheduled Scans](#scheduled-scans)
- [Webhooks](#webhooks)
- [Burp Suite](#burp-suite)
- [API Endpoints Discovery](#api-endpoints-discovery)
- [Settings](#settings)

---

## Base URL

```
http://localhost:8000/api
```

## Authentication

Bearer token via the `Authorization` header:

```
Authorization: Bearer <token>
```

Currently, the API does not require authentication for local development. Production deployments should implement JWT authentication.

## Pagination

List endpoints use page-based pagination with these query parameters:

| Parameter   | Type | Default | Description          |
|-------------|------|---------|----------------------|
| `page`      | int  | 1       | Page number (>= 1)  |
| `page_size` | int  | 20      | Items per page (1-100) |

Response format:

```json
{
  "items": [...],
  "total": 150,
  "page": 1,
  "page_size": 20,
  "pages": 8
}
```

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message describing the issue"
}
```

**Common HTTP Status Codes:**

| Code  | Meaning            |
|-------|--------------------|
| `400` | Bad Request        |
| `404` | Not Found          |
| `409` | Conflict           |
| `422` | Validation Error   |
| `500` | Internal Server Error |

## Rate Limiting

Production deployments enforce:

- 100 requests/minute for general endpoints
- 10 requests/minute for file uploads
- 5 concurrent scans per user

---

## Apps

Manage mobile applications (APK/IPA uploads, metadata, statistics).

**Prefix:** `/api/apps`

### List Apps

```
GET /api/apps
```

List all mobile apps with pagination and filters.

**Query Parameters:**

| Parameter  | Type   | Description                        |
|------------|--------|------------------------------------|
| `page`     | int    | Page number (default: 1)           |
| `page_size`| int    | Items per page (default: 20, max: 100) |
| `platform` | string | Filter by platform (`android`, `ios`) |
| `framework`| string | Filter by framework (`native`, `flutter`, `react_native`, etc.) |
| `status`   | string | Filter by status (`pending`, `analyzed`) |
| `search`   | string | Search in package_name or app_name |

**Response:** `PaginatedResponse` containing `MobileAppResponse` items.

**Example:**

```bash
curl "http://localhost:8000/api/apps?platform=android&search=lenovo&page_size=10"
```

---

### Get App

```
GET /api/apps/{app_id}
```

Get a single mobile app by its ID.

**Path Parameters:**

| Parameter | Type   | Description     |
|-----------|--------|-----------------|
| `app_id`  | string | The app UUID    |

**Response:**

```json
{
  "app_id": "b082b421-654d-4e97-8bc9-8ee0b1d72629",
  "package_name": "com.lenovo.fs360",
  "app_name": "FS360",
  "version_name": "1.0.0",
  "platform": "android",
  "framework": "flutter",
  "framework_version": "3.x",
  "status": "pending",
  "file_hash_sha256": "abc123...",
  "file_size_bytes": 52428800,
  "min_sdk_version": 21,
  "target_sdk_version": 33,
  "upload_date": "2026-02-03T12:00:00Z"
}
```

---

### Upload App

```
POST /api/apps
Content-Type: multipart/form-data
```

Upload a mobile app (APK or IPA file). The file is parsed for metadata, framework detection runs automatically, and a SHA-256 hash is computed for deduplication.

**Request Body (multipart/form-data):**

| Field  | Type | Description              |
|--------|------|--------------------------|
| `file` | File | APK or IPA binary (required) |

**Constraints:**

- Only `.apk` and `.ipa` file extensions are accepted.
- File size limits are configurable via settings (`max_apk_size_mb`, `max_ipa_size_mb`).
- Duplicate uploads (same SHA-256 hash) return `409 Conflict`.

**Example:**

```bash
curl -X POST http://localhost:8000/api/apps \
  -F "file=@app.apk"
```

**Response:** `MobileAppResponse` (see Get App above).

---

### Delete App

```
DELETE /api/apps/{app_id}
```

Delete an app and its associated file on disk. Cascade-deletes associated scans and findings.

**Response:**

```json
{
  "message": "App deleted successfully"
}
```

---

### Get App Stats

```
GET /api/apps/{app_id}/stats
```

Get aggregated statistics for an app: scan count, total findings, findings breakdown by severity and category.

**Response:**

```json
{
  "app_id": "b082b421-...",
  "scan_count": 5,
  "total_findings": 30,
  "findings_by_severity": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 3
  },
  "findings_by_category": {
    "Cryptography": 5,
    "Data Storage": 8,
    "Network Security": 7
  }
}
```

---

## Scans

Manage security scans (create, monitor, cancel, delete, purge).

**Prefix:** `/api/scans`

### List Scans

```
GET /api/scans
```

**Query Parameters:**

| Parameter   | Type   | Description                   |
|-------------|--------|-------------------------------|
| `page`      | int    | Page number                   |
| `page_size` | int    | Items per page                |
| `app_id`    | string | Filter by app                 |
| `status`    | string | Filter: `pending`, `running`, `completed`, `failed`, `cancelled` |
| `scan_type` | string | Filter: `static`, `dynamic`, `full`, `scheduled` |

**Response:** `PaginatedResponse` containing `ScanResponse` items.

---

### Get Scan

```
GET /api/scans/{scan_id}
```

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `scan_id` | UUID | Scan identifier |

**Response:**

```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "app_id": "b082b421-...",
  "scan_type": "static",
  "analyzers_enabled": ["manifest_analyzer", "crypto_auditor"],
  "status": "completed",
  "progress": 100,
  "current_analyzer": null,
  "findings_count": 15,
  "created_at": "2026-02-03T12:00:00Z",
  "completed_at": "2026-02-03T12:05:30Z"
}
```

---

### Create Scan

```
POST /api/scans
Content-Type: application/json
```

Create and start a new scan. The scan runs in the background.

**Request Body:**

```json
{
  "app_id": "b082b421-...",
  "scan_type": "static",
  "analyzers_enabled": ["manifest_analyzer", "crypto_auditor"]
}
```

| Field               | Type     | Required | Description |
|---------------------|----------|----------|-------------|
| `app_id`            | string   | Yes      | Target app ID |
| `scan_type`         | string   | Yes      | `static`, `dynamic`, or `full` |
| `analyzers_enabled` | string[] | No       | Specific analyzers to run (empty = all) |

**Scan Types:**

- `static` -- Static analysis only (code, manifest, crypto, etc.)
- `dynamic` -- Dynamic analysis with a device (runs `runtime_analyzer`, `network_analyzer`)
- `full` -- Complete static + dynamic analysis

**Response:** `ScanResponse`

---

### Get Scan Progress

```
GET /api/scans/{scan_id}/progress
```

Get real-time progress of a running scan.

**Response:**

```json
{
  "scan_id": "550e8400-...",
  "status": "running",
  "progress": 65,
  "current_analyzer": "crypto_auditor",
  "findings_count": 8,
  "analyzer_errors": {}
}
```

---

### Cancel Scan

```
POST /api/scans/{scan_id}/cancel
```

Cancel a `pending` or `running` scan.

**Response:**

```json
{
  "message": "Scan cancelled successfully"
}
```

---

### Delete Scan

```
DELETE /api/scans/{scan_id}
```

Delete a scan and all associated findings. Cannot delete a `running` scan -- cancel it first.

**Response:**

```json
{
  "message": "Scan deleted successfully"
}
```

---

### Purge Scans by App

```
DELETE /api/scans/purge/{app_id}
```

Delete ALL scans (and cascade-delete findings) for a given app. Fails if any scan is currently running.

**Response:**

```json
{
  "message": "Purged 5 scans",
  "deleted_count": 5
}
```

---

### Bulk Delete Scans

```
POST /api/scans/bulk-delete
Content-Type: application/json
```

Delete multiple scans by ID. Cannot delete running scans.

**Request Body:**

```json
["550e8400-e29b-41d4-a716-446655440000", "660f9500-..."]
```

**Response:**

```json
{
  "message": "Deleted 2 scans",
  "deleted_count": 2
}
```

---

## Findings

Manage security findings (list, filter, sort, update status, bulk operations, purge).

**Prefix:** `/api/findings`

### List Findings

```
GET /api/findings
```

**Query Parameters:**

| Parameter              | Type     | Description |
|------------------------|----------|-------------|
| `page`                 | int      | Page number |
| `page_size`            | int      | Items per page |
| `severity`             | string[] | Filter: `critical`, `high`, `medium`, `low`, `info` |
| `status`               | string[] | Filter: `open`, `confirmed`, `false_positive`, `accepted_risk`, `remediated` |
| `platform`             | string[] | Filter: `android`, `ios`, `cross-platform` |
| `category`             | string[] | Filter by finding category |
| `tool`                 | string[] | Filter by analyzer tool |
| `owasp_masvs_category` | string[] | Filter by MASVS category |
| `cwe_id`               | string[] | Filter by CWE ID |
| `app_id`               | string   | Filter by app |
| `scan_id`              | UUID     | Filter by scan |
| `search`               | string   | Search in title and description |
| `sort_by`              | string   | Sort field: `severity` (default), `title`, `created_at`, `status`, `tool` |
| `sort_order`           | string   | `asc` or `desc` (default) |

**Example:**

```bash
curl "http://localhost:8000/api/findings?severity=critical&severity=high&sort_by=severity&page_size=10"
```

**Response:**

```json
{
  "items": [
    {
      "finding_id": "abc123-...",
      "app_id": "b082b421-...",
      "scan_id": "550e8400-...",
      "tool": "crypto_auditor",
      "severity": "critical",
      "status": "open",
      "title": "Hardcoded Encryption Key",
      "description": "AES key found hardcoded in source...",
      "impact": "Attacker can decrypt all stored data...",
      "remediation": "Use Android Keystore to generate and store keys...",
      "category": "Cryptography",
      "file_path": "com/example/crypto/Manager.java",
      "line_number": 45,
      "code_snippet": "private static final String KEY = \"abc123\";",
      "cwe_id": "CWE-321",
      "cvss_score": 9.1,
      "owasp_masvs_category": "MASVS-CRYPTO",
      "owasp_masvs_control": "MASVS-CRYPTO-1",
      "poc_evidence": "...",
      "created_at": "2026-02-03T12:05:00Z"
    }
  ],
  "total": 150,
  "page": 1,
  "page_size": 10,
  "pages": 15
}
```

---

### Get Findings Summary

```
GET /api/findings/summary
```

Aggregated summary statistics for findings.

**Query Parameters:**

| Parameter | Type   | Description       |
|-----------|--------|-------------------|
| `app_id`  | string | Filter by app     |
| `scan_id` | UUID   | Filter by scan    |

**Response:**

```json
{
  "total": 150,
  "by_severity": {
    "critical": 2,
    "high": 5,
    "medium": 12,
    "low": 8,
    "info": 3
  },
  "by_status": {
    "open": 25,
    "confirmed": 3,
    "false_positive": 2
  },
  "by_category": {
    "Cryptography": 5,
    "Data Storage": 8
  },
  "by_masvs": {
    "MASVS-CRYPTO": 5,
    "MASVS-STORAGE": 8
  },
  "by_tool": {
    "manifest_analyzer": 8,
    "crypto_auditor": 5,
    "dex_analyzer": 7
  }
}
```

---

### Get Filter Options

```
GET /api/findings/filters/options
```

Returns all available filter values currently present in the database.

**Response:**

```json
{
  "severities": ["critical", "high", "medium", "low", "info"],
  "statuses": ["open", "confirmed", "false_positive", "accepted_risk", "remediated"],
  "platforms": ["android", "ios", "cross-platform"],
  "categories": ["Cryptography", "Data Storage", "Network Security"],
  "tools": ["manifest_analyzer", "crypto_auditor", "dex_analyzer"],
  "masvs_categories": ["MASVS-CRYPTO", "MASVS-STORAGE"],
  "cwe_ids": ["CWE-321", "CWE-295"]
}
```

---

### Get Finding

```
GET /api/findings/{finding_id}
```

**Response:** Full `FindingResponse` object.

---

### Update Finding Status

```
PATCH /api/findings/{finding_id}/status
```

**Query Parameters:**

| Parameter    | Type   | Required | Description |
|--------------|--------|----------|-------------|
| `new_status` | string | Yes      | One of: `open`, `confirmed`, `false_positive`, `accepted_risk`, `remediated` |

**Example:**

```bash
curl -X PATCH "http://localhost:8000/api/findings/abc123/status?new_status=confirmed"
```

**Response:**

```json
{
  "message": "Status updated successfully",
  "new_status": "confirmed"
}
```

---

### Bulk Update Status

```
POST /api/findings/bulk-status?new_status=false_positive
Content-Type: application/json
```

Update status of up to 1000 findings at once.

**Request Body:**

```json
["finding-id-1", "finding-id-2", "finding-id-3"]
```

**Response:**

```json
{
  "message": "Updated 3 findings",
  "new_status": "false_positive"
}
```

---

### Delete Finding

```
DELETE /api/findings/{finding_id}
```

**Response:**

```json
{
  "message": "Finding deleted successfully"
}
```

---

### Bulk Delete Findings

```
POST /api/findings/bulk-delete
Content-Type: application/json
```

Delete up to 1000 findings at once.

**Request Body:**

```json
["finding-id-1", "finding-id-2"]
```

**Response:**

```json
{
  "message": "Deleted 2 findings"
}
```

---

### Purge Findings by App

```
DELETE /api/findings/purge/{app_id}
```

Delete ALL findings for a given app.

**Response:**

```json
{
  "message": "Purged 150 findings",
  "deleted_count": 150
}
```

---

## Devices

Manage physical and virtual test devices (discover, register, connect, manage Frida server).

**Prefix:** `/api/devices`

### List Devices

```
GET /api/devices
```

**Query Parameters:**

| Parameter     | Type   | Description |
|---------------|--------|-------------|
| `page`        | int    | Page number |
| `page_size`   | int    | Items per page |
| `platform`    | string | `android` or `ios` |
| `device_type` | string | `physical`, `emulator`, `genymotion`, `corellium` |
| `status`      | string | `connected`, `disconnected`, `error` |

---

### Discover Devices

```
GET /api/devices/discover
```

Automatically discover connected Android devices via ADB and iOS devices via libimobiledevice. Discovered devices are upserted into the database.

**Response:**

```json
{
  "discovered": 2,
  "android": 1,
  "ios": 1,
  "devices": [
    {
      "device_id": "89AB1234",
      "model": "Pixel 3 XL",
      "android_version": "11",
      "is_rooted": true,
      "device_type": "physical"
    }
  ]
}
```

---

### Get Device

```
GET /api/devices/{device_id}
```

**Response:** `DeviceResponse`

---

### Register Device

```
POST /api/devices
Content-Type: application/json
```

Manually register a device.

**Request Body:**

```json
{
  "device_id": "emulator-5554",
  "name": "Pixel 6 Emulator",
  "device_type": "emulator",
  "platform": "android"
}
```

**Device Types:** `physical`, `emulator`, `genymotion`, `corellium`

---

### Connect Device

```
POST /api/devices/{device_id}/connect
```

Establish a connection to a registered device.

**Response:**

```json
{
  "message": "Connected successfully"
}
```

---

### Install Frida Server

```
POST /api/devices/{device_id}/frida/install
```

Download and install the appropriate Frida server binary on a connected device. The device must be rooted (Android) or jailbroken (iOS).

**Preconditions:** Device must have status `connected`.

**Response:**

```json
{
  "message": "Frida server 16.5.9 installed"
}
```

---

### Start Frida Server

```
POST /api/devices/{device_id}/frida/start
```

Start the Frida server process on the device.

**Response:**

```json
{
  "message": "Frida server started"
}
```

---

### Delete Device

```
DELETE /api/devices/{device_id}
```

**Response:**

```json
{
  "message": "Device deleted successfully"
}
```

---

## Frida

Manage Frida scripts, inject into running apps, and monitor sessions.

**Prefix:** `/api/frida`

### List Scripts

```
GET /api/frida/scripts
```

**Query Parameters:**

| Parameter    | Type   | Description |
|--------------|--------|-------------|
| `page`       | int    | Page number |
| `page_size`  | int    | Items per page |
| `category`   | string | Script category (e.g., `bypass`, `monitoring`) |
| `subcategory`| string | Script subcategory (e.g., `ssl_pinning`, `root`) |
| `platform`   | string | `android` or `ios` |
| `search`     | string | Search in name and description |

**Response:** `PaginatedResponse` containing `FridaScriptResponse` items.

---

### Get Script Categories

```
GET /api/frida/scripts/categories
```

Returns a map of categories to their subcategories.

**Response:**

```json
{
  "bypass": ["ssl_pinning", "root", "frida", "emulator"],
  "monitoring": ["network", "crypto", "filesystem"],
  "custom": []
}
```

---

### Get Script

```
GET /api/frida/scripts/{script_id}
```

**Path Parameters:**

| Parameter   | Type | Description |
|-------------|------|-------------|
| `script_id` | UUID | Script identifier |

---

### Create Script

```
POST /api/frida/scripts
Content-Type: application/json
```

Create a new Frida script via JSON body.

**Request Body:**

```json
{
  "script_name": "Custom SSL Bypass",
  "description": "Bypasses OkHttp certificate pinning",
  "category": "bypass",
  "subcategory": "ssl_pinning",
  "platforms": ["android"],
  "script_content": "Java.perform(function() { ... });"
}
```

---

### Import Script

```
POST /api/frida/scripts/import
Content-Type: multipart/form-data
```

Import a Frida script from a file upload or URL.

**Form Fields:**

| Field         | Type   | Description |
|---------------|--------|-------------|
| `file`        | File   | JavaScript file (.js), max 5MB |
| `url`         | string | URL to fetch script from; supports `codeshare:<project-id>` |
| `script_name` | string | Optional name override |
| `category`    | string | Category (default: `custom`) |
| `subcategory` | string | Optional subcategory |
| `description` | string | Optional description |
| `platforms`    | string | Comma-separated: `android,ios` (default: both) |

Provide either `file` or `url`, not both.

**Supported URL formats:**
- Direct URL to a `.js` file
- GitHub raw URLs
- Frida CodeShare: `codeshare:project-name`

---

### Update Script

```
PUT /api/frida/scripts/{script_id}
Content-Type: application/json
```

Update a custom Frida script. Built-in scripts cannot be modified.

---

### Delete Script

```
DELETE /api/frida/scripts/{script_id}
```

Delete a custom script. Built-in scripts cannot be deleted.

---

### Inject Script

```
POST /api/frida/inject
```

Inject a Frida script into a running app on a connected device.

**Query Parameters:**

| Parameter        | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `device_id`      | string | Yes      | Target device |
| `app_id`         | string | Yes      | Target app |
| `script_id`      | UUID   | No       | Script to inject (provide this or `script_content`) |
| `script_content` | string | No       | Inline script content |

**Response:**

```json
{
  "message": "Script injected successfully",
  "session_id": "session-abc123"
}
```

---

### List Frida Sessions

```
GET /api/frida/sessions
```

List all active Frida sessions.

**Response:**

```json
{
  "sessions": [
    {
      "session_id": "session-abc123",
      "device_id": "89AB1234",
      "pid": 12345,
      "package_name": "com.example.app"
    }
  ]
}
```

---

### Detach Frida Session

```
DELETE /api/frida/sessions/{session_id}
```

Detach from a Frida session.

**Response:**

```json
{
  "message": "Session detached"
}
```

---

## Compliance

OWASP MASVS v2 compliance assessment.

**Prefix:** `/api/compliance`

### Get MASVS Overview

```
GET /api/compliance/masvs
```

Returns the complete OWASP MASVS v2 framework: categories, controls, names, and descriptions.

**Response:**

```json
{
  "version": "2.0",
  "categories": {
    "MASVS-STORAGE": {
      "name": "Storage",
      "description": "Secure storage of sensitive data on a device",
      "controls": ["MASVS-STORAGE-1", "MASVS-STORAGE-2"],
      "controls_detail": [
        {
          "id": "MASVS-STORAGE-1",
          "name": "Secure Data Storage",
          "description": "The app securely stores sensitive data."
        }
      ]
    }
  }
}
```

**MASVS v2 Categories:** `MASVS-STORAGE`, `MASVS-CRYPTO`, `MASVS-AUTH`, `MASVS-NETWORK`, `MASVS-PLATFORM`, `MASVS-CODE`, `MASVS-RESILIENCE`, `MASVS-PRIVACY`

---

### Get App Compliance

```
GET /api/compliance/masvs/{app_id}
```

Get MASVS compliance status for a specific app, including per-category scores, control-level pass/fail, and summary.

**Response:**

```json
{
  "app_id": "b082b421-...",
  "masvs_version": "2.0",
  "overall_score": 62.5,
  "categories": {
    "MASVS-CRYPTO": {
      "name": "Cryptography",
      "status": "fail",
      "score": 50.0,
      "controls": {
        "MASVS-CRYPTO-1": { "status": "fail", "findings_count": 3 },
        "MASVS-CRYPTO-2": { "status": "not_tested", "findings_count": 0 }
      },
      "findings": { "total": 3, "critical": 1, "high": 2, "open": 3 }
    }
  },
  "controls": {
    "MASVS-CRYPTO-1": { "id": "MASVS-CRYPTO-1", "category": "MASVS-CRYPTO", "status": "fail", "findings_count": 3 }
  },
  "summary": { "pass": 5, "fail": 2, "warning": 1 }
}
```

**Category Statuses:** `pass`, `fail`, `warning`
**Control Statuses:** `pass`, `fail`, `not_tested`

---

### Get Category Details

```
GET /api/compliance/masvs/{app_id}/{category}
```

Get detailed findings for a specific MASVS category.

**Path Parameters:**

| Parameter  | Type   | Description |
|------------|--------|-------------|
| `app_id`   | string | App ID |
| `category` | string | MASVS category (e.g., `MASVS-CRYPTO`) |

**Response:**

```json
{
  "app_id": "b082b421-...",
  "category": "MASVS-CRYPTO",
  "category_info": { "name": "Cryptography", "description": "...", "controls": [...] },
  "findings": [
    {
      "finding_id": "abc123",
      "title": "Hardcoded Encryption Key",
      "severity": "critical",
      "status": "open",
      "control": "MASVS-CRYPTO-1",
      "mastg_test": "MASTG-TEST-0014",
      "description": "...",
      "remediation": "..."
    }
  ],
  "total_findings": 3
}
```

---

### Generate Compliance Report

```
GET /api/compliance/report/{app_id}
```

Generate a full MASVS compliance report including app metadata, compliance matrix, and all findings.

**Response:** JSON report with `report_type`, `app`, `compliance`, `findings`, and `generated_at`.

---

## Attack Paths

Generate and visualize attack paths based on chained findings.

**Prefix:** `/api/attack-paths`

### List Attack Paths

```
GET /api/attack-paths
```

**Query Parameters:**

| Parameter        | Type   | Description |
|------------------|--------|-------------|
| `page`           | int    | Page number |
| `page_size`      | int    | Items per page |
| `app_id`         | string | Filter by app |
| `exploitability` | string | Filter by exploitability level |

**Response:** Paginated list of attack path objects with steps, risk scores, and impact analysis.

```json
{
  "items": [
    {
      "path_id": "uuid",
      "title": "Data Exfiltration via Insecure Storage + Network",
      "description": "...",
      "attack_vector": "local",
      "risk_level": "critical",
      "risk_score": 9.2,
      "exploitability": "high",
      "findings_count": 3,
      "steps": [
        { "type": "entry_point", "title": "Insecure SharedPreferences", "severity": "high" },
        { "type": "vulnerability", "title": "Missing SSL Pinning", "severity": "medium" },
        { "type": "impact", "title": "Data Exfiltration", "severity": "critical" }
      ],
      "impact": { "confidentiality": 80, "integrity": 50, "availability": 20 }
    }
  ]
}
```

---

### Get Attack Path

```
GET /api/attack-paths/{path_id}
```

Get a single attack path with full details.

---

### Get Attack Path Findings

```
GET /api/attack-paths/{path_id}/findings
```

Get ordered findings that compose the attack chain.

**Response:**

```json
{
  "path_id": "uuid",
  "title": "Attack Path Name",
  "findings": [
    {
      "finding_id": "...",
      "title": "...",
      "severity": "high",
      "category": "...",
      "description": "...",
      "file_path": "...",
      "code_snippet": "..."
    }
  ]
}
```

---

### Get Attack Path Graph

```
GET /api/attack-paths/{path_id}/graph
```

Get graph data (nodes and edges) for visualization.

**Response:**

```json
{
  "path_id": "uuid",
  "path_name": "Data Exfiltration Path",
  "nodes": [
    { "id": "finding-1", "label": "Insecure Storage", "severity": "high", "position": 0 }
  ],
  "edges": [
    { "source": "finding-1", "target": "finding-2", "label": "leads to" }
  ]
}
```

---

### Generate Attack Paths

```
POST /api/attack-paths/generate?app_id={app_id}
```

Analyze open findings for an app and generate attack paths by chaining related vulnerabilities.

**Query Parameters:**

| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `app_id`  | string | Yes      | Target app  |

**Response:**

```json
{
  "app_id": "b082b421-...",
  "generated": 3,
  "paths": [...]
}
```

---

### Delete Attack Path

```
DELETE /api/attack-paths/{path_id}
```

---

## Secrets

Detect and validate hardcoded secrets, API keys, and credentials.

**Prefix:** `/api/secrets`

### List Secrets

```
GET /api/secrets
```

**Query Parameters:**

| Parameter      | Type   | Description |
|----------------|--------|-------------|
| `page`         | int    | Page number |
| `page_size`    | int    | Items per page |
| `app_id`       | string | Filter by app |
| `secret_type`  | string | Filter: `api_key`, `token`, `password`, `private_key`, `certificate`, `database_url`, `oauth_secret` |
| `provider`     | string | Filter by provider (e.g., `aws`, `firebase`, `stripe`) |
| `exposure_risk` | string | Filter: `critical`, `high`, `medium`, `low` |
| `is_valid`     | bool   | Filter by validation status |

---

### Get Secrets Summary

```
GET /api/secrets/summary
```

**Query Parameters:**

| Parameter | Type   | Description |
|-----------|--------|-------------|
| `app_id`  | string | Filter by app |

**Response:**

```json
{
  "total": 12,
  "by_type": { "api_key": 5, "token": 3, "password": 4 },
  "by_provider": { "aws": 3, "firebase": 2 },
  "by_risk": { "critical": 2, "high": 5, "medium": 5 },
  "validated_secrets": 4
}
```

---

### Get Secret Types

```
GET /api/secrets/types
```

Returns all supported secret types with their associated providers.

---

### Get Providers

```
GET /api/secrets/providers
```

Returns all detected providers across all secrets, with counts.

---

### Get Secret

```
GET /api/secrets/{secret_id}
```

---

### Validate Secret

```
POST /api/secrets/{secret_id}/validate
```

Attempt to validate whether a detected secret is active/valid by testing it against the provider's API.

**Response:**

```json
{
  "secret_id": "uuid",
  "is_valid": true,
  "error": null
}
```

---

## Bypass

Detect and bypass app protection mechanisms (root detection, SSL pinning, Frida detection, etc.).

**Prefix:** `/api/bypass`

### List Bypass Results

```
GET /api/bypass/results
```

**Query Parameters:**

| Parameter        | Type   | Description |
|------------------|--------|-------------|
| `page`           | int    | Page number |
| `page_size`      | int    | Items per page |
| `app_id`         | string | Filter by app |
| `detection_type` | string | Filter by type (see detection types) |
| `bypass_status`  | string | Filter: `success`, `partial`, `failed` |

---

### Analyze Protections

```
POST /api/bypass/analyze?app_id={app_id}
```

Static analysis of an app's protection mechanisms. Identifies which detections are implemented.

**Response:**

```json
{
  "app_id": "b082b421-...",
  "detections": [
    {
      "type": "root",
      "method": "file_check",
      "library": "com.scottyab.rootbeer",
      "confidence": "high"
    }
  ],
  "total": 4
}
```

---

### Attempt Bypass

```
POST /api/bypass/attempt
```

Attempt to bypass a specific protection on a connected device.

**Query Parameters:**

| Parameter        | Type   | Required | Description |
|------------------|--------|----------|-------------|
| `app_id`         | string | Yes      | Target app |
| `device_id`      | string | Yes      | Connected device |
| `detection_type` | string | Yes      | Protection to bypass |
| `script_id`      | UUID   | No       | Specific bypass script |

---

### Auto Bypass

```
POST /api/bypass/auto-bypass?app_id={app_id}&device_id={device_id}
```

Automatically detect all protections and attempt to bypass each one.

**Response:**

```json
{
  "app_id": "b082b421-...",
  "device_id": "89AB1234",
  "results": [...],
  "summary": {
    "total": 4,
    "success": 2,
    "partial": 1,
    "failed": 1
  }
}
```

---

### Get Detection Types

```
GET /api/bypass/detection-types
```

Returns available detection types with their methods.

**Detection Types:**

| Type          | Description                     | Methods |
|---------------|---------------------------------|---------|
| `frida`       | Frida instrumentation detection | port_scan, file_check, memory_scan, thread_check |
| `root`        | Root/superuser detection        | file_check, command_exec, prop_check |
| `jailbreak`   | iOS jailbreak detection         | file_check, url_scheme, fork_check, sandbox_check |
| `emulator`    | Emulator/simulator detection    | prop_check, build_check, sensor_check |
| `debugger`    | Debugger attachment detection   | ptrace, status_check, timing_check |
| `ssl_pinning` | SSL certificate pinning         | trustmanager, okhttp, alamofire, nsurlsession |

---

### Get Recommended Bypass Scripts

```
GET /api/bypass/scripts/recommended?app_id={app_id}&detection_type={type}
```

Get Frida scripts recommended for bypassing a specific detection type, prioritized by framework compatibility.

---

## Exports

Export findings and full reports in multiple formats.

**Prefix:** `/api/exports`

### Export Findings

```
GET /api/exports/findings/{app_id}
```

Export findings for an app. Use `app_id=all` to export findings across all apps.

**Query Parameters:**

| Parameter  | Type     | Description |
|------------|----------|-------------|
| `format`   | string   | `json` (default), `csv`, `sarif`, `html`, `pdf` |
| `severity` | string[] | Filter by severity |
| `status`   | string[] | Filter by status |

**Export Formats:**

| Format  | Content-Type        | Description |
|---------|---------------------|-------------|
| `json`  | application/json    | Structured JSON with full finding details |
| `csv`   | text/csv            | Tabular CSV (descriptions truncated to 200 chars) |
| `sarif` | application/json    | SARIF v2.1.0 for CI/CD integration |
| `html`  | text/html           | Styled HTML report with severity badges |
| `pdf`   | application/pdf     | PDF report with summary and detailed findings |

**Example:**

```bash
curl -o findings.sarif "http://localhost:8000/api/exports/findings/b082b421-...?format=sarif"
```

All export responses include a `Content-Disposition: attachment` header.

---

### Export Full Report

```
GET /api/exports/report/{app_id}
```

Generate a comprehensive security assessment report including app metadata, executive summary, scan history, and all findings.

**Query Parameters:**

| Parameter | Type   | Description |
|-----------|--------|-------------|
| `format`  | string | `json` (default), `html`, `pdf` |

---

## Drozer

Android dynamic security testing via Drozer integration.

**Prefix:** `/api/drozer`

### Check Drozer Status

```
GET /api/drozer/status
```

Check if Drozer is installed and available.

**Response:**

```json
{
  "installed": true,
  "message": "Drozer is available"
}
```

---

### List Modules

```
GET /api/drozer/modules
```

List available Drozer modules grouped by category.

---

### Install Drozer Agent

```
POST /api/drozer/install
Content-Type: application/json
```

Install the Drozer agent APK on an Android device.

**Request Body:**

```json
{
  "device_id": "89AB1234"
}
```

---

### Start Session

```
POST /api/drozer/sessions
Content-Type: application/json
```

Start a new Drozer session on a device.

**Request Body:**

```json
{
  "device_id": "89AB1234",
  "package_name": "com.example.app"
}
```

**Preconditions:**
- Device must be connected and Android.
- No active Drozer session on the same device.

**Response:** `DrozerSessionResponse`

---

### List Sessions

```
GET /api/drozer/sessions
```

**Query Parameters:**

| Parameter   | Type   | Description |
|-------------|--------|-------------|
| `page`      | int    | Page number |
| `page_size` | int    | Items per page |
| `device_id` | string | Filter by device |
| `status`    | string | Filter: `active`, `stopped` |

---

### Get Session

```
GET /api/drozer/sessions/{session_id}
```

---

### Run Module

```
POST /api/drozer/sessions/{session_id}/run
Content-Type: application/json
```

Execute a Drozer module within an active session.

**Request Body:**

```json
{
  "module_name": "app.package.attacksurface",
  "args": {}
}
```

**Response:** `DrozerResultResponse` with `result_type`, `result_data`, and `raw_output`.

---

### Get Session Results

```
GET /api/drozer/sessions/{session_id}/results
```

Paginated list of results from a Drozer session.

---

### Stop Session

```
DELETE /api/drozer/sessions/{session_id}
```

Stop a Drozer session.

---

### Quick Actions

Convenience endpoints that skip session management:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/drozer/quick/attack-surface?device_id=...&package_name=...` | Get attack surface for a package |
| `POST` | `/api/drozer/quick/enumerate-providers?device_id=...&package_name=...` | Enumerate content providers |
| `POST` | `/api/drozer/quick/test-sqli?device_id=...&package_name=...` | Test SQL injection in content providers |
| `POST` | `/api/drozer/quick/test-traversal?device_id=...&package_name=...` | Test path traversal in content providers |

All quick actions require `device_id` and `package_name` as query parameters. The device must be connected.

---

## Objection

Runtime mobile app manipulation via Objection (supports Android and iOS).

**Prefix:** `/api/objection`

### Check Objection Status

```
GET /api/objection/status
```

---

### List Commands

```
GET /api/objection/commands
```

**Query Parameters:**

| Parameter  | Type   | Description |
|------------|--------|-------------|
| `platform` | string | `android` or `ios` |

---

### Start Session

```
POST /api/objection/sessions
Content-Type: application/json
```

Start a new Objection session.

**Request Body:**

```json
{
  "device_id": "89AB1234",
  "package_name": "com.example.app"
}
```

---

### List Sessions

```
GET /api/objection/sessions
```

**Query Parameters:** `page`, `page_size`, `device_id`, `platform`, `status`

---

### Get Session

```
GET /api/objection/sessions/{session_id}
```

---

### Execute Command

```
POST /api/objection/sessions/{session_id}/execute
Content-Type: application/json
```

Execute an Objection command in an active session.

**Request Body:**

```json
{
  "command": "android hooking list activities",
  "args": []
}
```

---

### Stop Session

```
DELETE /api/objection/sessions/{session_id}
```

---

### File System Access

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET`  | `/api/objection/sessions/{session_id}/files?path=/data/data` | List files in a directory |
| `GET`  | `/api/objection/sessions/{session_id}/file?path=...` | Read a file's contents |

---

### Database Access

```
POST /api/objection/sessions/{session_id}/sql?db_path=...&query=...
```

Execute a SQL query on a database file within the app's sandbox.

---

### iOS Plist Reader

```
GET /api/objection/sessions/{session_id}/plist?path=...
```

Read an iOS plist file (iOS sessions only).

---

### Quick Actions

Convenience endpoints that skip session management:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/objection/quick/disable-ssl-pinning?device_id=...&package_name=...` | Disable SSL pinning |
| `POST` | `/api/objection/quick/disable-root-detection?device_id=...&package_name=...` | Disable root/jailbreak detection |
| `POST` | `/api/objection/quick/dump-keychain?device_id=...&package_name=...` | Dump keychain/keystore |
| `POST` | `/api/objection/quick/list-modules?device_id=...&package_name=...` | List loaded modules |

---

## Scheduled Scans

Manage recurring scans with cron expressions.

**Prefix:** `/api/scheduled-scans`

### Create Schedule

```
POST /api/scheduled-scans
Content-Type: application/json
```

**Request Body:**

```json
{
  "app_id": "b082b421-...",
  "name": "Nightly Full Scan",
  "cron_expression": "0 2 * * *",
  "analyzers": [],
  "is_active": true,
  "webhook_url": "https://hooks.slack.com/...",
  "notify_email": "security@example.com"
}
```

| Field             | Type     | Required | Description |
|-------------------|----------|----------|-------------|
| `app_id`          | string   | Yes      | Target app |
| `name`            | string   | Yes      | Schedule name (1-256 chars) |
| `cron_expression` | string   | Yes      | Standard cron format |
| `analyzers`       | string[] | No       | Specific analyzers (empty = all) |
| `is_active`       | bool     | No       | Active by default |
| `webhook_url`     | string   | No       | Webhook to call on completion |
| `notify_email`    | string   | No       | Email for notifications |

**Cron Examples:**

| Expression      | Description |
|-----------------|-------------|
| `0 2 * * *`     | Daily at 2 AM |
| `0 0 * * 0`     | Weekly on Sunday at midnight |
| `0 0 1 * *`     | Monthly on the 1st at midnight |
| `*/15 * * * *`  | Every 15 minutes |

**Response:** `ScheduleResponse` with `cron_description` and `next_run_at`.

---

### List Schedules

```
GET /api/scheduled-scans
```

**Query Parameters:**

| Parameter   | Type | Description |
|-------------|------|-------------|
| `app_id`    | string | Filter by app |
| `is_active` | bool   | Filter by active status |
| `page`      | int    | Page number |
| `page_size` | int    | Items per page |

---

### Get Schedule

```
GET /api/scheduled-scans/{schedule_id}
```

---

### Update Schedule

```
PUT /api/scheduled-scans/{schedule_id}
Content-Type: application/json
```

All fields are optional -- only provided fields are updated.

**Request Body:**

```json
{
  "name": "Updated Name",
  "cron_expression": "0 3 * * *",
  "is_active": false
}
```

---

### Delete Schedule

```
DELETE /api/scheduled-scans/{schedule_id}
```

---

### Trigger Schedule Manually

```
POST /api/scheduled-scans/{schedule_id}/run
```

Immediately trigger a scheduled scan regardless of cron timing.

**Response:**

```json
{
  "message": "Scan triggered successfully",
  "scan_id": "uuid",
  "schedule_id": "uuid"
}
```

---

### Pause / Resume Schedule

```
POST /api/scheduled-scans/{schedule_id}/pause
POST /api/scheduled-scans/{schedule_id}/resume
```

---

### Get Schedule History

```
GET /api/scheduled-scans/{schedule_id}/history?limit=10
```

Returns the last N scans triggered by this schedule.

---

### Validate Cron Expression

```
POST /api/scheduled-scans/validate-cron
Content-Type: application/json
```

Validate a cron expression and preview the next run times.

**Request Body:**

```json
{
  "cron_expression": "0 2 * * *"
}
```

**Response:**

```json
{
  "valid": true,
  "message": "Valid cron expression",
  "description": "At 02:00 AM every day",
  "next_runs": [
    "2026-02-06T02:00:00Z",
    "2026-02-07T02:00:00Z",
    "2026-02-08T02:00:00Z",
    "2026-02-09T02:00:00Z",
    "2026-02-10T02:00:00Z"
  ]
}
```

---

### List Due Schedules

```
GET /api/scheduled-scans/due/list
```

Internal endpoint used by the scheduler worker to find schedules that are due for execution.

---

## Webhooks

Manage webhook configurations for event-driven notifications.

**Prefix:** `/api/webhooks`

### List Event Types

```
GET /api/webhooks/events
```

Returns all available event types with descriptions and payload examples.

**Available Events:**

| Event Type                | Description |
|---------------------------|-------------|
| `scan.started`            | Triggered when a scan starts |
| `scan.completed`          | Triggered when a scan completes |
| `scan.failed`             | Triggered when a scan fails |
| `finding.new`             | Triggered when a new finding is discovered |
| `finding.status_changed`  | Triggered when a finding's status changes |
| `app.uploaded`            | Triggered when a new app is uploaded |
| `schedule.triggered`      | Triggered when a scheduled scan starts |

---

### Create Webhook

```
POST /api/webhooks
Content-Type: application/json
```

**Request Body:**

```json
{
  "name": "Slack Notifications",
  "url": "https://hooks.slack.com/services/...",
  "events": ["scan.completed", "finding.new"],
  "is_active": true,
  "headers": { "X-Custom-Header": "value" }
}
```

Webhook deliveries include these headers:

| Header                | Description |
|-----------------------|-------------|
| `X-Webhook-Signature` | HMAC SHA256 signature (`sha256=...`) |
| `X-Webhook-ID`        | The webhook ID |
| `X-Delivery-ID`       | Unique delivery ID |
| `X-Event-Type`        | The event type |

**Response:** `WebhookResponse` (includes the full `secret` on creation).

---

### List Webhooks

```
GET /api/webhooks
```

**Query Parameters:**

| Parameter    | Type   | Description |
|--------------|--------|-------------|
| `is_active`  | bool   | Filter by active status |
| `event_type` | string | Filter by subscribed event |
| `page`       | int    | Page number |
| `page_size`  | int    | Items per page |

---

### Get Webhook

```
GET /api/webhooks/{webhook_id}
```

Secret is masked in the response (first 8 and last 4 characters shown).

---

### Update Webhook

```
PUT /api/webhooks/{webhook_id}
Content-Type: application/json
```

All fields are optional.

---

### Delete Webhook

```
DELETE /api/webhooks/{webhook_id}
```

---

### Test Webhook

```
POST /api/webhooks/{webhook_id}/test
```

Send a `webhook.test` event to verify the webhook is working.

**Response:**

```json
{
  "webhook_id": "uuid",
  "delivery_id": "uuid",
  "success": true,
  "status_code": 200,
  "duration_ms": 150,
  "retry_count": 0
}
```

---

### Regenerate Secret

```
POST /api/webhooks/{webhook_id}/regenerate-secret
```

Regenerate the HMAC signing secret. The old secret is invalidated immediately.

**Response:**

```json
{
  "message": "Secret regenerated successfully",
  "secret": "whsec_new_secret_value"
}
```

---

### Pause / Resume Webhook

```
POST /api/webhooks/{webhook_id}/pause
POST /api/webhooks/{webhook_id}/resume
```

---

### Get Delivery History

```
GET /api/webhooks/{webhook_id}/deliveries?limit=50
```

Returns delivery history for a webhook (up to 200 entries).

---

## Burp Suite

Integration with Burp Suite Professional for web security testing.

**Prefix:** `/api/burp`

### Create Connection

```
POST /api/burp/connections
Content-Type: application/json
```

Register a Burp Suite Pro instance. The connection is tested before being saved.

**Request Body:**

```json
{
  "name": "Local Burp",
  "api_url": "http://localhost:1337",
  "api_key": "your-burp-api-key",
  "is_active": true
}
```

**Prerequisites:** Burp Suite Pro must be running with the REST API enabled (User options > Misc > Allow APIs to access private data).

---

### List Connections

```
GET /api/burp/connections
```

**Query Parameters:** `is_active`, `page`, `page_size`

---

### Get Connection

```
GET /api/burp/connections/{connection_id}
```

API key is not exposed in the response.

---

### Delete Connection

```
DELETE /api/burp/connections/{connection_id}
```

---

### Test Connection

```
POST /api/burp/connections/{connection_id}/test
```

Test connectivity to Burp Suite.

**Response:**

```json
{
  "connection_id": "uuid",
  "success": true,
  "message": "Connected",
  "burp_version": "2026.1"
}
```

---

### Start Burp Scan

```
POST /api/burp/connections/{connection_id}/scans
Content-Type: application/json
```

**Request Body:**

```json
{
  "target_urls": ["https://api.example.com"],
  "app_id": "b082b421-...",
  "scan_config": "Audit checks - all",
  "resource_pool": "default"
}
```

---

### Get Scan Status

```
GET /api/burp/scans/{task_id}
```

**Response:**

```json
{
  "task_id": "uuid",
  "burp_task_id": "12345",
  "status": "running",
  "issues_count": 5,
  "requests_made": 1200,
  "percent_complete": 65
}
```

---

### Stop Burp Scan

```
POST /api/burp/scans/{task_id}/stop
```

---

### Import Burp Issues

```
POST /api/burp/scans/{task_id}/import?app_id={app_id}
```

Import issues from a completed Burp scan into Mobilicustos findings.

**Response:**

```json
{
  "task_id": "uuid",
  "imported": 12,
  "skipped": 3,
  "total": 15
}
```

---

### Get Proxy History

```
GET /api/burp/connections/{connection_id}/proxy-history?limit=100
```

Retrieve captured HTTP requests from Burp's proxy.

---

### Import Proxy History

```
POST /api/burp/connections/{connection_id}/proxy-history/import?app_id={app_id}
```

Import proxy traffic data into Mobilicustos for network analysis.

**Query Parameters:**

| Parameter  | Type  | Required | Description |
|------------|-------|----------|-------------|
| `app_id`   | string| Yes      | App to associate traffic with |
| `item_ids` | int[] | No       | Specific proxy items to import |

---

### Get Scan Configurations

```
GET /api/burp/connections/{connection_id}/configurations
```

Get named scan configurations from Burp Suite.

---

### List Burp Issues

```
GET /api/burp/issues
```

List imported Burp issues.

**Query Parameters:**

| Parameter   | Type   | Description |
|-------------|--------|-------------|
| `task_id`   | string | Filter by scan task |
| `severity`  | string | Filter by severity |
| `page`      | int    | Page number |
| `page_size` | int    | Items per page (max: 200) |

---

### Get Burp Issue

```
GET /api/burp/issues/{issue_id}
```

---

## API Endpoints Discovery

Discover and export API endpoints found in mobile apps.

**Prefix:** `/api/api-endpoints`

### List Discovered Endpoints

```
GET /api/api-endpoints/{app_id}
```

List all API endpoints discovered during static analysis of an app.

**Response:**

```json
{
  "app_id": "b082b421-...",
  "endpoints": [
    {
      "url": "https://api.example.com/v1/users",
      "method": "POST",
      "host": "api.example.com",
      "source_file": "com/example/api/UserService.java",
      "is_https": true,
      "security_issues": []
    },
    {
      "url": "http://debug.example.com/admin",
      "method": null,
      "host": "debug.example.com",
      "source_file": "com/example/debug/Debug.java",
      "is_https": false,
      "security_issues": ["insecure_transport", "admin_endpoint"]
    }
  ],
  "total": 25,
  "unique_hosts": 3,
  "insecure_count": 5,
  "security_issues_count": 8
}
```

---

### Export Endpoints

```
GET /api/api-endpoints/{app_id}/export?format={format}
```

Export discovered endpoints in various tool-compatible formats.

**Query Parameters:**

| Parameter | Type   | Required | Description |
|-----------|--------|----------|-------------|
| `format`  | string | Yes      | `burp`, `openapi`, `postman`, `csv` |

**Export Formats:**

| Format    | Description |
|-----------|-------------|
| `burp`    | Burp Suite XML import format |
| `openapi` | OpenAPI 3.0 specification (JSON) |
| `postman` | Postman Collection v2.1 (JSON) |
| `csv`     | CSV with URL, Method, Host, HTTPS status, Security Issues |

---

### Probe Hidden Endpoints

```
POST /api/api-endpoints/{app_id}/probe
Content-Type: application/json
```

Probe common/hidden endpoints against provided base URLs (e.g., `/admin`, `/debug`, `/graphql`, `/swagger.json`, `/.env`, `/actuator`).

**Request Body:**

```json
{
  "base_urls": ["https://api.example.com", "https://backend.example.com"]
}
```

**Response:**

```json
{
  "app_id": "b082b421-...",
  "probed_count": 24,
  "responding_count": 3,
  "results": [
    { "url": "https://api.example.com/admin", "status_code": 403, "response_size": 150 },
    { "url": "https://api.example.com/health", "status_code": 200, "response_size": 25 },
    { "url": "https://api.example.com/.env", "status_code": 0, "response_size": 0, "error": "timeout" }
  ]
}
```

---

## Settings

System configuration and health status.

**Prefix:** `/api/settings`

### Get Settings

```
GET /api/settings
```

Return safe (non-secret) configuration values.

**Response:**

```json
{
  "database": { "host": "localhost", "port": 5432, "database": "mobilicustos", "user": "postgres" },
  "neo4j": { "uri": "bolt://localhost:7687" },
  "redis": { "url": "redis://localhost:6379" },
  "api": { "host": "0.0.0.0", "port": 8000, "debug": true, "log_level": "INFO" },
  "frida": { "server_version": "16.5.9", "server_host": "localhost:27042" },
  "analysis": { "max_apk_size_mb": 500, "max_ipa_size_mb": 2000, "timeout_seconds": 600 },
  "paths": { "uploads": "/data/uploads", "reports": "/data/reports", "frida_scripts": "/data/frida_scripts" },
  "tools": { "jadx": "/usr/local/bin/jadx", "apktool": "/usr/local/bin/apktool" }
}
```

---

### Get System Status

```
GET /api/settings/status
```

Check connectivity to all backend services.

**Response:**

```json
{
  "postgres": { "connected": true, "message": "Connected" },
  "neo4j": { "connected": true, "message": "Connected" },
  "redis": { "connected": true, "message": "Connected" },
  "frida": { "connected": true, "message": "Reachable at localhost:27042" }
}
```

---

## Endpoint Summary Table

A complete reference of all documented endpoints:

| Group | Method | Path | Description |
|-------|--------|------|-------------|
| **Apps** | `GET` | `/api/apps` | List apps |
| | `GET` | `/api/apps/{app_id}` | Get app |
| | `POST` | `/api/apps` | Upload app |
| | `DELETE` | `/api/apps/{app_id}` | Delete app |
| | `GET` | `/api/apps/{app_id}/stats` | Get app stats |
| **Scans** | `GET` | `/api/scans` | List scans |
| | `GET` | `/api/scans/{scan_id}` | Get scan |
| | `POST` | `/api/scans` | Create scan |
| | `GET` | `/api/scans/{scan_id}/progress` | Get progress |
| | `POST` | `/api/scans/{scan_id}/cancel` | Cancel scan |
| | `DELETE` | `/api/scans/{scan_id}` | Delete scan |
| | `DELETE` | `/api/scans/purge/{app_id}` | Purge scans by app |
| | `POST` | `/api/scans/bulk-delete` | Bulk delete scans |
| **Findings** | `GET` | `/api/findings` | List findings |
| | `GET` | `/api/findings/summary` | Findings summary |
| | `GET` | `/api/findings/filters/options` | Filter options |
| | `GET` | `/api/findings/{finding_id}` | Get finding |
| | `PATCH` | `/api/findings/{finding_id}/status` | Update status |
| | `POST` | `/api/findings/bulk-status` | Bulk update status |
| | `DELETE` | `/api/findings/{finding_id}` | Delete finding |
| | `POST` | `/api/findings/bulk-delete` | Bulk delete findings |
| | `DELETE` | `/api/findings/purge/{app_id}` | Purge findings by app |
| **Devices** | `GET` | `/api/devices` | List devices |
| | `GET` | `/api/devices/discover` | Discover devices |
| | `GET` | `/api/devices/{device_id}` | Get device |
| | `POST` | `/api/devices` | Register device |
| | `POST` | `/api/devices/{device_id}/connect` | Connect device |
| | `POST` | `/api/devices/{device_id}/frida/install` | Install Frida server |
| | `POST` | `/api/devices/{device_id}/frida/start` | Start Frida server |
| | `DELETE` | `/api/devices/{device_id}` | Delete device |
| **Frida** | `GET` | `/api/frida/scripts` | List scripts |
| | `GET` | `/api/frida/scripts/categories` | Get categories |
| | `GET` | `/api/frida/scripts/{script_id}` | Get script |
| | `POST` | `/api/frida/scripts` | Create script |
| | `POST` | `/api/frida/scripts/import` | Import script |
| | `PUT` | `/api/frida/scripts/{script_id}` | Update script |
| | `DELETE` | `/api/frida/scripts/{script_id}` | Delete script |
| | `POST` | `/api/frida/inject` | Inject script |
| | `GET` | `/api/frida/sessions` | List sessions |
| | `DELETE` | `/api/frida/sessions/{session_id}` | Detach session |
| **Compliance** | `GET` | `/api/compliance/masvs` | MASVS overview |
| | `GET` | `/api/compliance/masvs/{app_id}` | App compliance |
| | `GET` | `/api/compliance/masvs/{app_id}/{category}` | Category details |
| | `GET` | `/api/compliance/report/{app_id}` | Compliance report |
| **Attack Paths** | `GET` | `/api/attack-paths` | List paths |
| | `GET` | `/api/attack-paths/{path_id}` | Get path |
| | `GET` | `/api/attack-paths/{path_id}/findings` | Path findings |
| | `GET` | `/api/attack-paths/{path_id}/graph` | Graph data |
| | `POST` | `/api/attack-paths/generate` | Generate paths |
| | `DELETE` | `/api/attack-paths/{path_id}` | Delete path |
| **Secrets** | `GET` | `/api/secrets` | List secrets |
| | `GET` | `/api/secrets/summary` | Secrets summary |
| | `GET` | `/api/secrets/types` | Secret types |
| | `GET` | `/api/secrets/providers` | Providers |
| | `GET` | `/api/secrets/{secret_id}` | Get secret |
| | `POST` | `/api/secrets/{secret_id}/validate` | Validate secret |
| **Bypass** | `GET` | `/api/bypass/results` | List results |
| | `POST` | `/api/bypass/analyze` | Analyze protections |
| | `POST` | `/api/bypass/attempt` | Attempt bypass |
| | `POST` | `/api/bypass/auto-bypass` | Auto bypass all |
| | `GET` | `/api/bypass/detection-types` | Detection types |
| | `GET` | `/api/bypass/scripts/recommended` | Recommended scripts |
| **Exports** | `GET` | `/api/exports/findings/{app_id}` | Export findings |
| | `GET` | `/api/exports/report/{app_id}` | Export full report |
| **Drozer** | `GET` | `/api/drozer/status` | Check status |
| | `GET` | `/api/drozer/modules` | List modules |
| | `POST` | `/api/drozer/install` | Install agent |
| | `POST` | `/api/drozer/sessions` | Start session |
| | `GET` | `/api/drozer/sessions` | List sessions |
| | `GET` | `/api/drozer/sessions/{session_id}` | Get session |
| | `POST` | `/api/drozer/sessions/{session_id}/run` | Run module |
| | `GET` | `/api/drozer/sessions/{session_id}/results` | Session results |
| | `DELETE` | `/api/drozer/sessions/{session_id}` | Stop session |
| | `POST` | `/api/drozer/quick/attack-surface` | Quick: attack surface |
| | `POST` | `/api/drozer/quick/enumerate-providers` | Quick: enum providers |
| | `POST` | `/api/drozer/quick/test-sqli` | Quick: test SQLi |
| | `POST` | `/api/drozer/quick/test-traversal` | Quick: test traversal |
| **Objection** | `GET` | `/api/objection/status` | Check status |
| | `GET` | `/api/objection/commands` | List commands |
| | `POST` | `/api/objection/sessions` | Start session |
| | `GET` | `/api/objection/sessions` | List sessions |
| | `GET` | `/api/objection/sessions/{session_id}` | Get session |
| | `POST` | `/api/objection/sessions/{session_id}/execute` | Execute command |
| | `DELETE` | `/api/objection/sessions/{session_id}` | Stop session |
| | `GET` | `/api/objection/sessions/{session_id}/files` | List files |
| | `GET` | `/api/objection/sessions/{session_id}/file` | Read file |
| | `POST` | `/api/objection/sessions/{session_id}/sql` | Execute SQL |
| | `GET` | `/api/objection/sessions/{session_id}/plist` | Read plist (iOS) |
| | `POST` | `/api/objection/quick/disable-ssl-pinning` | Quick: disable SSL pinning |
| | `POST` | `/api/objection/quick/disable-root-detection` | Quick: disable root detection |
| | `POST` | `/api/objection/quick/dump-keychain` | Quick: dump keychain |
| | `POST` | `/api/objection/quick/list-modules` | Quick: list modules |
| **Scheduled Scans** | `POST` | `/api/scheduled-scans` | Create schedule |
| | `GET` | `/api/scheduled-scans` | List schedules |
| | `GET` | `/api/scheduled-scans/{schedule_id}` | Get schedule |
| | `PUT` | `/api/scheduled-scans/{schedule_id}` | Update schedule |
| | `DELETE` | `/api/scheduled-scans/{schedule_id}` | Delete schedule |
| | `POST` | `/api/scheduled-scans/{schedule_id}/run` | Trigger manually |
| | `POST` | `/api/scheduled-scans/{schedule_id}/pause` | Pause schedule |
| | `POST` | `/api/scheduled-scans/{schedule_id}/resume` | Resume schedule |
| | `GET` | `/api/scheduled-scans/{schedule_id}/history` | Schedule history |
| | `POST` | `/api/scheduled-scans/validate-cron` | Validate cron |
| | `GET` | `/api/scheduled-scans/due/list` | List due schedules |
| **Webhooks** | `GET` | `/api/webhooks/events` | List event types |
| | `POST` | `/api/webhooks` | Create webhook |
| | `GET` | `/api/webhooks` | List webhooks |
| | `GET` | `/api/webhooks/{webhook_id}` | Get webhook |
| | `PUT` | `/api/webhooks/{webhook_id}` | Update webhook |
| | `DELETE` | `/api/webhooks/{webhook_id}` | Delete webhook |
| | `POST` | `/api/webhooks/{webhook_id}/test` | Test webhook |
| | `POST` | `/api/webhooks/{webhook_id}/regenerate-secret` | Regenerate secret |
| | `POST` | `/api/webhooks/{webhook_id}/pause` | Pause webhook |
| | `POST` | `/api/webhooks/{webhook_id}/resume` | Resume webhook |
| | `GET` | `/api/webhooks/{webhook_id}/deliveries` | Delivery history |
| **Burp Suite** | `POST` | `/api/burp/connections` | Create connection |
| | `GET` | `/api/burp/connections` | List connections |
| | `GET` | `/api/burp/connections/{connection_id}` | Get connection |
| | `DELETE` | `/api/burp/connections/{connection_id}` | Delete connection |
| | `POST` | `/api/burp/connections/{connection_id}/test` | Test connection |
| | `POST` | `/api/burp/connections/{connection_id}/scans` | Start scan |
| | `GET` | `/api/burp/scans/{task_id}` | Get scan status |
| | `POST` | `/api/burp/scans/{task_id}/stop` | Stop scan |
| | `POST` | `/api/burp/scans/{task_id}/import` | Import issues |
| | `GET` | `/api/burp/connections/{connection_id}/proxy-history` | Proxy history |
| | `POST` | `/api/burp/connections/{connection_id}/proxy-history/import` | Import proxy history |
| | `GET` | `/api/burp/connections/{connection_id}/configurations` | Scan configurations |
| | `GET` | `/api/burp/issues` | List Burp issues |
| | `GET` | `/api/burp/issues/{issue_id}` | Get Burp issue |
| **API Endpoints** | `GET` | `/api/api-endpoints/{app_id}` | List endpoints |
| | `GET` | `/api/api-endpoints/{app_id}/export` | Export endpoints |
| | `POST` | `/api/api-endpoints/{app_id}/probe` | Probe endpoints |
| **Settings** | `GET` | `/api/settings` | Get settings |
| | `GET` | `/api/settings/status` | System status |
