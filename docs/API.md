# Mobilicustos API Reference

The Mobilicustos API is a RESTful API built with FastAPI. Full interactive documentation is available at `http://localhost:8000/docs` (Swagger UI) or `http://localhost:8000/redoc` (ReDoc).

## Base URL

```
http://localhost:8000/api
```

## Authentication

Currently, the API does not require authentication for local development. Production deployments should implement JWT authentication.

## Endpoints Overview

### Applications

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/apps` | List all applications |
| `GET` | `/apps/{app_id}` | Get application details |
| `POST` | `/apps/upload` | Upload APK/IPA file |
| `DELETE` | `/apps/{app_id}` | Delete application |

### Scans

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/scans` | List all scans |
| `GET` | `/scans/{scan_id}` | Get scan details |
| `POST` | `/scans` | Start new scan |
| `DELETE` | `/scans/{scan_id}` | Delete scan |
| `POST` | `/scans/{scan_id}/cancel` | Cancel running scan |

### Findings

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/findings` | List findings with filters |
| `GET` | `/findings/{finding_id}` | Get finding details |
| `GET` | `/findings/summary` | Get findings summary |
| `PUT` | `/findings/{finding_id}/status` | Update finding status |
| `GET` | `/findings/export/csv` | Export findings to CSV |

### Devices

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/devices` | List registered devices |
| `POST` | `/devices` | Register new device |
| `DELETE` | `/devices/{device_id}` | Remove device |
| `POST` | `/devices/discover` | Discover connected devices |

---

## Detailed Endpoints

### Upload Application

```http
POST /api/apps/upload
Content-Type: multipart/form-data
```

**Request:**
```bash
curl -X POST http://localhost:8000/api/apps/upload \
  -F "file=@app.apk"
```

**Response:**
```json
{
  "app_id": "com.example.app-1.0.0",
  "package_name": "com.example.app",
  "app_name": "Example App",
  "version_name": "1.0.0",
  "platform": "android",
  "framework": "native",
  "status": "pending"
}
```

### Start Scan

```http
POST /api/scans
Content-Type: application/json
```

**Request:**
```json
{
  "app_id": "com.example.app-1.0.0",
  "scan_type": "static"
}
```

**Scan Types:**
- `static` - Static analysis only
- `dynamic` - Dynamic analysis with device
- `full` - Complete static + dynamic

**Response:**
```json
{
  "scan_id": "550e8400-e29b-41d4-a716-446655440000",
  "app_id": "com.example.app-1.0.0",
  "scan_type": "static",
  "status": "pending",
  "created_at": "2026-02-03T12:00:00Z"
}
```

### List Findings

```http
GET /api/findings
```

**Query Parameters:**
| Parameter | Type | Description |
|-----------|------|-------------|
| `app_id` | string | Filter by application |
| `scan_id` | string | Filter by scan |
| `severity` | string | Filter by severity (critical,high,medium,low,info) |
| `status` | string | Filter by status (open,confirmed,false_positive,remediated) |
| `tool` | string | Filter by analyzer tool |
| `masvs_category` | string | Filter by MASVS category |
| `search` | string | Search in title/description |
| `limit` | int | Results per page (default: 50) |
| `offset` | int | Pagination offset |

**Example:**
```bash
curl "http://localhost:8000/api/findings?severity=critical,high&limit=10"
```

**Response:**
```json
{
  "items": [
    {
      "finding_id": "finding-001",
      "tool": "crypto_auditor",
      "severity": "critical",
      "title": "Hardcoded Encryption Key",
      "description": "...",
      "file_path": "com/example/crypto/Manager.java",
      "line_number": 45,
      "owasp_masvs_category": "MASVS-CRYPTO",
      "status": "open"
    }
  ],
  "total": 150,
  "limit": 10,
  "offset": 0
}
```

### Get Findings Summary

```http
GET /api/findings/summary
```

**Response:**
```json
{
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
  "by_tool": {
    "manifest_analyzer": 8,
    "crypto_auditor": 5,
    "dex_analyzer": 7
  }
}
```

### Update Finding Status

```http
PUT /api/findings/{finding_id}/status
Content-Type: application/json
```

**Request:**
```json
{
  "status": "confirmed"
}
```

**Valid Statuses:**
- `open` - Not reviewed
- `confirmed` - Verified vulnerability
- `false_positive` - Not a real issue
- `accepted_risk` - Known risk, accepted
- `remediated` - Fixed

### Register Device

```http
POST /api/devices
Content-Type: application/json
```

**Request:**
```json
{
  "name": "Pixel 6",
  "device_type": "physical",
  "platform": "android",
  "connection_string": "emulator-5554"
}
```

**Device Types:**
- `physical` - USB-connected device
- `emulator` - Android emulator
- `genymotion` - Genymotion emulator
- `corellium` - Corellium virtual device

### Discover Devices

```http
POST /api/devices/discover
```

Automatically discovers connected Android devices via ADB.

**Response:**
```json
{
  "discovered": [
    {
      "device_id": "emulator-5554",
      "model": "sdk_gphone64_x86_64",
      "android_version": "14",
      "is_rooted": false,
      "device_type": "emulator"
    }
  ]
}
```

---

## Error Responses

All errors follow this format:

```json
{
  "detail": "Error message describing the issue"
}
```

**Common HTTP Status Codes:**
- `400` - Bad Request (invalid input)
- `404` - Not Found
- `422` - Validation Error
- `500` - Internal Server Error

---

## Rate Limiting

The API implements rate limiting for production deployments:
- 100 requests per minute for general endpoints
- 10 requests per minute for file uploads
- 5 concurrent scans per user

---

## Pagination

List endpoints support pagination:

```bash
curl "http://localhost:8000/api/findings?limit=25&offset=50"
```

Response includes pagination metadata:
```json
{
  "items": [...],
  "total": 150,
  "limit": 25,
  "offset": 50
}
```
