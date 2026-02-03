# Mobilicustos Architecture

This document describes the technical architecture of Mobilicustos, a mobile security intelligence platform.

## Overview

Mobilicustos is a containerized application that analyzes mobile applications (Android APK, iOS IPA) for security vulnerabilities. It consists of several interconnected services that work together to provide comprehensive security analysis.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         MOBILICUSTOS ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         PRESENTATION LAYER                            │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │   │
│  │  │   Vue.js     │    │   FastAPI    │    │   Swagger    │           │   │
│  │  │   Frontend   │    │   REST API   │    │   Docs       │           │   │
│  │  │   :3000      │    │   :8000      │    │   /docs      │           │   │
│  │  └──────────────┘    └──────────────┘    └──────────────┘           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         BUSINESS LAYER                                │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │   │
│  │  │   Analysis   │    │   Report     │    │   Device     │           │   │
│  │  │   Service    │    │   Processor  │    │   Manager    │           │   │
│  │  └──────────────┘    └──────────────┘    └──────────────┘           │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │   │
│  │  │   Scan       │    │   Export     │    │   Knowledge  │           │   │
│  │  │   Orchestr.  │    │   Service    │    │   Base       │           │   │
│  │  └──────────────┘    └──────────────┘    └──────────────┘           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         ANALYZER LAYER                                │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │   │
│  │  │ manifest   │ │ dex        │ │ crypto     │ │ secret     │        │   │
│  │  │ analyzer   │ │ analyzer   │ │ auditor    │ │ scanner    │        │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │   │
│  │  │ binary     │ │ webview    │ │ network    │ │ flutter    │        │   │
│  │  │ protection │ │ auditor    │ │ security   │ │ analyzer   │        │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌────────────┐        │   │
│  │  │ ssl_       │ │ code_      │ │ firebase   │ │ CVE        │        │   │
│  │  │ pinning    │ │ quality    │ │ analyzer   │ │ detector   │        │   │
│  │  └────────────┘ └────────────┘ └────────────┘ └────────────┘        │   │
│  │  ┌────────────┐ ┌────────────┐ ┌────────────┐                       │   │
│  │  │ auth       │ │ data       │ │ attack     │                       │   │
│  │  │ analyzer   │ │ leakage    │ │ paths      │                       │   │
│  │  └────────────┘ └────────────┘ └────────────┘                       │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │                         DATA LAYER                                    │   │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐           │   │
│  │  │  PostgreSQL  │    │    Neo4j     │    │    Redis     │           │   │
│  │  │  Findings    │    │    Graph     │    │    Cache     │           │   │
│  │  │  Apps, Scans │    │    Paths     │    │    Jobs      │           │   │
│  │  └──────────────┘    └──────────────┘    └──────────────┘           │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Components

### Frontend (Vue.js)

**Technology:** Vue 3 + Composition API + TypeScript + PrimeVue

**Location:** `/frontend`

The frontend provides the user interface for:
- Dashboard with security posture metrics
- Findings view with filtering and expandable details
- Application management and upload
- Scan orchestration and monitoring
- Device management (physical, emulator, Genymotion, Corellium)

**Key files:**
- `src/views/` - Page components
- `src/components/` - Reusable UI components
- `src/stores/` - Pinia state management
- `src/types/` - TypeScript type definitions

### API (FastAPI)

**Technology:** FastAPI + SQLAlchemy + Pydantic

**Location:** `/api`

The REST API handles:
- Application upload and management
- Scan orchestration
- Findings queries and export
- Device management
- Authentication

**Key directories:**
- `routers/` - API endpoint definitions
- `services/` - Business logic
- `models/` - Database models and Pydantic schemas
- `services/analyzers/` - Security analysis modules

### Analyzers

Modular security analyzers that examine different aspects of mobile applications:

| Analyzer | Purpose |
|----------|---------|
| `manifest_analyzer` | Android manifest security review |
| `plist_analyzer` | iOS Info.plist analysis |
| `dex_analyzer` | DEX bytecode analysis |
| `crypto_auditor` | Cryptographic implementation review |
| `secret_scanner` | Hardcoded secrets detection |
| `binary_protection_analyzer` | Binary hardening checks |
| `network_security_config_analyzer` | Network security configuration |
| `webview_auditor` | WebView security analysis |
| `flutter_analyzer` | Flutter-specific analysis |
| `react_native_analyzer` | React Native analysis |
| `ssl_pinning_analyzer` | SSL/TLS certificate pinning detection |
| `code_quality_analyzer` | SQL injection, command injection, path traversal |
| `firebase_analyzer` | Firebase misconfiguration detection |
| `authentication_analyzer` | Biometric and credential storage patterns |
| `data_leakage_analyzer` | Clipboard, screenshot, keyboard cache leaks |
| `dependency_analyzer` | Library CVE detection via OSV/NVD |
| `attack_path_generator` | Graph-based attack path analysis |

### Report Processor

**Location:** `/report-processor`

Normalizes findings from different analyzers into a unified format:
- Severity normalization
- OWASP MASVS mapping
- Deduplication
- Trend tracking

### Data Stores

#### PostgreSQL
- Applications metadata
- Scan records
- Findings (normalized)
- User preferences

#### Neo4j
- Attack path graphs
- Resource relationships
- Component dependencies

#### Redis
- Job queue
- Session cache
- Rate limiting

## Data Flow

### Application Upload

```
1. User uploads APK/IPA via UI or API
2. API validates file type and size
3. File stored in uploads directory
4. Metadata extracted and stored in PostgreSQL
5. Framework detection runs
6. Application ready for scanning
```

### Scan Execution

```
1. User triggers scan (static/dynamic/full)
2. Scan orchestrator creates scan record
3. Appropriate analyzers selected based on:
   - Platform (Android/iOS)
   - Framework (Native/Flutter/RN)
   - Scan type
4. Analyzers run in sequence
5. Raw findings stored
6. Report processor normalizes findings
7. Scan marked complete
```

### Findings Query

```
1. User requests findings with filters
2. API queries PostgreSQL with filters
3. Results paginated and returned
4. Frontend renders with expandable details
```

## Security Considerations

### Input Validation
- All API inputs validated with Pydantic
- File uploads checked for type and size
- Path traversal prevented on all file operations

### Data Protection
- Secrets in findings are redacted
- Credentials never logged
- Sensitive data encrypted at rest

### Container Isolation
- Each service runs in isolated container
- Analysis performed in sandboxed environments
- Network access restricted

## Scaling Considerations

### Horizontal Scaling
- Frontend: Stateless, can be replicated
- API: Stateless with Redis sessions
- Analyzers: Can run as separate workers

### Vertical Scaling
- PostgreSQL: Increase resources for large datasets
- Neo4j: Memory-intensive for large graphs
- Analysis: CPU/memory for complex apps

## Configuration

All configuration via environment variables in `.env`:

```bash
# Database
POSTGRES_HOST=postgres
POSTGRES_PORT=5432
POSTGRES_DB=mobilicustos

# Neo4j
NEO4J_URI=bolt://neo4j:7687

# Redis
REDIS_URL=redis://redis:6379

# API
API_HOST=0.0.0.0
API_PORT=8000

# Analysis
MAX_APK_SIZE_MB=500
ANALYSIS_TIMEOUT_SECONDS=3600
```

## Directory Structure

```
mobilicustos/
├── api/                      # FastAPI backend
│   ├── routers/             # API endpoints
│   ├── services/            # Business logic
│   │   └── analyzers/       # Security analyzers
│   ├── models/              # Database models
│   └── tests/               # Backend tests
├── frontend/                # Vue.js frontend
│   ├── src/
│   │   ├── components/      # UI components
│   │   ├── views/           # Page views
│   │   ├── stores/          # Pinia stores
│   │   └── types/           # TypeScript types
│   └── tests/               # Frontend tests
├── report-processor/        # Findings normalization
├── knowledge-base/          # Remediation content
├── docs/                    # Documentation
├── scripts/                 # Utility scripts
└── docker-compose.yml       # Container orchestration
```
