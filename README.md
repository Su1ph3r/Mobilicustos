# Mobilicustos

Mobile app security scanner for Android and iOS — static analysis, dynamic analysis, framework detection, OWASP MASVS mapping, and Frida-based proof of concept in one tool.

## Workflow

A typical mobile security assessment runs like this:

**1. Point it at an APK or IPA.**

Upload through the web UI or the API:

```bash
curl -X POST http://localhost:8000/api/apps/upload \
  -F "file=@target-app.apk"
```

**2. Run analysis.**

Static analysis runs automatically; add dynamic analysis if you have a device connected:

```bash
curl -X POST http://localhost:8000/api/scans \
  -H "Content-Type: application/json" \
  -d '{"app_id": "com.target.app-1.0.0", "scan_type": "full"}'
```

Scan types: `static` (5-15 min), `dynamic` (10-30 min), `full` (20-45 min).

**3. Framework detection kicks in.**

Mobilicustos identifies the app's framework — Flutter, React Native, Xamarin, Cordova, or native Java/Kotlin/Swift — and applies specialized decompilers and analyzers for each.

**4. Findings get mapped to OWASP MASVS.**

Every finding is normalized to a consistent severity scale and mapped to MASVS categories: STORAGE, CRYPTO, AUTH, NETWORK, PLATFORM, CODE, and RESILIENCE.

**5. Frida scripts are generated for proof of concept.**

For exploitable findings, the tool generates Frida hooking scripts you can run against a live device to verify the issue:

```bash
# Example: hook certificate pinning bypass
frida -U -f com.target.app -l generated-scripts/ssl-pinning-bypass.js
```

**6. Pull the report.**

Export findings in the format you need:

```bash
# JSON findings filtered by severity
curl "http://localhost:8000/api/findings?severity=critical,high"

# CSV export
curl http://localhost:8000/api/findings/export/csv -o findings.csv
```

## Install

```bash
git clone https://github.com/Su1ph3r/Mobilicustos.git
cd Mobilicustos
cp .env.example .env
docker compose up -d
```

The web UI is at `http://localhost:3000`, the API at `http://localhost:8000`, and Swagger docs at `http://localhost:8000/docs`.

## Device support

- Physical Android devices (rooted) and iOS devices (jailbroken) via USB
- Android AVD emulators
- Genymotion (cloud and desktop)
- Corellium virtual devices

## Output formats

Findings export as JSON, CSV, or through the REST API with filtering by severity, MASVS category, and framework.

## Web UI

The Vue.js 3 frontend gives you a dashboard, findings browser with severity filtering, app inventory, scan management, device status, and a remediation knowledge base. Access it at `http://localhost:3000` after starting the stack.

## Configuration

Edit `.env` to set database credentials, device connections, and tool paths:

```bash
# Database
POSTGRES_PASSWORD=changeme_in_production
NEO4J_PASSWORD=changeme_in_production

# Device management
ADB_HOST=host.docker.internal
CORELLIUM_API_KEY=your-key-here
CORELLIUM_DOMAIN=https://app.corellium.com

# API
API_PORT=8000
API_DEBUG=false
VITE_API_URL=http://localhost:8000
```

## License

MIT — see [LICENSE](LICENSE) for details.
