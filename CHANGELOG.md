# Changelog

All notable changes to Mobilicustos will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-03

### Added
- Initial release of Mobilicustos
- **Findings View** - Unified findings display with expandable details
  - Severity quick-filter buttons with counts
  - Expandable table rows showing full finding details
  - Code snippets with syntax highlighting
  - OWASP MASVS/MASTG mapping
  - Remediation guidance
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
- **API**
  - RESTful API with FastAPI
  - OpenAPI/Swagger documentation
  - Findings export (CSV)
- **Frontend**
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
