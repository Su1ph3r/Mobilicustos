# Mobilicustos User Guide

Mobilicustos is a mobile security penetration testing platform that provides comprehensive static and dynamic analysis of Android and iOS applications. This guide covers every feature of the platform, from initial setup to advanced integrations.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [Uploading Applications](#2-uploading-applications)
3. [Running Security Scans](#3-running-security-scans)
4. [Analyzing Findings](#4-analyzing-findings)
5. [OWASP MASVS Compliance](#5-owasp-masvs-compliance)
6. [Dynamic Analysis with Frida](#6-dynamic-analysis-with-frida)
7. [Security Bypass Testing](#7-security-bypass-testing)
8. [Attack Paths](#8-attack-paths)
9. [Secrets Detection](#9-secrets-detection)
10. [Drozer Integration](#10-drozer-integration)
11. [Objection Integration](#11-objection-integration)
12. [API Endpoint Discovery](#12-api-endpoint-discovery)
13. [Burp Suite Integration](#13-burp-suite-integration)
14. [Scheduled Scans](#14-scheduled-scans)
15. [Webhooks](#15-webhooks)
16. [Settings](#16-settings)

---

## 1. Getting Started

### Prerequisites

Before installing Mobilicustos, ensure the following are available on your system:

- **Docker and Docker Compose** -- The entire platform runs as a set of Docker containers. Docker Compose V2 is required.
- **ADB (Android Debug Bridge)** -- Required for connecting physical Android devices. The ADB server must be running on the host machine so that the API container can communicate with it via `host.docker.internal:5037`.
- **A rooted Android device (recommended)** -- Dynamic analysis features such as Frida injection, Drozer, and Objection require root access. Magisk is the recommended rooting method.
- **frida-server on the device** -- For dynamic instrumentation, frida-server must be running on the target device. Version 16.5.9 is recommended and should listen on TCP port 27042. Use `adb forward tcp:27042 tcp:27042` to tunnel the port from the host to the device so Docker containers can reach it.

### Installation

1. Clone the repository and navigate to the project directory.

2. Start all services with Docker Compose:

   ```
   docker compose up -d
   ```

   This launches the following containers:
   - **PostgreSQL** (port 5432) -- Primary data store for apps, scans, findings, and all configuration.
   - **Neo4j** (port 7474 for browser, 7687 for Bolt) -- Graph database used for attack path analysis.
   - **Redis** (port 6379) -- Caching and message queue.
   - **API** (port 8000) -- FastAPI backend that orchestrates all analysis.
   - **Frontend** (port 3000) -- Vue.js web interface served via Nginx.
   - **Report Processor** -- Background service for processing scan reports.

3. Wait for all services to become healthy. You can monitor startup with:

   ```
   docker compose ps
   ```

### First Launch and Initial Setup

1. Open your browser and navigate to `http://localhost:3000`.
2. You will see the **Dashboard**, which is empty on first launch. This is expected -- it will populate once you upload apps and run scans.
3. The sidebar on the left provides navigation to all platform features. It can be collapsed by clicking the collapse button at the bottom of the sidebar.
4. Toggle between light and dark mode using the theme button in the sidebar footer.
5. Keyboard shortcuts are available. Press the "Shortcuts" button in the sidebar footer (or press `?`) to view all available shortcuts.

### Connecting a Device

1. Navigate to **Devices** in the sidebar (keyboard shortcut: `Alt+V`).
2. Click **Discover Devices** to auto-detect connected Android or iOS devices via ADB.
3. Alternatively, click **Register Device** to manually add a device by providing its ID, name, platform, and connection details.
4. Each discovered device card shows:
   - Device name and model
   - Platform and OS version
   - Connection status
   - Root/jailbreak status
   - Frida server status and version
5. Ensure the device shows a "Connected" status and that Frida server is marked as "running" before attempting dynamic analysis.

---

## 2. Uploading Applications

### Supported Formats

Mobilicustos accepts the following mobile application formats:

- **APK** -- Android application packages
- **IPA** -- iOS application archives
- **AAB** -- Android App Bundles

The maximum upload size is 500 MB.

### Upload Process

1. Navigate to **Apps** in the sidebar (keyboard shortcut: `Alt+A`).
2. Click the **Upload App** button in the top-right corner.
3. In the upload dialog, either:
   - Click **Select APK or IPA** to browse for a file, or
   - Drag and drop a file into the upload area.
4. Click **Upload** to begin the upload.
5. The application will appear in the apps table with a "processing" status while Mobilicustos extracts metadata (package name, version, platform, framework detection).
6. Once processing completes, the status changes to "ready".

### App Details View

Click on any application name in the apps table to open its detail view. This page shows:

- Application metadata (package name, version name, version code)
- Platform (Android or iOS)
- Detected framework (Flutter, React Native, Xamarin, Cordova, .NET MAUI, or Native)
- Upload date
- Associated scans and their results

### Filtering and Searching Apps

The apps list provides filters for:

- **Platform** -- Filter by Android or iOS
- **Framework** -- Filter by detected framework
- **Search** -- Free-text search across app names and package names

---

## 3. Running Security Scans

### Scan Types

Mobilicustos supports three scan types:

| Scan Type | Description | Analyzers |
|-----------|-------------|-----------|
| **Static** | Analyzes the application binary without executing it. Inspects code, manifest, configurations, dependencies, and embedded secrets. | DEX Analyzer, Manifest Analyzer, Plist Analyzer, Binary Analyzer, Secret Scanner, Crypto Auditor, Privacy Analyzer, Dependency Scanner, IPC Scanner, WebView Auditor |
| **Dynamic** | Runtime analysis using Frida instrumentation on a connected device. Monitors network calls, crypto operations, and runtime behavior. | Runtime Analyzer, Network Analyzer |
| **Full** | Combines both static and dynamic analysis for comprehensive coverage. | All of the above |

### Starting a Scan

There are two ways to start a scan:

**From the Apps view:**
1. In the apps table, click the scan icon button in the Actions column for the desired app.
2. A dialog appears where you select the scan type (Static, Dynamic, or Full).
3. Click **Start Scan**.

**From the Scans view:**
1. Navigate to **Scans** (keyboard shortcut: `Alt+S`).
2. Scans initiated from the Apps view will appear here.

### Monitoring Progress

1. Navigate to **Scans** to see all scans.
2. Running scans display a progress bar and show the current analyzer being executed.
3. The page auto-refreshes every 5 seconds for running scans.
4. You can manually refresh a specific scan's progress using the refresh button.
5. To cancel a running scan, click the stop button in the Actions column.

### Understanding Results

Each scan row in the table shows:

- **Scan ID** -- Click to view full scan details.
- **Application** -- Link to the associated app.
- **Type** -- Static, Dynamic, or Full (color-coded).
- **Status** -- Pending, Running, Completed, Failed, or Cancelled.
- **Current Task** -- The analyzer currently executing (while running).
- **Findings** -- Color-coded badges showing the count of findings by severity (critical, high, medium, low, info).
- **Started** -- Timestamp of when the scan began.

Click on a scan ID to view its full detail page, which includes a breakdown of all findings produced by that scan.

### Bulk Operations

- Select multiple scans using the checkboxes and click **Delete Selected** to remove them along with their findings.
- Use **Delete All Scans** (requires filtering by a specific app first) to purge all scans for an application.

---

## 4. Analyzing Findings

### Viewing Findings

Navigate to **Findings** in the sidebar (keyboard shortcut: `Alt+F`). This view displays all security findings across all scans.

The header shows the total count of findings and indicates when filters are active.

### Filtering and Sorting

The findings view provides a comprehensive filter panel:

- **Severity** -- Critical, High, Medium, Low, Info
- **Status** -- Open, Confirmed, False Positive, Remediated
- **App** -- Filter by specific application
- **Category** -- Filter by finding category
- **Tool** -- Filter by the analyzer that produced the finding

All columns in the findings table are sortable. Click a column header to sort ascending, click again for descending.

Findings can also be filtered directly from the Dashboard by clicking on severity cards, which navigates to the Findings view with the corresponding severity filter pre-applied.

### Finding Detail View

Click on any finding to open its detail page. The detail view includes:

- **Severity badge and title** at the top
- **Status dropdown** to change the finding's status directly
- **Overview card** showing category, tool, platform, CWE ID (linked to MITRE), CVSS score, and OWASP MASVS mapping
- **Description** -- Detailed explanation of the vulnerability
- **Impact** -- What could happen if exploited
- **Location** -- File path and line number where the issue was found, with a code snippet viewer
- **PoC Evidence** -- Proof-of-concept details when available
- **Remediation** -- Recommended steps to fix the issue

### Exporting Findings

Click the **Export** split button in the findings header to export in multiple formats:

| Format | Description |
|--------|-------------|
| **CSV** | Comma-separated values for spreadsheet analysis |
| **JSON** | Structured JSON for programmatic processing |
| **HTML** | Formatted HTML report for stakeholders |
| **PDF** | Print-ready PDF report |
| **SARIF** | Static Analysis Results Interchange Format for CI/CD integration |

Exports respect the currently active filters, so you can export a specific subset of findings.

### Status Management

Each finding has a status that can be managed individually:

- **open** -- Default status for new findings
- **confirmed** -- Verified as a real vulnerability
- **false_positive** -- Determined to be a false alarm
- **remediated** -- The issue has been fixed

Change a finding's status from the detail view using the status dropdown in the header.

### Purging Findings

To delete all findings for a specific application:

1. Filter findings by the target application.
2. Click the **Purge All** button.
3. Confirm the action in the dialog.

This permanently removes all findings for the selected app.

---

## 5. OWASP MASVS Compliance

### Understanding MASVS Categories

The OWASP Mobile Application Security Verification Standard (MASVS) defines security requirements for mobile apps. Mobilicustos maps all findings to MASVS categories automatically.

Navigate to **Compliance** in the sidebar (keyboard shortcut: `Alt+C`).

### Viewing Compliance Status

1. Select an application from the dropdown.
2. The compliance overview displays:
   - **Overall compliance score** as a circular progress indicator
   - **Category chips** showing per-category scores with color coding (green for pass, yellow for partial, red for fail)
   - **Category cards** with detailed control-by-control status

3. Each category card shows:
   - Category ID and name
   - Percentage score with a progress bar
   - List of individual controls with Pass/Fail/Partial tags

4. Click **View Details** on any category card to open a dialog with:
   - Full control descriptions
   - Related findings linked to each control
   - Direct links to findings for further investigation

### Generating Compliance Reports

1. Select an application.
2. Click **Generate Report** in the header.
3. The platform generates and downloads a JSON compliance report containing the full MASVS assessment for the selected application.

---

## 6. Dynamic Analysis with Frida

### Overview

The Frida Console provides a full-featured interface for dynamic instrumentation. It allows you to write, manage, and inject Frida scripts into running applications.

Navigate to **Frida** in the sidebar (keyboard shortcut: `Alt+R`).

### Script Editor

The left panel contains the script editor:

- **Load Script** -- Select from saved scripts using the dropdown.
- **Save Script** -- Save the current script with a name, category, and description.
- **New Script** -- Clear the editor to start a new script.
- Write JavaScript Frida scripts directly in the editor area.

### Injecting Scripts

1. In the right panel, select a **Device** from the dropdown (only connected devices are shown).
2. Select an **Application** to target.
3. Click **Inject** to inject the current script into the target application.
4. The output console below shows injection status and script output in real-time.
5. Click **Detach** to stop the script and detach from the process.

### Monitoring Output

The output console displays timestamped messages from injected scripts:

- Green text indicates successful operations
- Red text indicates errors
- Blue text indicates informational messages
- White/gray text is standard log output

Use **Clear Output** to reset the console.

### Active Sessions

When scripts are injected, active sessions appear in the sessions panel showing the app name and device. You can detach individual sessions by clicking the close button next to each session.

### Built-in Script Library

The platform seeds a library of built-in Frida scripts on startup. Scripts are organized by category:

- **bypass** -- SSL pinning bypass, root detection bypass
- **monitor** -- Function call monitoring, network traffic monitoring
- **exploit** -- Exploitation scripts
- **crypto** -- Cryptographic operation interception
- **network** -- Network request interception
- **custom** -- User-created scripts

To use a library script:

1. Select it from the script dropdown, or open the Script Library dialog.
2. Filter by category or search by name.
3. Click **Use** to load the script into the editor.

---

## 7. Security Bypass Testing

### Overview

The Bypass view provides automated detection and bypassing of common mobile security protections. Navigate to **Bypass** in the sidebar.

### Analyzing Protections

1. Select a **Target App** from the dropdown.
2. Click **Analyze Protections**.
3. The platform scans the application binary for security protection mechanisms and displays detection cards for each one found.

Detectable protections include:

| Protection | Description |
|-----------|-------------|
| **Root Detection** | Checks for root/su binaries and Magisk |
| **Jailbreak Detection** | iOS jailbreak checks |
| **Frida Detection** | Anti-Frida instrumentation checks |
| **Emulator Detection** | Virtual device detection |
| **Debugger Detection** | Anti-debugging mechanisms |
| **SSL Pinning** | Certificate pinning implementations |

Each detection card shows:
- Protection type and detection method
- Confidence level (percentage)
- Detection library (when identifiable)
- Evidence snippets

### Attempting Bypasses

1. Select a **Device** in addition to the target app.
2. On any detection card, click **Attempt Bypass** to run a targeted bypass script against that specific protection.
3. The result shows one of three statuses:
   - **success** -- The protection was fully bypassed
   - **partial** -- The bypass partially worked
   - **failed** -- The bypass did not succeed
4. Bypass notes and PoC evidence are displayed below the result.

### Auto Bypass

Click **Auto Bypass All** to automatically attempt bypasses against all detected protections in sequence. The summary cards show totals for success, partial, and failed bypasses.

### Bypass History

The history table at the bottom records all bypass attempts with timestamps, allowing you to track results over time and retry failed bypasses.

---

## 8. Attack Paths

### Overview

Attack Paths use graph analysis (powered by Neo4j) to identify chains of vulnerabilities that could be exploited together. Navigate to **Attack Paths** in the sidebar (keyboard shortcut: `Alt+P`).

### Generating Attack Paths

1. Select an application from the dropdown.
2. Click **Generate Paths** to analyze all findings for the selected app and compute potential attack chains.
3. Generated paths appear in the left panel, sorted by risk level.

### Understanding Attack Chains

Each attack path includes:

- **Risk level** -- Critical, High, Medium, or Low
- **Risk score** -- Numerical score indicating overall risk
- **Findings count** -- Number of related findings
- **Steps count** -- Number of steps in the attack chain

Click on a path to view its details in the right panel:

- **Attack Chain visualization** -- A step-by-step diagram showing how an attacker could chain vulnerabilities. Steps are categorized as Entry Point, Vulnerability, Exploit, or Impact, each color-coded.
- **Impact Assessment** -- Progress bars showing impact on Confidentiality, Integrity, and Availability.
- **Related Findings table** -- All findings involved in the attack chain, with direct links to their detail pages.

### Exporting Attack Paths

Click **Export Path** on any path's detail view to download it as a JSON file for documentation or reporting.

---

## 9. Secrets Detection

### Overview

The Secrets view displays API keys, tokens, passwords, and other credentials discovered in application binaries during scanning. Navigate to **Secrets** in the sidebar (keyboard shortcut: `Alt+K`).

### Dashboard

Four summary cards at the top show:
- **Total Secrets** -- All detected secrets
- **Validated** -- Secrets that have been tested
- **Active** -- Secrets confirmed to still be valid (a red-colored card, indicating urgency)
- **Revoked** -- Secrets that are no longer active

### Viewing Detected Secrets

The secrets table displays:
- **Type** -- API Key, AWS Access Key, Private Key, Password, Token, etc.
- **Provider** -- The service the secret belongs to (AWS, Google, Stripe, etc.)
- **Secret** -- The value, masked by default for security. Use the eye icon to reveal, or the copy icon to copy to clipboard.
- **Location** -- File path and line number where the secret was found.
- **Status** -- Unknown, Validated, Active, Inactive, or Revoked.

### Filtering Secrets

Filter by:
- **Type** -- Filter by secret type
- **Provider** -- Filter by cloud/service provider
- **Status** -- Filter by validation status
- **Search** -- Free-text search

### Validating Secrets

Click the check icon on any secret row to validate whether the secret is still active. The platform attempts to verify the credential against the relevant service and reports:
- **Active** -- The secret is valid and working (requires immediate attention)
- **Inactive** -- The secret is no longer valid

### Secret Details Dialog

Click the eye icon on any row to open the full details dialog, which includes:
- Basic information (type, provider, status)
- Full secret value (with show/hide toggle)
- File location with surrounding code context
- Validation results
- Remediation steps:
  1. Revoke or rotate the credential immediately
  2. Remove the hardcoded secret from source code
  3. Use environment variables or a secrets manager
  4. Audit access logs for unauthorized usage

---

## 10. Drozer Integration

### Overview

Drozer is an Android security testing framework. Mobilicustos integrates Drozer for analyzing exposed components, content providers, and common vulnerabilities. Navigate to **Drozer** in the sidebar.

A status tag in the header indicates whether Drozer is available in the environment.

### Starting Sessions

1. Select an **Android Device** from the dropdown (only connected Android devices are shown).
2. Enter the **Package Name** of the target application (e.g., `com.example.app`).
3. Click **Start Session**.
4. The active session panel shows the session ID, package name, and status.
5. Click **Stop Session** to end the session.

### Module Browser

The left panel includes a searchable module browser organized into categories (e.g., App, Provider, Scanner). Each module shows its name and description. Click a module to select it, then configure any required arguments in the right panel and click **Run** to execute it.

### Quick Actions

Four quick action buttons provide one-click access to common tests:

| Quick Action | Module | Description |
|-------------|--------|-------------|
| **Attack Surface** | `app.package.attacksurface` | Enumerates exported activities, services, broadcast receivers, and content providers |
| **Enumerate Providers** | `app.provider.info` | Lists all content providers and their export status |
| **Test SQL Injection** | `scanner.provider.injection` | Tests content providers for SQL injection vulnerabilities |
| **Test Path Traversal** | `scanner.provider.traversal` | Tests content providers for path traversal vulnerabilities |

### Results Console

All module results appear in the dark-themed console panel. Results are displayed with:
- Module name (in blue)
- Execution timestamp (in green)
- Result type tag (info, finding, vulnerability, warning, error)
- Structured data (activities, providers, vulnerabilities) or raw output

Use the trash icon to clear the results console.

---

## 11. Objection Integration

### Overview

Objection is a runtime mobile exploration toolkit powered by Frida. Mobilicustos integrates Objection for both Android and iOS. Navigate to **Objection** in the sidebar.

### Starting Sessions

1. Select a **Device** from the dropdown (both Android and iOS devices are supported).
2. Enter the **Package Name** (Android) or **Bundle ID** (iOS).
3. Click **Start Session**.
4. The session panel shows platform, package name, and status.

### Terminal

The Terminal tab provides a command-line interface for running Objection commands:

1. Type a command in the input field at the bottom.
2. Press Enter or click the send button.
3. Output appears in the terminal with color-coded messages:
   - Green prompt for input commands
   - White text for standard output
   - Red text for errors
   - Green text for success messages

### Command Browser

The left panel includes a searchable command browser organized by category. Commands are filtered by the selected platform (Android or iOS). Click a command to auto-fill it in the terminal input.

### Quick Actions

| Quick Action | Description |
|-------------|-------------|
| **Disable SSL Pinning** | Bypasses certificate pinning in the target app |
| **Disable Root Detection** | Disables root/jailbreak detection checks |
| **Dump Keychain/Keystore** | Extracts stored credentials (switches to Keychain tab with results) |
| **List Modules** | Lists all loaded native modules in the app process |

### File Browser

The File Browser tab lets you navigate the application's file system on the device:

1. The path bar shows the current directory (defaults to `/data/data` for Android or `/var/mobile/Containers/Data/Application` for iOS).
2. Use the up arrow to navigate to the parent directory.
3. Double-click folders to navigate into them.
4. Double-click files to view their contents in a dialog.
5. Icons indicate file types: folders, databases (.db, .sqlite), configuration files (.plist, .xml, .json), and generic files.

### SQLite Explorer

The SQLite tab allows direct database queries:

1. Enter the **Database Path** on the device (e.g., `/data/data/com.example/databases/app.db`).
2. Write a **SQL Query**.
3. Click **Execute Query**.
4. Results display in a paginated table.

### Keychain/Keystore Viewer

The Keychain (iOS) or Keystore (Android) tab displays dumped credential entries with:
- Service or alias name
- Account or key identifier
- Data value (truncated for security)

---

## 12. API Endpoint Discovery

### Overview

Mobilicustos extracts API endpoints from application binaries during static analysis. Navigate to **API Endpoints** in the sidebar.

### Viewing Discovered Endpoints

1. Select an application from the dropdown.
2. Summary cards display:
   - Total endpoints discovered
   - Unique hosts
   - Insecure (HTTP) endpoints
   - Security issues count

3. The endpoints table shows:
   - **URL** -- The discovered endpoint (insecure URLs highlighted in red)
   - **Method** -- HTTP method (GET, POST, PUT, DELETE), color-coded
   - **Host** -- The hostname
   - **Source File** -- Where in the app binary the URL was found
   - **HTTPS** -- Lock icon indicating secure (green) or insecure (red) transport
   - **Security Issues** -- Tags for issues like insecure transport, debug endpoints, admin endpoints, exposed Swagger, GraphQL introspection, or Spring Actuator endpoints

### Filtering Endpoints

Filter by:
- **Host** -- Filter by specific hostname
- **Method** -- Filter by HTTP method
- **Issue Type** -- Filter by security issue type

### Exporting Endpoints

Use the **Export** split button to download endpoints in multiple formats:

| Format | Use Case |
|--------|----------|
| **Burp Suite XML** | Import directly into Burp Suite's target scope |
| **OpenAPI 3.0** | Standard API specification format |
| **Postman Collection** | Import into Postman for API testing |
| **CSV** | Spreadsheet analysis |

### Probing Hidden Endpoints

The probe feature tests for common hidden paths that may not appear in the application code:

1. Click **Probe Hidden Endpoints**.
2. Enter one or more base URLs (one per line).
3. The platform probes predefined paths including: `/admin`, `/debug`, `/actuator`, `/graphql`, `/swagger.json`, `/swagger-ui`, `/.env`, `/wp-admin`, `/api/v1/docs`, `/health`, `/metrics`, `/trace`, `/info`.
4. Results show the URL, HTTP status code, and response size. Responding endpoints (200-299) are highlighted in green.

---

## 13. Burp Suite Integration

### Overview

Mobilicustos integrates with Burp Suite Professional's REST API for web vulnerability scanning and proxy history import. Navigate to **Burp Suite** in the sidebar.

### Adding Connections

1. Click **Add Connection**.
2. Provide:
   - **Connection Name** -- A friendly name (e.g., "Local Burp")
   - **API URL** -- The Burp REST API endpoint (default: `http://localhost:1337`)
   - **API Key** -- Found in Burp Suite under User Options > Misc > REST API
3. Click **Add Connection**.
4. Test the connection using the refresh button on the connection card. A successful test shows the Burp version.

### Managing Connections

Connection cards display the name, API URL, connection status, and Burp version. Click a connection card to select it and access scan management features.

### Running Scans

After selecting a connection, the **Start Scan** tab allows you to:

1. Enter **Target URLs** (one per line).
2. Optionally link the scan to a Mobilicustos application.
3. Optionally select a Burp scan configuration.
4. Click **Start Scan**.

### Active Scans

The **Active Scans** tab shows running Burp scans with:
- Task ID
- Number of target URLs
- Status (running, completed, failed, stopped)
- Progress percentage
- Issue count

Actions include refreshing status, importing issues (when completed), and stopping running scans.

### Importing Results

When a Burp scan completes:
1. Click the import button on the scan row.
2. Optionally link the issues to a Mobilicustos application.
3. Click **Import** to create Mobilicustos findings from Burp issues.

### Proxy History

The **Proxy History** tab retrieves captured HTTP requests from Burp:
1. Click **Fetch History** to load entries.
2. Select entries using checkboxes.
3. Click **Import Selected** to import them.

### Imported Issues

The **Imported Issues** tab shows all Burp issues that have been imported into Mobilicustos, with severity, confidence, URL, and a link to the corresponding Mobilicustos finding.

---

## 14. Scheduled Scans

### Overview

Scheduled Scans allow you to automate recurring security scans using CRON expressions. Navigate to **Scheduled Scans** in the sidebar.

### Dashboard

Four stats cards show:
- **Active Schedules** -- Number of currently active schedules
- **Paused** -- Number of paused schedules
- **Runs Today** -- Scans triggered today
- **Next Run** -- Time until the next scheduled scan

### Creating a Schedule

1. Click **New Schedule**.
2. Fill in the form:
   - **Schedule Name** -- A descriptive name (e.g., "Daily Security Scan")
   - **Application** -- Select the target application
   - **Schedule** -- Choose a preset or enter a custom CRON expression:

     | Preset | CRON Expression |
     |--------|----------------|
     | Every hour | `0 * * * *` |
     | Every 6 hours | `0 */6 * * *` |
     | Daily at midnight | `0 0 * * *` |
     | Daily at 2 AM | `0 2 * * *` |
     | Weekly on Monday | `0 0 * * 1` |
     | Monthly on the 1st | `0 0 1 * *` |

   - **Analyzers** -- Optionally select specific analyzers (leave empty to run all)
   - **Webhook URL** -- Optional URL for scan completion notifications
   - **Notification Email** -- Optional email for scan results
   - **Status** -- Active or Paused

3. Click **Create**.

### Managing Schedules

The schedules table shows all configured schedules with:
- Name and active/paused indicator
- Associated application
- Schedule description (human-readable CRON interpretation)
- Next run time
- Last run time (relative, e.g., "2h ago")
- Total run count
- Active/Paused status tag

Actions for each schedule:
- **Run Now** -- Trigger the scan immediately without waiting for the schedule
- **Pause/Resume** -- Toggle the schedule's active state
- **Edit** -- Modify schedule settings
- **Delete** -- Remove the schedule

---

## 15. Webhooks

### Overview

Webhooks deliver real-time HTTP POST notifications when events occur in Mobilicustos. Navigate to **Webhooks** in the sidebar.

### Creating a Webhook

1. Click **New Webhook**.
2. Fill in the form:
   - **Webhook Name** -- A descriptive name (e.g., "Slack Notifications")
   - **Webhook URL** -- The endpoint that will receive POST requests
   - **Events** -- Select one or more events to subscribe to:

     | Event | Trigger |
     |-------|---------|
     | Scan Started | When a scan begins |
     | Scan Completed | When a scan finishes successfully |
     | Scan Failed | When a scan encounters an error |
     | New Finding | When a new security finding is discovered |
     | Finding Status Changed | When a finding's status is updated |
     | App Uploaded | When a new application is uploaded |
     | Schedule Triggered | When a scheduled scan fires |

   - **Custom Headers** -- Add optional HTTP headers (e.g., for authentication)
   - **Status** -- Active or Paused

3. Click **Create**.
4. A dialog displays the **webhook secret**. Copy and store this securely -- it is used to verify webhook signatures via the `X-Webhook-Signature` header.

### Managing Webhooks

The webhooks table shows:
- Name with active/paused indicator
- URL (truncated)
- Subscribed events (as tags)
- Delivery stats (success and failure counts)
- Active/Paused status

### Actions

| Action | Description |
|--------|-------------|
| **Test** | Sends a test payload to verify delivery. Shows response time and status code. |
| **Pause/Resume** | Toggles the webhook's active state |
| **Regenerate Secret** | Creates a new signing secret (invalidates the old one) |
| **Edit** | Modify webhook settings |
| **Delete** | Remove the webhook |

### Verifying Webhook Signatures

Each webhook delivery includes an `X-Webhook-Signature` header. Use the webhook secret to verify the HMAC signature of the request body to ensure the payload was not tampered with.

---

## 16. Settings

### Overview

The Settings page provides system configuration details and service health monitoring. Navigate to **Settings** in the sidebar.

### Connection Status

Four status cards show the health of core services:

| Service | Description |
|---------|-------------|
| **PostgreSQL** | Primary database |
| **Neo4j** | Graph database for attack paths |
| **Redis** | Cache and message queue |
| **Frida** | Dynamic instrumentation server |

Each card shows Connected (green) or Disconnected (red) with a status message. Click **Refresh Status** to re-check all services.

### Configuration Overview

Configuration cards display current system settings organized by section:

- **Database** -- Host, port, database name, user
- **API** -- Host, port, debug mode, log level
- **Frida** -- Server version, server host
- **Analysis** -- Max APK size, max IPA size, analysis timeout
- **Paths** -- Upload directory, reports directory, Frida scripts directory
- **Tools** -- JADX path, APKTool path

### Registered Devices

A table of all registered devices with quick access to the Devices management page.

### Frida Configuration

Detailed Frida server configuration including connection status, server version, and a link to the Frida Console for script management.

### Preferences

- **Dark Mode** -- Toggle between light and dark themes. The preference is saved to local storage and persists across sessions.
- **Default Export Format** -- Set the default format for finding exports (CSV, JSON, HTML, PDF, or SARIF).

### About

Displays the platform version (currently 0.1.0) and a link to the GitHub repository.

---

## Keyboard Shortcuts

Mobilicustos supports keyboard shortcuts for fast navigation:

| Shortcut | Action |
|----------|--------|
| `Alt+D` | Go to Dashboard |
| `Alt+A` | Go to Apps |
| `Alt+S` | Go to Scans |
| `Alt+F` | Go to Findings |
| `Alt+V` | Go to Devices |
| `Alt+R` | Go to Frida Console |
| `Alt+C` | Go to Compliance |
| `Alt+P` | Go to Attack Paths |
| `Alt+K` | Go to Secrets |

Press the **Shortcuts** button in the sidebar footer to view the full list of available shortcuts.

---

## Tips and Best Practices

1. **Run static analysis first.** Static scans do not require a connected device and provide a baseline of findings that dynamic analysis can build upon.

2. **Use Full scans for comprehensive coverage.** Full scans combine static and dynamic analysis, ensuring both code-level and runtime issues are detected.

3. **Validate secrets immediately.** The Secrets view can check whether discovered credentials are still active. Active secrets represent the highest-priority findings.

4. **Generate attack paths after scanning.** Attack paths are most valuable when there are multiple findings that can be chained together.

5. **Export in SARIF for CI/CD integration.** The SARIF format is supported by most CI/CD platforms and code scanning tools (e.g., GitHub Code Scanning, Azure DevOps).

6. **Use scheduled scans for regression testing.** Set up recurring scans to catch new vulnerabilities introduced by app updates.

7. **Configure webhooks for notifications.** Integrate with Slack, Teams, or custom endpoints to receive real-time alerts when critical findings are discovered.

8. **Pin Frida server to version 16.x.** Version 17.x has known compatibility issues with certain device configurations. Keep the client and server on the same major version.

9. **Use the Bypass view before manual testing.** Automated bypass detection and execution can save significant time compared to writing custom Frida scripts from scratch.

10. **Check MASVS compliance before release.** Use the Compliance view to generate a comprehensive MASVS report before submitting an app to stakeholders or app stores.
