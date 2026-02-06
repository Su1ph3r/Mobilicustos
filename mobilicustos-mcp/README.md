# Mobilicustos MCP Server

Model Context Protocol (MCP) server for the Mobilicustos mobile security analysis platform.

## Features

This MCP server provides AI assistant integration for:

- **Application Analysis**: Upload, scan, and analyze mobile apps
- **Finding Management**: Query and explain security findings
- **Device Control**: Manage connected devices for dynamic analysis
- **Frida Integration**: Inject scripts and bypass protections
- **Compliance Reporting**: Generate OWASP MASVS compliance reports

## Installation

```bash
cd mobilicustos-mcp
npm install
npm run build
```

## Configuration

Set the API URL environment variable:

```bash
export MOBILICUSTOS_API_URL=http://localhost:8000/api
```

## Usage with MCP Clients

Add to your MCP client configuration:

```json
{
  "mcpServers": {
    "mobilicustos": {
      "command": "node",
      "args": ["/path/to/mobilicustos-mcp/dist/index.js"],
      "env": {
        "MOBILICUSTOS_API_URL": "http://localhost:8000/api"
      }
    }
  }
}
```

## Available Tools

| Tool | Description |
|------|-------------|
| `list_apps` | List uploaded mobile applications |
| `get_app` | Get application details |
| `start_scan` | Start a security scan |
| `get_scan_status` | Check scan progress |
| `list_findings` | List security findings |
| `get_finding` | Get finding details with PoC and remediation |
| `get_findings_summary` | Get findings statistics |
| `list_devices` | List connected devices |
| `discover_devices` | Refresh device list |
| `inject_frida_script` | Run Frida script on device |
| `analyze_protections` | Analyze app protections |
| `attempt_bypass` | Attempt to bypass protection |
| `extract_ml_models` | Extract ML models from app |
| `list_secrets` | List detected secrets |
| `validate_secret` | Check if secret is active |
| `get_compliance` | Get MASVS compliance status |
| `generate_attack_paths` | Generate attack path analysis |
| `get_ios_capabilities` | Check iOS analysis capabilities |

## Available Prompts

| Prompt | Description |
|--------|-------------|
| `analyze_app` | Comprehensive security analysis |
| `explain_finding` | Detailed finding explanation |
| `bypass_guide` | Protection bypass guide |
| `compliance_report` | MASVS compliance report |

## Example Usage

Once connected, you can ask questions like:

- "Analyze the app with ID abc123 for security issues"
- "Explain finding XYZ and how to fix it"
- "Help me bypass SSL pinning on this Android app"
- "Generate a compliance report for app abc123"
- "List all critical findings with remediation steps"

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Type check
npm run typecheck
```

## License

MIT
