#!/usr/bin/env node
/**
 * Mobilicustos MCP Server
 *
 * Provides LLM integration for mobile security analysis platform.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";
import { z } from "zod";

// Configuration
const API_BASE_URL = process.env.MOBILICUSTOS_API_URL || "http://localhost:8000/api";

// API Client
class MobilicustosClient {
  private client: AxiosInstance;

  constructor(baseUrl: string) {
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 30000,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Apps
  async listApps(params?: Record<string, any>) {
    const response = await this.client.get("/apps", { params });
    return response.data;
  }

  async getApp(appId: string) {
    const response = await this.client.get(`/apps/${appId}`);
    return response.data;
  }

  async getAppStats(appId: string) {
    const response = await this.client.get(`/apps/${appId}/stats`);
    return response.data;
  }

  // Scans
  async listScans(params?: Record<string, any>) {
    const response = await this.client.get("/scans", { params });
    return response.data;
  }

  async getScan(scanId: string) {
    const response = await this.client.get(`/scans/${scanId}`);
    return response.data;
  }

  async createScan(appId: string, scanType: string, analyzers?: string[]) {
    const response = await this.client.post("/scans", {
      app_id: appId,
      scan_type: scanType,
      analyzers_enabled: analyzers,
    });
    return response.data;
  }

  async getScanProgress(scanId: string) {
    const response = await this.client.get(`/scans/${scanId}/progress`);
    return response.data;
  }

  // Findings
  async listFindings(params?: Record<string, any>) {
    const response = await this.client.get("/findings", { params });
    return response.data;
  }

  async getFinding(findingId: string) {
    const response = await this.client.get(`/findings/${findingId}`);
    return response.data;
  }

  async getFindingsSummary(params?: Record<string, any>) {
    const response = await this.client.get("/findings/summary", { params });
    return response.data;
  }

  // Devices
  async listDevices() {
    const response = await this.client.get("/devices");
    return response.data;
  }

  async discoverDevices() {
    const response = await this.client.get("/devices/discover");
    return response.data;
  }

  // Frida
  async listFridaScripts() {
    const response = await this.client.get("/frida/scripts");
    return response.data;
  }

  async injectFridaScript(deviceId: string, appId: string, scriptContent: string) {
    const response = await this.client.post("/frida/inject", {
      device_id: deviceId,
      app_id: appId,
      script_content: scriptContent,
    });
    return response.data;
  }

  // Bypass
  async analyzeProtections(appId: string) {
    const response = await this.client.post("/bypass/analyze", null, {
      params: { app_id: appId },
    });
    return response.data;
  }

  async attemptBypass(appId: string, deviceId: string, detectionType: string) {
    const response = await this.client.post("/bypass/attempt", null, {
      params: { app_id: appId, device_id: deviceId, detection_type: detectionType },
    });
    return response.data;
  }

  // ML Models
  async listMLModels(params?: Record<string, any>) {
    const response = await this.client.get("/ml-models", { params });
    return response.data;
  }

  async extractMLModels(appId: string) {
    const response = await this.client.post("/ml-models/extract", null, {
      params: { app_id: appId },
    });
    return response.data;
  }

  // Secrets
  async listSecrets(params?: Record<string, any>) {
    const response = await this.client.get("/secrets", { params });
    return response.data;
  }

  async validateSecret(secretId: string) {
    const response = await this.client.post(`/secrets/${secretId}/validate`);
    return response.data;
  }

  // Compliance
  async getAppCompliance(appId: string) {
    const response = await this.client.get(`/compliance/masvs/${appId}`);
    return response.data;
  }

  // Attack Paths
  async listAttackPaths(params?: Record<string, any>) {
    const response = await this.client.get("/attack-paths", { params });
    return response.data;
  }

  async generateAttackPaths(appId: string) {
    const response = await this.client.post("/attack-paths/generate", null, {
      params: { app_id: appId },
    });
    return response.data;
  }

  // iOS
  async getIOSCapabilities() {
    const response = await this.client.get("/ios/capabilities");
    return response.data;
  }
}

// Create client
const client = new MobilicustosClient(API_BASE_URL);

// Tool Definitions
const tools = [
  {
    name: "list_apps",
    description: "List all mobile applications uploaded to Mobilicustos",
    inputSchema: {
      type: "object" as const,
      properties: {
        platform: { type: "string", enum: ["android", "ios"], description: "Filter by platform" },
        framework: { type: "string", description: "Filter by framework (flutter, react_native, etc.)" },
        search: { type: "string", description: "Search by app name or package" },
      },
    },
  },
  {
    name: "get_app",
    description: "Get details of a specific mobile application",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID" },
      },
      required: ["app_id"],
    },
  },
  {
    name: "start_scan",
    description: "Start a security scan on a mobile application",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID to scan" },
        scan_type: {
          type: "string",
          enum: ["static", "dynamic", "full"],
          description: "Type of scan to run",
        },
        analyzers: {
          type: "array",
          items: { type: "string" },
          description: "Specific analyzers to enable (optional)",
        },
      },
      required: ["app_id", "scan_type"],
    },
  },
  {
    name: "get_scan_status",
    description: "Get the current status and progress of a scan",
    inputSchema: {
      type: "object" as const,
      properties: {
        scan_id: { type: "string", description: "Scan ID" },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "list_findings",
    description: "List security findings from scans",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Filter by application ID" },
        scan_id: { type: "string", description: "Filter by scan ID" },
        severity: {
          type: "array",
          items: { type: "string", enum: ["critical", "high", "medium", "low", "info"] },
          description: "Filter by severity levels",
        },
        category: { type: "string", description: "Filter by category" },
        status: { type: "string", description: "Filter by status (open, confirmed, etc.)" },
      },
    },
  },
  {
    name: "get_finding",
    description: "Get detailed information about a specific finding including PoC and remediation",
    inputSchema: {
      type: "object" as const,
      properties: {
        finding_id: { type: "string", description: "Finding ID" },
      },
      required: ["finding_id"],
    },
  },
  {
    name: "get_findings_summary",
    description: "Get summary statistics of findings",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Filter by application ID" },
        scan_id: { type: "string", description: "Filter by scan ID" },
      },
    },
  },
  {
    name: "list_devices",
    description: "List connected mobile devices for dynamic analysis",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "discover_devices",
    description: "Discover and refresh connected mobile devices",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "inject_frida_script",
    description: "Inject a Frida script into a running application",
    inputSchema: {
      type: "object" as const,
      properties: {
        device_id: { type: "string", description: "Target device ID" },
        app_id: { type: "string", description: "Target application ID" },
        script: { type: "string", description: "Frida script content" },
      },
      required: ["device_id", "app_id", "script"],
    },
  },
  {
    name: "analyze_protections",
    description: "Analyze an app for security protections (root detection, SSL pinning, etc.)",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID to analyze" },
      },
      required: ["app_id"],
    },
  },
  {
    name: "attempt_bypass",
    description: "Attempt to bypass a detected security protection",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID" },
        device_id: { type: "string", description: "Device ID" },
        detection_type: {
          type: "string",
          enum: ["root", "ssl_pinning", "frida", "jailbreak", "emulator", "debugger", "tamper", "biometric", "play_integrity"],
          description: "Type of protection to bypass",
        },
      },
      required: ["app_id", "device_id", "detection_type"],
    },
  },
  {
    name: "extract_ml_models",
    description: "Extract ML models from a mobile application",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID" },
      },
      required: ["app_id"],
    },
  },
  {
    name: "list_secrets",
    description: "List detected secrets and credentials",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Filter by application ID" },
        secret_type: { type: "string", description: "Filter by secret type (api_key, password, etc.)" },
        validation_status: { type: "string", description: "Filter by validation status" },
      },
    },
  },
  {
    name: "validate_secret",
    description: "Validate if a detected secret is still active",
    inputSchema: {
      type: "object" as const,
      properties: {
        secret_id: { type: "string", description: "Secret ID to validate" },
      },
      required: ["secret_id"],
    },
  },
  {
    name: "get_compliance",
    description: "Get OWASP MASVS compliance status for an application",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID" },
      },
      required: ["app_id"],
    },
  },
  {
    name: "generate_attack_paths",
    description: "Generate attack path analysis for an application",
    inputSchema: {
      type: "object" as const,
      properties: {
        app_id: { type: "string", description: "Application ID" },
      },
      required: ["app_id"],
    },
  },
  {
    name: "get_ios_capabilities",
    description: "Get available iOS analysis capabilities",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
];

// Prompt Definitions
const prompts = [
  {
    name: "analyze_app",
    description: "Analyze a mobile application for security vulnerabilities",
    arguments: [
      { name: "app_id", description: "The application ID to analyze", required: true },
      { name: "focus", description: "Focus area (storage, network, crypto, auth)", required: false },
    ],
  },
  {
    name: "explain_finding",
    description: "Explain a security finding and how to fix it",
    arguments: [
      { name: "finding_id", description: "The finding ID to explain", required: true },
    ],
  },
  {
    name: "bypass_guide",
    description: "Guide for bypassing a specific security protection",
    arguments: [
      { name: "protection_type", description: "Type of protection (ssl_pinning, root_detection, etc.)", required: true },
      { name: "platform", description: "Platform (android, ios)", required: true },
    ],
  },
  {
    name: "compliance_report",
    description: "Generate a compliance report for an application",
    arguments: [
      { name: "app_id", description: "The application ID", required: true },
    ],
  },
];

// Create MCP Server
const server = new Server(
  {
    name: "mobilicustos-mcp",
    version: "0.1.1",
  },
  {
    capabilities: {
      tools: {},
      prompts: {},
      resources: {},
    },
  }
);

// Tool Handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "list_apps": {
        const result = await client.listApps(args as Record<string, any>);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "get_app": {
        const result = await client.getApp((args as any).app_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "start_scan": {
        const { app_id, scan_type, analyzers } = args as any;
        const result = await client.createScan(app_id, scan_type, analyzers);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "get_scan_status": {
        const result = await client.getScanProgress((args as any).scan_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "list_findings": {
        const result = await client.listFindings(args as Record<string, any>);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "get_finding": {
        const result = await client.getFinding((args as any).finding_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "get_findings_summary": {
        const result = await client.getFindingsSummary(args as Record<string, any>);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "list_devices": {
        const result = await client.listDevices();
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "discover_devices": {
        const result = await client.discoverDevices();
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "inject_frida_script": {
        const { device_id, app_id, script } = args as any;
        const result = await client.injectFridaScript(device_id, app_id, script);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "analyze_protections": {
        const result = await client.analyzeProtections((args as any).app_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "attempt_bypass": {
        const { app_id, device_id, detection_type } = args as any;
        const result = await client.attemptBypass(app_id, device_id, detection_type);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "extract_ml_models": {
        const result = await client.extractMLModels((args as any).app_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "list_secrets": {
        const result = await client.listSecrets(args as Record<string, any>);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "validate_secret": {
        const result = await client.validateSecret((args as any).secret_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "get_compliance": {
        const result = await client.getAppCompliance((args as any).app_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "generate_attack_paths": {
        const result = await client.generateAttackPaths((args as any).app_id);
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      case "get_ios_capabilities": {
        const result = await client.getIOSCapabilities();
        return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
      }
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// Prompt Handlers
server.setRequestHandler(ListPromptsRequestSchema, async () => ({
  prompts,
}));

server.setRequestHandler(GetPromptRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  switch (name) {
    case "analyze_app": {
      const appId = args?.app_id;
      const focus = args?.focus || "all";
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Analyze the mobile application with ID "${appId}" for security vulnerabilities.
${focus !== "all" ? `Focus specifically on ${focus} security.` : ""}

Please:
1. First get the app details using get_app
2. Check findings summary using get_findings_summary
3. List any critical or high findings
4. Provide a summary of the security posture
5. Recommend priority remediation steps`,
            },
          },
        ],
      };
    }

    case "explain_finding": {
      const findingId = args?.finding_id;
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Explain the security finding with ID "${findingId}" in detail.

Please:
1. Get the finding details using get_finding
2. Explain what the vulnerability is in simple terms
3. Describe the potential impact and attack scenarios
4. Provide step-by-step remediation guidance
5. Include any PoC or verification steps`,
            },
          },
        ],
      };
    }

    case "bypass_guide": {
      const protectionType = args?.protection_type;
      const platform = args?.platform;
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Guide me through bypassing ${protectionType} on ${platform}.

Please explain:
1. How ${protectionType} typically works on ${platform}
2. Common detection methods used
3. Step-by-step bypass techniques
4. Frida scripts or tools that can help
5. How to verify the bypass was successful`,
            },
          },
        ],
      };
    }

    case "compliance_report": {
      const appId = args?.app_id;
      return {
        messages: [
          {
            role: "user",
            content: {
              type: "text",
              text: `Generate an OWASP MASVS compliance report for application "${appId}".

Please:
1. Get the compliance status using get_compliance
2. List all MASVS categories and their status
3. For failed controls, list the related findings
4. Provide a compliance score
5. Recommend steps to improve compliance`,
            },
          },
        ],
      };
    }

    default:
      throw new Error(`Unknown prompt: ${name}`);
  }
});

// Resource Handlers
server.setRequestHandler(ListResourcesRequestSchema, async () => ({
  resources: [
    {
      uri: "mobilicustos://findings/summary",
      name: "Findings Summary",
      description: "Summary of all security findings",
      mimeType: "application/json",
    },
    {
      uri: "mobilicustos://apps",
      name: "Applications",
      description: "List of all uploaded applications",
      mimeType: "application/json",
    },
    {
      uri: "mobilicustos://devices",
      name: "Devices",
      description: "Connected mobile devices",
      mimeType: "application/json",
    },
  ],
}));

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
  const { uri } = request.params;

  switch (uri) {
    case "mobilicustos://findings/summary": {
      const result = await client.getFindingsSummary();
      return {
        contents: [{ uri, mimeType: "application/json", text: JSON.stringify(result, null, 2) }],
      };
    }
    case "mobilicustos://apps": {
      const result = await client.listApps();
      return {
        contents: [{ uri, mimeType: "application/json", text: JSON.stringify(result, null, 2) }],
      };
    }
    case "mobilicustos://devices": {
      const result = await client.listDevices();
      return {
        contents: [{ uri, mimeType: "application/json", text: JSON.stringify(result, null, 2) }],
      };
    }
    default:
      throw new Error(`Unknown resource: ${uri}`);
  }
});

// Start Server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Mobilicustos MCP server running on stdio");
}

main().catch(console.error);
