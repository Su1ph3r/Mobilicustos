import { test as base, Page } from '@playwright/test'

/** Shared mock API data used across E2E tests. */
export const mockData = {
  apps: [
    {
      app_id: 'app-001',
      package_name: 'com.example.testapp',
      app_name: 'Test App',
      version_name: '1.0.0',
      platform: 'android',
      status: 'ready',
      upload_date: '2025-01-15T10:00:00Z',
    },
    {
      app_id: 'app-002',
      package_name: 'com.example.iosapp',
      app_name: 'iOS App',
      version_name: '2.0.0',
      platform: 'ios',
      status: 'ready',
      upload_date: '2025-01-16T10:00:00Z',
    },
  ],

  findings: [
    {
      finding_id: 'finding-001',
      app_id: 'app-001',
      tool: 'manifest_analyzer',
      severity: 'high',
      status: 'open',
      category: 'Insecure Configuration',
      title: 'Debuggable Application',
      description: 'The application is marked as debuggable.',
      platform: 'android',
    },
    {
      finding_id: 'finding-002',
      app_id: 'app-001',
      tool: 'secret_scanner',
      severity: 'critical',
      status: 'open',
      category: 'Hardcoded Secrets',
      title: 'API Key Exposed',
      description: 'Firebase API key found in strings.xml.',
      platform: 'android',
    },
    {
      finding_id: 'finding-003',
      app_id: 'app-002',
      tool: 'ssl_pinning_analyzer',
      severity: 'medium',
      status: 'open',
      category: 'Network Security',
      title: 'Missing Certificate Pinning',
      description: 'No SSL pinning detected.',
      platform: 'ios',
    },
  ],

  scans: [
    {
      scan_id: 'scan-001',
      app_id: 'app-001',
      scan_type: 'static',
      status: 'completed',
      progress: 100,
      created_at: '2025-01-15T10:05:00Z',
      completed_at: '2025-01-15T10:10:00Z',
      findings_count: 2,
    },
  ],

  dashboard: {
    total_apps: 2,
    total_scans: 1,
    total_findings: 3,
    severity_counts: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
    recent_scans: [],
    top_vulnerable_apps: [],
  },

  devices: [
    {
      device_id: 'device-001',
      device_type: 'emulator',
      platform: 'android',
      device_name: 'Pixel 6 API 33',
      model: 'sdk_gphone64_x86_64',
      os_version: '13',
      status: 'connected',
      is_rooted: true,
    },
  ],
}

/** Set up API route interception to mock all backend calls. */
export async function mockApiRoutes(page: Page) {
  // Dashboard
  await page.route('**/api/dashboard**', (route) =>
    route.fulfill({ json: mockData.dashboard })
  )

  // Apps
  await page.route('**/api/apps', (route) => {
    if (route.request().method() === 'GET') {
      return route.fulfill({ json: mockData.apps })
    }
    return route.fulfill({ status: 201, json: { app_id: 'app-new', status: 'processing' } })
  })
  await page.route('**/api/apps/*', (route) =>
    route.fulfill({ json: mockData.apps[0] })
  )

  // Scans
  await page.route('**/api/scans', (route) =>
    route.fulfill({ json: mockData.scans })
  )
  await page.route('**/api/scans/*', (route) =>
    route.fulfill({ json: mockData.scans[0] })
  )

  // Findings
  await page.route('**/api/findings', (route) =>
    route.fulfill({ json: mockData.findings })
  )
  await page.route('**/api/findings/*', (route) =>
    route.fulfill({ json: mockData.findings[0] })
  )

  // Devices
  await page.route('**/api/devices**', (route) =>
    route.fulfill({ json: mockData.devices })
  )

  // Exports
  await page.route('**/api/exports/**', (route) =>
    route.fulfill({
      status: 200,
      headers: { 'Content-Disposition': 'attachment; filename=export.json' },
      body: JSON.stringify({ findings: mockData.findings }),
    })
  )

  // Health
  await page.route('**/api/health', (route) =>
    route.fulfill({ json: { status: 'healthy' } })
  )

  // Catch-all for remaining API routes
  await page.route('**/api/**', (route) =>
    route.fulfill({ json: [] })
  )
}

/** Extended test fixture with API mocking pre-configured. */
export const test = base.extend<{ mockPage: Page }>({
  mockPage: async ({ page }, use) => {
    await mockApiRoutes(page)
    await use(page)
  },
})

export { expect } from '@playwright/test'
