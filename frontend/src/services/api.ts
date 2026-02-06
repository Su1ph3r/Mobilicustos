import axios from 'axios'

/**
 * Axios instance configured with /api base URL, 30s timeout, and JSON content type.
 * Includes request interceptor for Bearer token injection and response interceptor
 * for 401 handling (token removal).
 */
const api = axios.create({
  baseURL: '/api',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Add auth token if available
    const token = localStorage.getItem('token')
    if (token) {
      config.headers.Authorization = `Bearer ${token}`
    }
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized
      localStorage.removeItem('token')
    }
    return Promise.reject(error)
  }
)

/** Apps API - CRUD operations for mobile application management (upload, list, get, delete, stats) */
export const appsApi = {
  list: (params?: Record<string, any>) => api.get('/apps', { params }),
  get: (id: string) => api.get(`/apps/${id}`),
  upload: (file: File) => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/apps', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
  },
  delete: (id: string) => api.delete(`/apps/${id}`),
  getStats: (id: string) => api.get(`/apps/${id}/stats`),
}

/** Scans API - Create, list, cancel, delete scans with progress tracking and bulk operations */
export const scansApi = {
  list: (params?: Record<string, any>) => api.get('/scans', { params }),
  get: (id: string) => api.get(`/scans/${id}`),
  create: (data: { app_id: string; scan_type: string; analyzers_enabled?: string[] }) =>
    api.post('/scans', data),
  cancel: (id: string) => api.post(`/scans/${id}/cancel`),
  delete: (id: string) => api.delete(`/scans/${id}`),
  getProgress: (id: string) => api.get(`/scans/${id}/progress`),
  purge: (appId: string) => api.delete(`/scans/purge/${appId}`),
  bulkDelete: (scanIds: string[]) => api.post('/scans/bulk-delete', scanIds),
}

/** Findings API - List, filter, update status, bulk operations, and purge security findings */
export const findingsApi = {
  list: (params?: Record<string, any>) => api.get('/findings', { params }),
  get: (id: string) => api.get(`/findings/${id}`),
  getSummary: (params?: Record<string, any>) => api.get('/findings/summary', { params }),
  updateStatus: (id: string, status: string) =>
    api.patch(`/findings/${id}/status`, null, { params: { new_status: status } }),
  bulkUpdateStatus: (ids: string[], status: string) =>
    api.post('/findings/bulk-status', ids, { params: { new_status: status } }),
  getFilterOptions: () => api.get('/findings/filters/options'),
  delete: (id: string) => api.delete(`/findings/${id}`),
  bulkDelete: (ids: string[]) => api.post('/findings/bulk-delete', ids),
  purge: (appId: string) => api.delete(`/findings/purge/${appId}`),
}

/** Devices API - Device discovery, registration, connection, and Frida server management */
export const devicesApi = {
  list: (params?: Record<string, any>) => api.get('/devices', { params }),
  get: (id: string) => api.get(`/devices/${id}`),
  discover: () => api.get('/devices/discover'),
  register: (data: Record<string, any>) => api.post('/devices', data),
  connect: (id: string) => api.post(`/devices/${id}/connect`),
  installFrida: (id: string) => api.post(`/devices/${id}/frida/install`),
  startFrida: (id: string) => api.post(`/devices/${id}/frida/start`),
  delete: (id: string) => api.delete(`/devices/${id}`),
}

/** Frida API - Script CRUD, injection, session management, and script categories */
export const fridaApi = {
  listScripts: (params?: Record<string, any>) => api.get('/frida/scripts', { params }),
  getScript: (id: string) => api.get(`/frida/scripts/${id}`),
  createScript: (data: Record<string, any>) => api.post('/frida/scripts', data),
  updateScript: (id: string, data: Record<string, any>) => api.put(`/frida/scripts/${id}`, data),
  deleteScript: (id: string) => api.delete(`/frida/scripts/${id}`),
  inject: (data: { device_id: string; app_id: string; script_id?: string; script_content?: string }) =>
    api.post('/frida/inject', data),
  listSessions: () => api.get('/frida/sessions'),
  detachSession: (id: string) => api.delete(`/frida/sessions/${id}`),
  getCategories: () => api.get('/frida/scripts/categories'),
}

/** Bypass API - Analyze protections, attempt individual/auto bypass, and list results */
export const bypassApi = {
  listResults: (params?: Record<string, any>) => api.get('/bypass/results', { params }),
  analyzeProtections: (appId: string) => api.post('/bypass/analyze', null, { params: { app_id: appId } }),
  attemptBypass: (data: Record<string, any>) => api.post('/bypass/attempt', null, { params: data }),
  autoBypass: (appId: string, deviceId: string) =>
    api.post('/bypass/auto-bypass', null, { params: { app_id: appId, device_id: deviceId } }),
  getDetectionTypes: () => api.get('/bypass/detection-types'),
  getRecommendedScripts: (appId: string, detectionType: string) =>
    api.get('/bypass/scripts/recommended', { params: { app_id: appId, detection_type: detectionType } }),
}

/** ML Models API - Extract, analyze, and inspect machine learning models embedded in apps */
export const mlModelsApi = {
  list: (params?: Record<string, any>) => api.get('/ml-models', { params }),
  get: (id: string) => api.get(`/ml-models/${id}`),
  extract: (appId: string) => api.post('/ml-models/extract', null, { params: { app_id: appId } }),
  analyze: (id: string) => api.post(`/ml-models/${id}/analyze`),
  getSecurity: (id: string) => api.get(`/ml-models/${id}/security`),
  getFormats: () => api.get('/ml-models/formats'),
}

/** Secrets API - List, validate, and summarize detected secrets with type/provider metadata */
export const secretsApi = {
  list: (params?: Record<string, any>) => api.get('/secrets', { params }),
  get: (id: string) => api.get(`/secrets/${id}`),
  getSummary: (params?: Record<string, any>) => api.get('/secrets/summary', { params }),
  validate: (id: string) => api.post(`/secrets/${id}/validate`),
  getTypes: () => api.get('/secrets/types'),
  getProviders: () => api.get('/secrets/providers'),
}

/** Attack Paths API - List, generate, get details, graph, and findings for attack chains */
export const attackPathsApi = {
  list: (params?: Record<string, any>) => api.get('/attack-paths', { params }),
  get: (id: string) => api.get(`/attack-paths/${id}`),
  getFindings: (id: string) => api.get(`/attack-paths/${id}/findings`),
  generate: (appId: string) => api.post('/attack-paths/generate', null, { params: { app_id: appId } }),
  getGraph: (id: string) => api.get(`/attack-paths/${id}/graph`),
  delete: (id: string) => api.delete(`/attack-paths/${id}`),
}

/** Compliance API - OWASP MASVS overview, per-app compliance, category details, and report generation */
export const complianceApi = {
  getMasvsOverview: () => api.get('/compliance/masvs'),
  getAppCompliance: (appId: string) => api.get(`/compliance/masvs/${appId}`),
  getCategoryDetails: (appId: string, category: string) =>
    api.get(`/compliance/masvs/${appId}/${category}`),
  generateReport: (appId: string) => api.get(`/compliance/report/${appId}`),
}

/** Exports API - Download findings and reports in multiple formats (CSV, JSON, HTML, PDF, SARIF) */
export const exportsApi = {
  exportFindings: (appId: string, format: string, params?: Record<string, any>) =>
    api.get(`/exports/findings/${appId}`, {
      params: { format, ...params },
      responseType: 'blob',
    }),
  exportReport: (appId: string, format: string) =>
    api.get(`/exports/report/${appId}`, {
      params: { format },
      responseType: format === 'json' ? 'json' : 'blob',
    }),
}

/** Drozer API - Session management, module execution, and quick security assessment actions for Android */
export const drozerApi = {
  getStatus: () => api.get('/drozer/status'),
  listModules: () => api.get('/drozer/modules'),
  listSessions: (params?: Record<string, any>) => api.get('/drozer/sessions', { params }),
  getSession: (id: string) => api.get(`/drozer/sessions/${id}`),
  startSession: (data: { device_id: string; package_name: string }) =>
    api.post('/drozer/sessions', data),
  stopSession: (id: string) => api.delete(`/drozer/sessions/${id}`),
  runModule: (sessionId: string, data: { module_name: string; args: Record<string, string> }) =>
    api.post(`/drozer/sessions/${sessionId}/run`, data),
  getSessionResults: (sessionId: string, params?: Record<string, any>) =>
    api.get(`/drozer/sessions/${sessionId}/results`, { params }),
  // Quick actions
  quickAttackSurface: (deviceId: string, packageName: string) =>
    api.post('/drozer/quick/attack-surface', null, { params: { device_id: deviceId, package_name: packageName } }),
  quickEnumerateProviders: (deviceId: string, packageName: string) =>
    api.post('/drozer/quick/enumerate-providers', null, { params: { device_id: deviceId, package_name: packageName } }),
  quickTestSQLi: (deviceId: string, packageName: string) =>
    api.post('/drozer/quick/test-sqli', null, { params: { device_id: deviceId, package_name: packageName } }),
  quickTestTraversal: (deviceId: string, packageName: string) =>
    api.post('/drozer/quick/test-traversal', null, { params: { device_id: deviceId, package_name: packageName } }),
}

/** Objection API - Session management, command execution, file/SQL operations, and quick runtime actions */
export const objectionApi = {
  getStatus: () => api.get('/objection/status'),
  listCommands: (platform?: string) => api.get('/objection/commands', { params: { platform } }),
  listSessions: (params?: Record<string, any>) => api.get('/objection/sessions', { params }),
  getSession: (id: string) => api.get(`/objection/sessions/${id}`),
  startSession: (data: { device_id: string; package_name: string }) =>
    api.post('/objection/sessions', data),
  stopSession: (id: string) => api.delete(`/objection/sessions/${id}`),
  executeCommand: (sessionId: string, data: { command: string; args: string[] }) =>
    api.post(`/objection/sessions/${sessionId}/execute`, data),
  // File operations
  listFiles: (sessionId: string, path: string) =>
    api.get(`/objection/sessions/${sessionId}/files`, { params: { path } }),
  readFile: (sessionId: string, path: string) =>
    api.get(`/objection/sessions/${sessionId}/file`, { params: { path } }),
  // SQL operations
  executeSql: (sessionId: string, dbPath: string, query: string) =>
    api.post(`/objection/sessions/${sessionId}/sql`, null, { params: { db_path: dbPath, query } }),
  // iOS plist
  readPlist: (sessionId: string, path: string) =>
    api.get(`/objection/sessions/${sessionId}/plist`, { params: { path } }),
  // Quick actions
  quickDisableSSL: (deviceId: string, packageName: string) =>
    api.post('/objection/quick/disable-ssl-pinning', null, { params: { device_id: deviceId, package_name: packageName } }),
  quickDisableRoot: (deviceId: string, packageName: string) =>
    api.post('/objection/quick/disable-root-detection', null, { params: { device_id: deviceId, package_name: packageName } }),
  quickDumpKeychain: (deviceId: string, packageName: string) =>
    api.post('/objection/quick/dump-keychain', null, { params: { device_id: deviceId, package_name: packageName } }),
  quickListModules: (deviceId: string, packageName: string) =>
    api.post('/objection/quick/list-modules', null, { params: { device_id: deviceId, package_name: packageName } }),
}

/** Scheduled Scans API - CRUD, trigger, pause/resume, history, and cron validation for scheduled scans */
export const scheduledScansApi = {
  list: (params?: Record<string, any>) => api.get('/scheduled-scans', { params }).then(r => r.data),
  get: (id: string) => api.get(`/scheduled-scans/${id}`).then(r => r.data),
  create: (data: Record<string, any>) => api.post('/scheduled-scans', data).then(r => r.data),
  update: (id: string, data: Record<string, any>) => api.put(`/scheduled-scans/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/scheduled-scans/${id}`).then(r => r.data),
  trigger: (id: string) => api.post(`/scheduled-scans/${id}/run`).then(r => r.data),
  pause: (id: string) => api.post(`/scheduled-scans/${id}/pause`).then(r => r.data),
  resume: (id: string) => api.post(`/scheduled-scans/${id}/resume`).then(r => r.data),
  getHistory: (id: string) => api.get(`/scheduled-scans/${id}/history`).then(r => r.data),
  validateCron: (expression: string) => api.post('/scheduled-scans/validate-cron', { cron_expression: expression }).then(r => r.data),
}

/** Webhooks API - CRUD, test, pause/resume, secret regeneration, events, and delivery history */
export const webhooksApi = {
  list: (params?: Record<string, any>) => api.get('/webhooks', { params }).then(r => r.data),
  get: (id: string) => api.get(`/webhooks/${id}`).then(r => r.data),
  create: (data: Record<string, any>) => api.post('/webhooks', data).then(r => r.data),
  update: (id: string, data: Record<string, any>) => api.put(`/webhooks/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/webhooks/${id}`).then(r => r.data),
  test: (id: string) => api.post(`/webhooks/${id}/test`).then(r => r.data),
  pause: (id: string) => api.post(`/webhooks/${id}/pause`).then(r => r.data),
  resume: (id: string) => api.post(`/webhooks/${id}/resume`).then(r => r.data),
  regenerateSecret: (id: string) => api.post(`/webhooks/${id}/regenerate-secret`).then(r => r.data),
  getEvents: () => api.get('/webhooks/events').then(r => r.data),
  getDeliveries: (id: string) => api.get(`/webhooks/${id}/deliveries`).then(r => r.data),
}

/** Burp Suite API - Connection management, scan control, proxy history, and issue import/listing */
export const burpApi = {
  // Connections
  listConnections: (params?: Record<string, any>) => api.get('/burp/connections', { params }).then(r => r.data),
  getConnection: (id: string) => api.get(`/burp/connections/${id}`).then(r => r.data),
  createConnection: (data: Record<string, any>) => api.post('/burp/connections', data).then(r => r.data),
  deleteConnection: (id: string) => api.delete(`/burp/connections/${id}`).then(r => r.data),
  testConnection: (id: string) => api.post(`/burp/connections/${id}/test`).then(r => r.data),
  getScanConfigs: (id: string) => api.get(`/burp/connections/${id}/configurations`).then(r => r.data),

  // Scans
  startScan: (connectionId: string, data: { target_urls: string[]; app_id?: string; scan_config?: string }) =>
    api.post(`/burp/connections/${connectionId}/scans`, data).then(r => r.data),
  getScanStatus: (taskId: string) => api.get(`/burp/scans/${taskId}`).then(r => r.data),
  stopScan: (taskId: string) => api.post(`/burp/scans/${taskId}/stop`).then(r => r.data),
  importIssues: (taskId: string, appId?: string) =>
    api.post(`/burp/scans/${taskId}/import`, null, { params: appId ? { app_id: appId } : {} }).then(r => r.data),

  // Proxy
  getProxyHistory: (connectionId: string, limit?: number) =>
    api.get(`/burp/connections/${connectionId}/proxy-history`, { params: { limit } }).then(r => r.data),
  importProxyHistory: (connectionId: string, appId: string, itemIds?: number[]) =>
    api.post(`/burp/connections/${connectionId}/proxy-history/import`, null, {
      params: { app_id: appId, item_ids: itemIds },
    }).then(r => r.data),

  // Issues
  listIssues: (params?: Record<string, any>) => api.get('/burp/issues', { params }).then(r => r.data),
  getIssue: (id: string) => api.get(`/burp/issues/${id}`).then(r => r.data),
}

/** API Endpoints API - List discovered endpoints, export in multiple formats, and probe hidden paths */
export const apiEndpointsApi = {
  list: (appId: string) => api.get(`/api-endpoints/${appId}`),
  exportEndpoints: (appId: string, format: string) =>
    api.get(`/api-endpoints/${appId}/export`, { params: { format }, responseType: 'blob' }),
  probe: (appId: string, baseUrls: string[]) =>
    api.post(`/api-endpoints/${appId}/probe`, { base_urls: baseUrls }),
}

/** Settings API - Retrieve system configuration and service connection status */
export const settingsApi = {
  getSettings: () => api.get('/settings'),
  getStatus: () => api.get('/settings/status'),
}

export default api
