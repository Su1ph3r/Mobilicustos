<template>
  <div class="api-endpoints-view">
    <div class="page-header">
      <div>
        <h1>API Endpoints</h1>
        <p class="text-secondary">Discovered API endpoints and security analysis</p>
      </div>
      <div class="header-actions">
        <SplitButton
          label="Export"
          icon="pi pi-download"
          :model="exportOptions"
          @click="exportEndpoints('csv')"
          :disabled="!selectedApp || endpoints.length === 0"
        />
        <Button
          label="Probe Hidden Endpoints"
          icon="pi pi-search-plus"
          severity="warning"
          @click="showProbeDialog = true"
          :disabled="!selectedApp"
        />
      </div>
    </div>

    <!-- App Selector -->
    <div class="card app-selector-card">
      <div class="selector-row">
        <label for="app-select">Select Application:</label>
        <Dropdown
          id="app-select"
          v-model="selectedApp"
          :options="apps"
          optionLabel="app_name"
          optionValue="app_id"
          placeholder="Choose an application..."
          :loading="loadingApps"
          @change="onAppSelected"
          class="app-dropdown"
        />
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid summary-grid" v-if="selectedApp">
      <div class="col-12 md:col-3">
        <div class="summary-card total">
          <span class="count">{{ stats.total }}</span>
          <span class="label">Total Endpoints</span>
        </div>
      </div>
      <div class="col-12 md:col-3">
        <div class="summary-card hosts">
          <span class="count">{{ stats.uniqueHosts }}</span>
          <span class="label">Unique Hosts</span>
        </div>
      </div>
      <div class="col-12 md:col-3">
        <div class="summary-card insecure">
          <span class="count">{{ stats.insecureCount }}</span>
          <span class="label">Insecure (HTTP)</span>
        </div>
      </div>
      <div class="col-12 md:col-3">
        <div class="summary-card issues">
          <span class="count">{{ stats.securityIssuesCount }}</span>
          <span class="label">Security Issues</span>
        </div>
      </div>
    </div>

    <!-- Filter Bar -->
    <div class="card filters-card" v-if="selectedApp">
      <div class="filters-row">
        <Dropdown
          v-model="filterHost"
          :options="availableHosts"
          placeholder="All Hosts"
          showClear
          @change="applyFilters"
        />
        <Dropdown
          v-model="filterMethod"
          :options="availableMethods"
          placeholder="All Methods"
          showClear
          @change="applyFilters"
        />
        <Dropdown
          v-model="filterIssueType"
          :options="availableIssueTypes"
          placeholder="All Issue Types"
          showClear
          @change="applyFilters"
        />
      </div>
    </div>

    <!-- Endpoints Table -->
    <div class="card" v-if="selectedApp">
      <DataTable
        :value="filteredEndpoints"
        :loading="loading"
        responsiveLayout="scroll"
        :paginator="true"
        :rows="20"
        :rowsPerPageOptions="[10, 20, 50, 100]"
        sortMode="single"
        :sortField="'url'"
        :sortOrder="1"
        stripedRows
      >
        <template #empty>
          <div class="empty-state">
            <i class="pi pi-link"></i>
            <p>No API endpoints discovered yet. Run a scan to extract endpoints.</p>
          </div>
        </template>

        <Column field="url" header="URL" sortable style="min-width: 300px">
          <template #body="{ data }">
            <span :class="getUrlClass(data)">{{ data.url }}</span>
          </template>
        </Column>

        <Column field="method" header="Method" sortable style="width: 100px">
          <template #body="{ data }">
            <Tag
              v-if="data.method"
              :value="data.method"
              :severity="getMethodSeverity(data.method)"
            />
            <span v-else class="text-secondary">-</span>
          </template>
        </Column>

        <Column field="host" header="Host" sortable style="width: 200px">
          <template #body="{ data }">
            <span class="host-text">{{ data.host }}</span>
          </template>
        </Column>

        <Column field="source_file" header="Source File" sortable style="width: 200px">
          <template #body="{ data }">
            <span v-if="data.source_file" class="source-file">{{ truncatePath(data.source_file) }}</span>
            <span v-else class="text-secondary">-</span>
          </template>
        </Column>

        <Column field="is_https" header="HTTPS" sortable style="width: 80px; text-align: center">
          <template #body="{ data }">
            <i
              :class="data.is_https ? 'pi pi-lock' : 'pi pi-lock-open'"
              :style="{ color: data.is_https ? 'var(--green-500)' : 'var(--red-500)', fontSize: '1.1rem' }"
            ></i>
          </template>
        </Column>

        <Column field="security_issues" header="Security Issues" style="width: 200px">
          <template #body="{ data }">
            <div v-if="data.security_issues && data.security_issues.length > 0" class="issues-cell">
              <Tag
                v-for="issue in data.security_issues"
                :key="issue"
                :value="formatIssue(issue)"
                :severity="getIssueSeverity(issue)"
                class="issue-tag"
              />
            </div>
            <span v-else class="text-secondary">None</span>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- Probe Hidden Endpoints Dialog -->
    <Dialog
      v-model:visible="showProbeDialog"
      header="Probe Hidden Endpoints"
      :modal="true"
      :style="{ width: '650px' }"
    >
      <div class="probe-dialog-content">
        <p class="probe-description">
          Enter base URLs to probe for common hidden endpoints (admin panels, debug interfaces, API docs, etc.).
        </p>
        <div class="probe-input-section">
          <label for="probe-urls">Base URLs (one per line):</label>
          <textarea
            id="probe-urls"
            v-model="probeUrlsText"
            placeholder="https://api.example.com&#10;https://app.example.com"
            rows="5"
            class="probe-textarea"
          ></textarea>
        </div>

        <div class="probe-paths-info">
          <h4>Paths to probe:</h4>
          <div class="paths-list">
            <Tag v-for="path in probePaths" :key="path" :value="path" severity="secondary" class="path-tag" />
          </div>
        </div>

        <div v-if="probeResults.length > 0" class="probe-results">
          <h4>Probe Results ({{ probeRespondingCount }} responding):</h4>
          <DataTable :value="probeResults" :paginator="false" responsiveLayout="scroll" class="probe-results-table">
            <Column field="url" header="URL" style="min-width: 250px">
              <template #body="{ data }">
                <span :class="getProbeUrlClass(data)">{{ data.url }}</span>
              </template>
            </Column>
            <Column field="status_code" header="Status" style="width: 100px">
              <template #body="{ data }">
                <Tag
                  v-if="data.status_code > 0"
                  :value="String(data.status_code)"
                  :severity="getStatusSeverity(data.status_code)"
                />
                <Tag v-else value="Error" severity="secondary" />
              </template>
            </Column>
            <Column field="response_size" header="Size" style="width: 100px">
              <template #body="{ data }">
                <span>{{ data.response_size > 0 ? formatBytes(data.response_size) : '-' }}</span>
              </template>
            </Column>
          </DataTable>
        </div>
      </div>

      <template #footer>
        <Button label="Cancel" icon="pi pi-times" class="p-button-text" @click="showProbeDialog = false" />
        <Button
          label="Probe"
          icon="pi pi-search"
          :loading="probing"
          @click="runProbe"
          :disabled="!probeUrlsText.trim()"
        />
      </template>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
/**
 * APIEndpointsView - Discovered API endpoint browser with security analysis and export.
 *
 * Features:
 * - Per-app endpoint listing with host, method, HTTPS status, and security issues
 * - Summary cards for total endpoints, unique hosts, insecure (HTTP) count, and security issues
 * - Filterable by host, HTTP method, and issue type
 * - Multi-format export: Burp Suite XML, OpenAPI 3.0, Postman Collection, CSV
 * - Hidden endpoint probing dialog for common admin/debug/API doc paths
 * - Probe results table with status codes and response sizes
 *
 * @requires apiEndpointsApi - list, export, and probe endpoints per application
 * @requires appsApi - provides the application list for selection
 */
import { ref, computed, onMounted } from 'vue'
import { appsApi, apiEndpointsApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import SplitButton from 'primevue/splitbutton'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import Dialog from 'primevue/dialog'
import Toast from 'primevue/toast'

const toast = useToast()

// State
const loading = ref(false)
const loadingApps = ref(false)
const apps = ref<any[]>([])
const selectedApp = ref<string | null>(null)
const endpoints = ref<any[]>([])
const stats = ref({
  total: 0,
  uniqueHosts: 0,
  insecureCount: 0,
  securityIssuesCount: 0,
})

// Filters
const filterHost = ref<string | null>(null)
const filterMethod = ref<string | null>(null)
const filterIssueType = ref<string | null>(null)

// Probe dialog
const showProbeDialog = ref(false)
const probeUrlsText = ref('')
const probing = ref(false)
const probeResults = ref<any[]>([])
const probePaths = [
  '/admin', '/debug', '/actuator', '/graphql', '/swagger.json',
  '/swagger-ui', '/.env', '/wp-admin', '/api/v1/docs', '/health',
  '/metrics', '/trace', '/info',
]

// Computed
const availableHosts = computed(() => {
  const hosts = new Set(endpoints.value.map((ep: any) => ep.host))
  return Array.from(hosts).sort()
})

const availableMethods = computed(() => {
  const methods = new Set(
    endpoints.value
      .filter((ep: any) => ep.method)
      .map((ep: any) => ep.method)
  )
  return Array.from(methods).sort()
})

const availableIssueTypes = computed(() => {
  const issues = new Set<string>()
  endpoints.value.forEach((ep: any) => {
    if (ep.security_issues) {
      ep.security_issues.forEach((issue: string) => issues.add(issue))
    }
  })
  return Array.from(issues).sort()
})

const filteredEndpoints = computed(() => {
  return endpoints.value.filter((ep: any) => {
    if (filterHost.value && ep.host !== filterHost.value) return false
    if (filterMethod.value && ep.method !== filterMethod.value) return false
    if (filterIssueType.value) {
      if (!ep.security_issues || !ep.security_issues.includes(filterIssueType.value)) return false
    }
    return true
  })
})

const probeRespondingCount = computed(() => {
  return probeResults.value.filter((r: any) => r.status_code > 0).length
})

// Export menu options
const exportOptions = [
  {
    label: 'Burp Suite XML',
    icon: 'pi pi-server',
    command: () => exportEndpoints('burp'),
  },
  {
    label: 'OpenAPI 3.0',
    icon: 'pi pi-file',
    command: () => exportEndpoints('openapi'),
  },
  {
    label: 'Postman Collection',
    icon: 'pi pi-send',
    command: () => exportEndpoints('postman'),
  },
  {
    label: 'CSV',
    icon: 'pi pi-table',
    command: () => exportEndpoints('csv'),
  },
]

// Methods
function getUrlClass(data: any) {
  const classes = ['url-text']
  if (!data.is_https) classes.push('url-insecure')
  if (data.security_issues?.includes('debug_endpoint')) classes.push('url-debug')
  if (data.security_issues?.includes('admin_endpoint')) classes.push('url-admin')
  return classes.join(' ')
}

function getMethodSeverity(method: string) {
  switch (method?.toUpperCase()) {
    case 'GET': return 'info'
    case 'POST': return 'success'
    case 'PUT': return 'warning'
    case 'PATCH': return 'warning'
    case 'DELETE': return 'danger'
    default: return 'secondary'
  }
}

function getIssueSeverity(issue: string) {
  switch (issue) {
    case 'insecure_transport': return 'danger'
    case 'debug_endpoint': return 'warning'
    case 'admin_endpoint': return 'warning'
    case 'swagger_exposed': return 'info'
    case 'graphql_introspection': return 'warning'
    case 'actuator': return 'warning'
    default: return 'secondary'
  }
}

function formatIssue(issue: string) {
  return issue.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())
}

function truncatePath(path: string) {
  if (!path) return ''
  if (path.length > 35) return '...' + path.slice(-32)
  return path
}

function getStatusSeverity(status: number) {
  if (status >= 200 && status < 300) return 'success'
  if (status >= 300 && status < 400) return 'info'
  if (status >= 400 && status < 500) return 'warning'
  return 'danger'
}

function getProbeUrlClass(data: any) {
  if (data.status_code >= 200 && data.status_code < 300) return 'probe-url-found'
  if (data.status_code >= 300 && data.status_code < 400) return 'probe-url-redirect'
  return 'probe-url-default'
}

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i]
}

async function loadApps() {
  loadingApps.value = true
  try {
    const response = await appsApi.list()
    apps.value = response.data.items || response.data || []
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load applications', life: 3000 })
  } finally {
    loadingApps.value = false
  }
}

async function onAppSelected() {
  if (!selectedApp.value) {
    endpoints.value = []
    return
  }
  await loadEndpoints()
}

async function loadEndpoints() {
  if (!selectedApp.value) return
  loading.value = true
  try {
    const response = await apiEndpointsApi.list(selectedApp.value)
    const data = response.data
    endpoints.value = data.endpoints || []
    stats.value = {
      total: data.total || 0,
      uniqueHosts: data.unique_hosts || 0,
      insecureCount: data.insecure_count || 0,
      securityIssuesCount: data.security_issues_count || 0,
    }
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load API endpoints', life: 3000 })
  } finally {
    loading.value = false
  }
}

function applyFilters() {
  // Filters are reactive through computed property, no explicit action needed
}

async function exportEndpoints(format: string) {
  if (!selectedApp.value) return
  try {
    const response = await apiEndpointsApi.exportEndpoints(selectedApp.value, format)
    const blob = new Blob([response.data])
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url

    const extensions: Record<string, string> = {
      burp: 'xml',
      openapi: 'json',
      postman: 'json',
      csv: 'csv',
    }
    link.download = `api_endpoints_${selectedApp.value}.${extensions[format] || 'txt'}`
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
    window.URL.revokeObjectURL(url)

    toast.add({ severity: 'success', summary: 'Exported', detail: `Endpoints exported as ${format.toUpperCase()}`, life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to export endpoints', life: 3000 })
  }
}

async function runProbe() {
  if (!selectedApp.value || !probeUrlsText.value.trim()) return

  probing.value = true
  probeResults.value = []

  const baseUrls = probeUrlsText.value
    .split('\n')
    .map((u: string) => u.trim())
    .filter((u: string) => u.length > 0)

  try {
    const response = await apiEndpointsApi.probe(selectedApp.value, baseUrls)
    probeResults.value = response.data.results || []
    toast.add({
      severity: 'info',
      summary: 'Probe Complete',
      detail: `${response.data.responding_count} of ${response.data.probed_count} paths responded`,
      life: 3000,
    })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Probe failed', life: 3000 })
  } finally {
    probing.value = false
  }
}

onMounted(async () => {
  await loadApps()
})
</script>

<style scoped>
.api-endpoints-view {
  padding: 1rem;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
  flex-wrap: wrap;
  gap: 1rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.75rem;
}

.text-secondary {
  color: var(--text-color-secondary);
  margin-top: 0.25rem;
}

.header-actions {
  display: flex;
  gap: 0.75rem;
  align-items: center;
}

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  margin-bottom: 1rem;
}

.app-selector-card {
  padding: 1rem 1.25rem;
}

.selector-row {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.selector-row label {
  font-weight: 500;
  white-space: nowrap;
}

.app-dropdown {
  min-width: 350px;
}

/* Summary Cards */
.summary-grid {
  margin-bottom: 1rem;
}

.summary-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1.25rem;
  border-radius: 8px;
  color: white;
}

.summary-card .count {
  font-size: 2rem;
  font-weight: 700;
}

.summary-card .label {
  font-size: 0.85rem;
  opacity: 0.9;
}

.summary-card.total {
  background: linear-gradient(135deg, #6366f1, #4f46e5);
}

.summary-card.hosts {
  background: linear-gradient(135deg, #3b82f6, #2563eb);
}

.summary-card.insecure {
  background: linear-gradient(135deg, #ef4444, #dc2626);
}

.summary-card.issues {
  background: linear-gradient(135deg, #f59e0b, #d97706);
  color: #1a1a2e;
}

/* Filters */
.filters-card {
  padding: 1rem;
}

.filters-row {
  display: flex;
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: center;
}

/* URL styling */
.url-text {
  font-family: monospace;
  font-size: 0.85rem;
  word-break: break-all;
}

.url-insecure {
  color: var(--red-500);
}

.url-debug {
  color: var(--orange-500);
}

.url-admin {
  color: var(--yellow-600);
}

.host-text {
  font-family: monospace;
  font-size: 0.85rem;
}

.source-file {
  font-family: monospace;
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.issues-cell {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.issue-tag {
  font-size: 0.75rem;
}

/* Empty state */
.empty-state {
  text-align: center;
  padding: 3rem 1rem;
  color: var(--text-color-secondary);
}

.empty-state i {
  font-size: 3rem;
  margin-bottom: 1rem;
  opacity: 0.5;
}

.empty-state p {
  margin: 0;
  font-size: 1rem;
}

/* Probe dialog */
.probe-dialog-content {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.probe-description {
  color: var(--text-color-secondary);
  margin: 0;
}

.probe-input-section {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.probe-input-section label {
  font-weight: 500;
}

.probe-textarea {
  width: 100%;
  padding: 0.75rem;
  border: 1px solid var(--surface-border);
  border-radius: 6px;
  background: var(--surface-ground);
  color: var(--text-color);
  font-family: monospace;
  font-size: 0.9rem;
  resize: vertical;
}

.probe-textarea:focus {
  outline: none;
  border-color: var(--primary-color);
  box-shadow: 0 0 0 2px rgba(99, 102, 241, 0.2);
}

.probe-paths-info h4 {
  margin: 0 0 0.5rem;
  font-size: 0.9rem;
}

.paths-list {
  display: flex;
  flex-wrap: wrap;
  gap: 0.375rem;
}

.path-tag {
  font-family: monospace;
  font-size: 0.8rem;
}

.probe-results h4 {
  margin: 0 0 0.5rem;
  font-size: 0.9rem;
}

.probe-url-found {
  font-family: monospace;
  font-size: 0.85rem;
  color: var(--green-500);
}

.probe-url-redirect {
  font-family: monospace;
  font-size: 0.85rem;
  color: var(--blue-500);
}

.probe-url-default {
  font-family: monospace;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

/* Responsive */
@media (max-width: 768px) {
  .page-header {
    flex-direction: column;
  }

  .header-actions {
    width: 100%;
    flex-wrap: wrap;
  }

  .selector-row {
    flex-direction: column;
    align-items: flex-start;
  }

  .app-dropdown {
    min-width: 100%;
  }

  .filters-row {
    flex-direction: column;
  }

  .filters-row > * {
    width: 100%;
  }
}
</style>
