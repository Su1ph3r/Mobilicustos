<template>
  <div class="burp-view">
    <div class="header">
      <h1>
        <i class="pi pi-globe mr-2"></i>
        Burp Suite Pro Integration
      </h1>
      <Button
        label="Add Connection"
        icon="pi pi-plus"
        @click="showConnectionDialog = true"
      />
    </div>

    <!-- Connections Section -->
    <Card class="mb-4">
      <template #title>
        <div class="section-title">
          <span>Connections</span>
          <Tag :value="`${connections.length} configured`" severity="info" />
        </div>
      </template>
      <template #content>
        <div v-if="connections.length === 0" class="empty-state">
          <i class="pi pi-link-slash"></i>
          <p>No Burp Suite connections configured</p>
          <Button
            label="Add Connection"
            icon="pi pi-plus"
            @click="showConnectionDialog = true"
          />
        </div>

        <div v-else class="connections-grid">
          <Card
            v-for="conn in connections"
            :key="conn.connection_id"
            class="connection-card"
            :class="{ 'selected': selectedConnection?.connection_id === conn.connection_id }"
            @click="selectConnection(conn)"
          >
            <template #content>
              <div class="connection-info">
                <div class="connection-header">
                  <span class="connection-name">{{ conn.name }}</span>
                  <Tag
                    :value="conn.status || 'Unknown'"
                    :severity="conn.status === 'connected' ? 'success' : 'warning'"
                  />
                </div>
                <div class="connection-details">
                  <code>{{ conn.api_url }}</code>
                  <span v-if="conn.burp_version" class="version">
                    v{{ conn.burp_version }}
                  </span>
                </div>
                <div class="connection-actions">
                  <Button
                    icon="pi pi-refresh"
                    class="p-button-sm p-button-text"
                    v-tooltip.top="'Test Connection'"
                    @click.stop="testConnection(conn)"
                    :loading="testingConnectionId === conn.connection_id"
                  />
                  <Button
                    icon="pi pi-trash"
                    class="p-button-sm p-button-danger p-button-text"
                    v-tooltip.top="'Delete'"
                    @click.stop="confirmDeleteConnection(conn)"
                  />
                </div>
              </div>
            </template>
          </Card>
        </div>
      </template>
    </Card>

    <!-- Scan Management -->
    <div v-if="selectedConnection" class="scan-section">
      <TabView>
        <TabPanel value="0" header="Start Scan">
          <Card>
            <template #content>
              <div class="scan-form">
                <div class="form-field">
                  <label>Target URLs</label>
                  <Textarea
                    v-model="scanForm.targetUrls"
                    placeholder="Enter URLs to scan (one per line)&#10;https://example.com&#10;https://api.example.com"
                    rows="4"
                    class="w-full"
                  />
                </div>

                <div class="form-row">
                  <div class="form-field">
                    <label>Associated App (optional)</label>
                    <Dropdown
                      v-model="scanForm.app_id"
                      :options="apps"
                      optionLabel="app_name"
                      optionValue="app_id"
                      placeholder="Link to app..."
                      class="w-full"
                      showClear
                    />
                  </div>

                  <div class="form-field">
                    <label>Scan Configuration</label>
                    <Dropdown
                      v-model="scanForm.scan_config"
                      :options="scanConfigs"
                      optionLabel="name"
                      optionValue="name"
                      placeholder="Default"
                      class="w-full"
                      showClear
                    />
                  </div>
                </div>

                <Button
                  label="Start Scan"
                  icon="pi pi-play"
                  @click="startScan"
                  :loading="startingScan"
                />
              </div>
            </template>
          </Card>
        </TabPanel>

        <TabPanel value="1" header="Active Scans">
          <DataTable
            :value="activeScans"
            :loading="loadingScans"
            responsiveLayout="scroll"
          >
            <Column field="task_id" header="Task ID">
              <template #body="{ data }">
                <code>{{ data.task_id.substring(0, 8) }}...</code>
              </template>
            </Column>

            <Column field="target_urls" header="Targets">
              <template #body="{ data }">
                <span>{{ data.target_urls?.length || 0 }} URL(s)</span>
              </template>
            </Column>

            <Column field="status" header="Status">
              <template #body="{ data }">
                <Tag
                  :value="data.status"
                  :severity="getStatusSeverity(data.status)"
                />
              </template>
            </Column>

            <Column field="percent_complete" header="Progress">
              <template #body="{ data }">
                <ProgressBar
                  :value="data.percent_complete || 0"
                  :showValue="true"
                  style="height: 20px"
                />
              </template>
            </Column>

            <Column field="issues_count" header="Issues">
              <template #body="{ data }">
                {{ data.issues_count || 0 }}
              </template>
            </Column>

            <Column header="Actions" style="width: 150px">
              <template #body="{ data }">
                <Button
                  icon="pi pi-refresh"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="'Refresh'"
                  @click="refreshScanStatus(data)"
                />
                <Button
                  icon="pi pi-download"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="'Import Issues'"
                  @click="importIssues(data)"
                  :disabled="data.status !== 'completed'"
                />
                <Button
                  icon="pi pi-stop"
                  class="p-button-sm p-button-danger p-button-text"
                  v-tooltip.top="'Stop'"
                  @click="stopScan(data)"
                  :disabled="data.status !== 'running'"
                />
              </template>
            </Column>

            <template #empty>
              <div class="text-center p-4">No active scans</div>
            </template>
          </DataTable>
        </TabPanel>

        <TabPanel value="2" header="Proxy History">
          <div class="proxy-controls mb-3">
            <Button
              label="Fetch History"
              icon="pi pi-refresh"
              @click="fetchProxyHistory"
              :loading="loadingProxy"
            />
            <Button
              label="Import Selected"
              icon="pi pi-download"
              class="ml-2"
              @click="importProxyHistory"
              :disabled="selectedProxyItems.length === 0"
            />
          </div>

          <DataTable
            :value="proxyHistory"
            :loading="loadingProxy"
            v-model:selection="selectedProxyItems"
            responsiveLayout="scroll"
            :paginator="true"
            :rows="20"
          >
            <Column selectionMode="multiple" style="width: 3rem" />

            <Column field="method" header="Method" style="width: 80px">
              <template #body="{ data }">
                <Tag
                  :value="data.method"
                  :severity="getMethodSeverity(data.method)"
                />
              </template>
            </Column>

            <Column field="url" header="URL">
              <template #body="{ data }">
                <code class="url-code">{{ truncateUrl(data.url, 60) }}</code>
              </template>
            </Column>

            <Column field="status" header="Status" style="width: 80px">
              <template #body="{ data }">
                <span :class="getStatusClass(data.status)">
                  {{ data.status }}
                </span>
              </template>
            </Column>

            <Column field="length" header="Length" style="width: 100px">
              <template #body="{ data }">
                {{ formatBytes(data.length) }}
              </template>
            </Column>

            <Column field="mime_type" header="Type" style="width: 120px">
              <template #body="{ data }">
                <Tag :value="data.mime_type || '-'" severity="secondary" />
              </template>
            </Column>

            <template #empty>
              <div class="text-center p-4">
                No proxy history. Click "Fetch History" to load.
              </div>
            </template>
          </DataTable>
        </TabPanel>

        <TabPanel value="3" header="Imported Issues">
          <DataTable
            :value="burpIssues"
            :loading="loadingIssues"
            responsiveLayout="scroll"
            :paginator="true"
            :rows="20"
          >
            <Column field="name" header="Issue" sortable />

            <Column field="severity" header="Severity" style="width: 100px" sortable>
              <template #body="{ data }">
                <Tag
                  :value="data.severity"
                  :severity="getSeverityColor(data.severity)"
                />
              </template>
            </Column>

            <Column field="confidence" header="Confidence" style="width: 100px">
              <template #body="{ data }">
                <Tag :value="data.confidence" severity="secondary" />
              </template>
            </Column>

            <Column field="url" header="URL">
              <template #body="{ data }">
                <code class="url-code">{{ truncateUrl(data.url, 50) }}</code>
              </template>
            </Column>

            <Column field="finding_id" header="Finding" style="width: 100px">
              <template #body="{ data }">
                <Button
                  v-if="data.finding_id"
                  label="View"
                  class="p-button-sm p-button-link"
                  @click="viewFinding(data.finding_id)"
                />
                <span v-else class="text-gray-500">-</span>
              </template>
            </Column>

            <template #empty>
              <div class="text-center p-4">No imported issues</div>
            </template>
          </DataTable>
        </TabPanel>
      </TabView>
    </div>

    <div v-else class="select-prompt">
      <i class="pi pi-arrow-up"></i>
      <p>Select a Burp Suite connection above to manage scans</p>
    </div>

    <!-- Add Connection Dialog -->
    <Dialog
      v-model:visible="showConnectionDialog"
      header="Add Burp Suite Connection"
      :style="{ width: '500px' }"
      modal
    >
      <div class="form-grid">
        <div class="form-field">
          <label>Connection Name</label>
          <InputText
            v-model="connectionForm.name"
            placeholder="e.g., Local Burp"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>API URL</label>
          <InputText
            v-model="connectionForm.api_url"
            placeholder="http://localhost:1337"
            class="w-full"
          />
          <small class="text-gray-500">
            Burp Suite REST API endpoint
          </small>
        </div>

        <div class="form-field">
          <label>API Key</label>
          <Password
            v-model="connectionForm.api_key"
            :feedback="false"
            toggleMask
            class="w-full"
            placeholder="Enter Burp API key"
          />
          <small class="text-gray-500">
            Found in Burp: User options > Misc > REST API
          </small>
        </div>
      </div>

      <template #footer>
        <Button
          label="Cancel"
          class="p-button-text"
          @click="showConnectionDialog = false"
        />
        <Button
          label="Add Connection"
          :loading="savingConnection"
          @click="saveConnection"
        />
      </template>
    </Dialog>

    <!-- Import Issues Dialog -->
    <Dialog
      v-model:visible="showImportDialog"
      header="Import Issues"
      :style="{ width: '400px' }"
      modal
    >
      <p>Import issues from Burp scan into Mobilicustos?</p>

      <div class="form-field mt-3">
        <label>Link to App (optional)</label>
        <Dropdown
          v-model="importAppId"
          :options="apps"
          optionLabel="app_name"
          optionValue="app_id"
          placeholder="Select app..."
          class="w-full"
          showClear
        />
      </div>

      <template #footer>
        <Button
          label="Cancel"
          class="p-button-text"
          @click="showImportDialog = false"
        />
        <Button
          label="Import"
          :loading="importing"
          @click="doImport"
        />
      </template>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useToast } from 'primevue/usetoast'
import { burpApi, appsApi } from '@/services/api'

const router = useRouter()
const toast = useToast()

// State
const connections = ref<any[]>([])
const selectedConnection = ref<any>(null)
const apps = ref<any[]>([])
const scanConfigs = ref<any[]>([])
const activeScans = ref<any[]>([])
const proxyHistory = ref<any[]>([])
const selectedProxyItems = ref<any[]>([])
const burpIssues = ref<any[]>([])

const loading = ref(false)
const loadingScans = ref(false)
const loadingProxy = ref(false)
const loadingIssues = ref(false)
const savingConnection = ref(false)
const startingScan = ref(false)
const importing = ref(false)
const testingConnectionId = ref<string | null>(null)

const showConnectionDialog = ref(false)
const showImportDialog = ref(false)
const importTaskId = ref<string | null>(null)
const importAppId = ref<string | null>(null)

const connectionForm = ref({
  name: '',
  api_url: 'http://localhost:1337',
  api_key: '',
})

const scanForm = ref({
  targetUrls: '',
  app_id: null as string | null,
  scan_config: null as string | null,
})

// Methods
async function fetchConnections() {
  loading.value = true
  try {
    const response = await burpApi.listConnections()
    connections.value = response.items || []
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to load connections',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

async function fetchApps() {
  try {
    const response = await appsApi.list({ page: 1, page_size: 100 })
    apps.value = response.data?.apps || response.data?.items || []
  } catch (error) {
    console.error('Failed to load apps:', error)
  }
}

async function saveConnection() {
  if (!connectionForm.value.name || !connectionForm.value.api_url || !connectionForm.value.api_key) {
    toast.add({
      severity: 'warn',
      summary: 'Validation',
      detail: 'Please fill in all fields',
      life: 3000,
    })
    return
  }

  savingConnection.value = true
  try {
    await burpApi.createConnection(connectionForm.value)
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: 'Connection added',
      life: 3000,
    })
    showConnectionDialog.value = false
    connectionForm.value = { name: '', api_url: 'http://localhost:1337', api_key: '' }
    fetchConnections()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: error.response?.data?.detail || 'Failed to add connection',
      life: 3000,
    })
  } finally {
    savingConnection.value = false
  }
}

async function testConnection(conn: any) {
  testingConnectionId.value = conn.connection_id
  try {
    const result = await burpApi.testConnection(conn.connection_id)
    if (result.success) {
      toast.add({
        severity: 'success',
        summary: 'Connected',
        detail: `Burp ${result.burp_version}`,
        life: 3000,
      })
      conn.status = 'connected'
    } else {
      toast.add({
        severity: 'error',
        summary: 'Failed',
        detail: result.message,
        life: 3000,
      })
      conn.status = 'disconnected'
    }
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Connection test failed',
      life: 3000,
    })
  } finally {
    testingConnectionId.value = null
  }
}

function confirmDeleteConnection(conn: any) {
  // Simplified - could use confirm dialog
  if (confirm(`Delete connection "${conn.name}"?`)) {
    deleteConnection(conn)
  }
}

async function deleteConnection(conn: any) {
  try {
    await burpApi.deleteConnection(conn.connection_id)
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: 'Connection deleted',
      life: 3000,
    })
    if (selectedConnection.value?.connection_id === conn.connection_id) {
      selectedConnection.value = null
    }
    fetchConnections()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to delete connection',
      life: 3000,
    })
  }
}

function selectConnection(conn: any) {
  selectedConnection.value = conn
  fetchScanConfigs()
  fetchActiveScans()
  fetchBurpIssues()
}

async function fetchScanConfigs() {
  if (!selectedConnection.value) return
  try {
    const response = await burpApi.getScanConfigs(selectedConnection.value.connection_id)
    scanConfigs.value = response.configurations || []
  } catch (error) {
    console.error('Failed to load scan configs:', error)
  }
}

async function fetchActiveScans() {
  if (!selectedConnection.value) return
  loadingScans.value = true
  try {
    // This would need a list scans endpoint - for now just track locally
    // activeScans.value = ...
  } catch (error) {
    console.error('Failed to load scans:', error)
  } finally {
    loadingScans.value = false
  }
}

async function startScan() {
  if (!scanForm.value.targetUrls.trim()) {
    toast.add({
      severity: 'warn',
      summary: 'Validation',
      detail: 'Please enter at least one URL',
      life: 3000,
    })
    return
  }

  startingScan.value = true
  try {
    const urls = scanForm.value.targetUrls
      .split('\n')
      .map(u => u.trim())
      .filter(u => u.length > 0)

    const result = await burpApi.startScan(selectedConnection.value.connection_id, {
      target_urls: urls,
      app_id: scanForm.value.app_id || undefined,
      scan_config: scanForm.value.scan_config || undefined,
    })

    toast.add({
      severity: 'success',
      summary: 'Scan Started',
      detail: `Task ID: ${result.task_id}`,
      life: 3000,
    })

    activeScans.value.unshift(result)
    scanForm.value.targetUrls = ''
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: error.response?.data?.detail || 'Failed to start scan',
      life: 3000,
    })
  } finally {
    startingScan.value = false
  }
}

async function refreshScanStatus(scan: any) {
  try {
    const status = await burpApi.getScanStatus(scan.task_id)
    Object.assign(scan, status)
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to refresh status',
      life: 3000,
    })
  }
}

async function stopScan(scan: any) {
  try {
    await burpApi.stopScan(scan.task_id)
    scan.status = 'stopped'
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: 'Scan stopped',
      life: 3000,
    })
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to stop scan',
      life: 3000,
    })
  }
}

function importIssues(scan: any) {
  importTaskId.value = scan.task_id
  importAppId.value = scan.app_id
  showImportDialog.value = true
}

async function doImport() {
  if (!importTaskId.value) return

  importing.value = true
  try {
    const result = await burpApi.importIssues(importTaskId.value, importAppId.value || undefined)
    toast.add({
      severity: 'success',
      summary: 'Import Complete',
      detail: `Imported ${result.imported} issues`,
      life: 3000,
    })
    showImportDialog.value = false
    fetchBurpIssues()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to import issues',
      life: 3000,
    })
  } finally {
    importing.value = false
  }
}

async function fetchProxyHistory() {
  if (!selectedConnection.value) return
  loadingProxy.value = true
  try {
    const response = await burpApi.getProxyHistory(selectedConnection.value.connection_id)
    proxyHistory.value = response.items || []
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to fetch proxy history',
      life: 3000,
    })
  } finally {
    loadingProxy.value = false
  }
}

async function importProxyHistory() {
  if (selectedProxyItems.value.length === 0) return

  // Would need app selection dialog
  toast.add({
    severity: 'info',
    summary: 'Not Implemented',
    detail: 'Proxy history import coming soon',
    life: 3000,
  })
}

async function fetchBurpIssues() {
  loadingIssues.value = true
  try {
    const response = await burpApi.listIssues({ page: 1, page_size: 100 })
    burpIssues.value = response.items || []
  } catch (error) {
    console.error('Failed to load issues:', error)
  } finally {
    loadingIssues.value = false
  }
}

function viewFinding(findingId: string) {
  router.push(`/findings/${findingId}`).catch(() => {})
}

function getStatusSeverity(status: string) {
  const map: Record<string, string> = {
    running: 'info',
    completed: 'success',
    failed: 'danger',
    stopped: 'warning',
    queued: 'secondary',
  }
  return map[status] || 'secondary'
}

function getMethodSeverity(method: string) {
  const map: Record<string, string> = {
    GET: 'info',
    POST: 'success',
    PUT: 'warning',
    DELETE: 'danger',
    PATCH: 'warning',
  }
  return map[method] || 'secondary'
}

function getStatusClass(status: number) {
  if (status >= 200 && status < 300) return 'text-green-500'
  if (status >= 300 && status < 400) return 'text-blue-500'
  if (status >= 400 && status < 500) return 'text-orange-500'
  if (status >= 500) return 'text-red-500'
  return ''
}

function getSeverityColor(severity: string) {
  const map: Record<string, string> = {
    critical: 'danger',
    high: 'danger',
    medium: 'warning',
    low: 'info',
    info: 'secondary',
  }
  return map[severity] || 'secondary'
}

function truncateUrl(url: string, maxLen: number) {
  if (url.length > maxLen) return url.substring(0, maxLen - 3) + '...'
  return url
}

function formatBytes(bytes: number) {
  if (!bytes) return '-'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

onMounted(() => {
  fetchConnections()
  fetchApps()
})
</script>

<style scoped>
.burp-view {
  padding: 1.5rem;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}

.header h1 {
  margin: 0;
  font-size: 1.5rem;
  display: flex;
  align-items: center;
}

.section-title {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.empty-state {
  text-align: center;
  padding: 2rem;
  color: var(--text-color-secondary);
}

.empty-state i {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.connections-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
}

.connection-card {
  cursor: pointer;
  transition: all 0.2s;
  border: 2px solid transparent;
}

.connection-card:hover {
  border-color: var(--primary-color);
}

.connection-card.selected {
  border-color: var(--primary-color);
  background: var(--primary-color-text);
}

.connection-info {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.connection-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.connection-name {
  font-weight: 600;
}

.connection-details {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
  font-size: 0.875rem;
}

.connection-details code {
  background: var(--surface-ground);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.connection-details .version {
  color: var(--text-color-secondary);
}

.connection-actions {
  display: flex;
  gap: 0.25rem;
  margin-top: 0.5rem;
}

.scan-section {
  margin-top: 1.5rem;
}

.scan-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 1rem;
}

.form-field label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.form-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.proxy-controls {
  display: flex;
  align-items: center;
}

.url-code {
  font-size: 0.75rem;
  background: var(--surface-ground);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.select-prompt {
  text-align: center;
  padding: 3rem;
  color: var(--text-color-secondary);
}

.select-prompt i {
  font-size: 2rem;
  margin-bottom: 1rem;
  animation: bounce 2s infinite;
}

@keyframes bounce {
  0%, 20%, 50%, 80%, 100% { transform: translateY(0); }
  40% { transform: translateY(-10px); }
  60% { transform: translateY(-5px); }
}
</style>
