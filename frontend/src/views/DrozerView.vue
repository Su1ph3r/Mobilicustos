<template>
  <div class="drozer-view">
    <div class="page-header">
      <div>
        <h1>Drozer Console</h1>
        <p class="text-secondary">Dynamic Android security testing with Drozer</p>
      </div>
      <div class="header-actions">
        <Tag v-if="drozerStatus.installed" value="Drozer Available" severity="success" />
        <Tag v-else value="Drozer Not Installed" severity="danger" />
      </div>
    </div>

    <div class="drozer-container">
      <!-- Left Panel: Session Management -->
      <div class="panel session-panel">
        <div class="panel-header">
          <h3>Session</h3>
        </div>

        <!-- New Session Form -->
        <div class="session-form card">
          <div class="field">
            <label>Device</label>
            <Dropdown
              v-model="selectedDevice"
              :options="androidDevices"
              optionLabel="device_name"
              optionValue="device_id"
              placeholder="Select Android Device"
              :disabled="!!activeSession"
            />
          </div>
          <div class="field">
            <label>Package Name</label>
            <InputText
              v-model="packageName"
              placeholder="com.example.app"
              :disabled="!!activeSession"
            />
          </div>
          <div class="session-actions">
            <Button
              v-if="!activeSession"
              label="Start Session"
              icon="pi pi-play"
              @click="startSession"
              :loading="startingSession"
              :disabled="!selectedDevice || !packageName"
            />
            <Button
              v-else
              label="Stop Session"
              icon="pi pi-stop"
              class="p-button-danger"
              @click="stopSession"
              :loading="stoppingSession"
            />
          </div>
        </div>

        <!-- Active Session Info -->
        <div v-if="activeSession" class="active-session card">
          <div class="session-info-item">
            <span class="label">Session ID</span>
            <span class="value">{{ activeSession.session_id?.slice(0, 8) }}...</span>
          </div>
          <div class="session-info-item">
            <span class="label">Package</span>
            <span class="value">{{ activeSession.package_name }}</span>
          </div>
          <div class="session-info-item">
            <span class="label">Status</span>
            <Tag :value="activeSession.status" :severity="activeSession.status === 'active' ? 'success' : 'secondary'" />
          </div>
        </div>

        <!-- Module Browser -->
        <div class="module-browser card">
          <h4>Modules</h4>
          <InputText
            v-model="moduleSearch"
            placeholder="Search modules..."
            class="module-search"
          />
          <div class="module-categories">
            <Accordion :multiple="true">
              <AccordionTab
                v-for="(modules, category) in filteredModules"
                :key="category"
                :header="formatCategory(category)"
              >
                <div class="module-list">
                  <div
                    v-for="module in modules"
                    :key="module.name"
                    class="module-item"
                    :class="{ selected: selectedModule?.name === module.name }"
                    @click="selectModule(module)"
                  >
                    <span class="module-name">{{ module.name }}</span>
                    <span class="module-desc">{{ module.description }}</span>
                  </div>
                </div>
              </AccordionTab>
            </Accordion>
          </div>
        </div>
      </div>

      <!-- Right Panel: Results & Quick Actions -->
      <div class="panel results-panel">
        <!-- Quick Actions -->
        <div class="quick-actions card">
          <h4>Quick Actions</h4>
          <div class="action-buttons">
            <Button
              label="Attack Surface"
              icon="pi pi-shield"
              class="p-button-sm"
              @click="quickAttackSurface"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'attack-surface'"
            />
            <Button
              label="Enumerate Providers"
              icon="pi pi-database"
              class="p-button-sm"
              @click="quickEnumerateProviders"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'providers'"
            />
            <Button
              label="Test SQL Injection"
              icon="pi pi-exclamation-triangle"
              class="p-button-sm p-button-warning"
              @click="quickTestSQLi"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'sqli'"
            />
            <Button
              label="Test Path Traversal"
              icon="pi pi-folder"
              class="p-button-sm p-button-warning"
              @click="quickTestTraversal"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'traversal'"
            />
          </div>
        </div>

        <!-- Selected Module -->
        <div v-if="selectedModule" class="selected-module card">
          <div class="module-header">
            <h4>{{ selectedModule.name }}</h4>
            <Button
              label="Run"
              icon="pi pi-play"
              class="p-button-sm"
              @click="runSelectedModule"
              :disabled="!activeSession"
              :loading="runningModule"
            />
          </div>
          <p class="module-description">{{ selectedModule.description }}</p>
          <div v-if="selectedModule.args?.length" class="module-args">
            <h5>Arguments</h5>
            <div v-for="arg in selectedModule.args" :key="arg.name" class="arg-field">
              <label>{{ arg.name }}</label>
              <InputText
                v-model="moduleArgs[arg.name]"
                :placeholder="arg.description || arg.name"
              />
            </div>
          </div>
        </div>

        <!-- Results Console -->
        <div class="results-console card">
          <div class="console-header">
            <h4>Results</h4>
            <Button
              icon="pi pi-trash"
              class="p-button-sm p-button-text"
              @click="clearResults"
              v-tooltip="'Clear Results'"
            />
          </div>
          <div ref="resultsContainer" class="console-output">
            <div v-for="(result, index) in results" :key="index" class="result-item">
              <div class="result-header">
                <span class="result-module">{{ result.module_name }}</span>
                <span class="result-time">{{ formatTime(result.executed_at) }}</span>
                <Tag
                  :value="result.result_type"
                  :severity="getResultSeverity(result.result_type)"
                  class="result-type"
                />
              </div>
              <div class="result-content">
                <pre v-if="result.raw_output">{{ result.raw_output }}</pre>
                <div v-else-if="result.result_data" class="result-data">
                  <div v-if="result.result_data.activities">
                    <strong>Activities ({{ result.result_data.activities.length }})</strong>
                    <ul>
                      <li v-for="a in result.result_data.activities?.slice(0, 10)" :key="a">{{ a }}</li>
                    </ul>
                  </div>
                  <div v-if="result.result_data.providers">
                    <strong>Content Providers ({{ result.result_data.providers.length }})</strong>
                    <ul>
                      <li v-for="p in result.result_data.providers?.slice(0, 10)" :key="p.authority">
                        {{ p.authority }} <Tag v-if="p.exported" value="exported" severity="warning" />
                      </li>
                    </ul>
                  </div>
                  <div v-if="result.result_data.vulnerabilities">
                    <strong>Vulnerabilities Found</strong>
                    <ul>
                      <li v-for="v in result.result_data.vulnerabilities" :key="v.uri" class="vuln-item">
                        <span class="vuln-type">{{ v.type }}</span>: {{ v.uri }}
                      </li>
                    </ul>
                  </div>
                  <pre v-if="!hasStructuredData(result.result_data)">{{ JSON.stringify(result.result_data, null, 2) }}</pre>
                </div>
              </div>
            </div>
            <div v-if="results.length === 0" class="results-placeholder">
              Run a module or quick action to see results here...
            </div>
          </div>
        </div>
      </div>
    </div>

    <Toast />
  </div>
</template>

<script setup lang="ts">
/**
 * DrozerView - Drozer security assessment console for dynamic Android testing.
 *
 * Features:
 * - Session management targeting connected Android devices
 * - Searchable module browser with categorized accordion layout
 * - Module execution with configurable arguments
 * - Quick actions: attack surface analysis, provider enumeration, SQL injection and path traversal tests
 * - Results console with structured data display (activities, providers, vulnerabilities)
 * - Drozer installation status indicator
 *
 * @requires drozerApi - session CRUD, module execution, quick action endpoints, and status check
 * @requires useDevicesStore - provides connected Android device list
 */
import { ref, computed, onMounted, nextTick } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { drozerApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import Accordion from 'primevue/accordion'
import AccordionTab from 'primevue/accordiontab'
import Toast from 'primevue/toast'

interface DrozerModule {
  name: string
  description: string
  category: string
  args?: { name: string; description?: string }[]
}

interface DrozerResult {
  result_id?: string
  session_id?: string
  module_name: string
  module_args?: Record<string, string>
  result_type: string
  result_data?: Record<string, any>
  raw_output?: string
  executed_at: string
}

interface DrozerSession {
  session_id: string
  device_id: string
  package_name: string
  status: string
  drozer_port?: number
  started_at: string
}

const devicesStore = useDevicesStore()
const toast = useToast()

// State
const drozerStatus = ref({ installed: false })
const selectedDevice = ref<string | null>(null)
const packageName = ref('')
const activeSession = ref<DrozerSession | null>(null)
const modules = ref<Record<string, DrozerModule[]>>({})
const moduleSearch = ref('')
const selectedModule = ref<DrozerModule | null>(null)
const moduleArgs = ref<Record<string, string>>({})
const results = ref<DrozerResult[]>([])
const resultsContainer = ref<HTMLElement | null>(null)

// Loading states
const startingSession = ref(false)
const stoppingSession = ref(false)
const runningModule = ref(false)
const runningQuickAction = ref<string | null>(null)

// Computed
const androidDevices = computed(() =>
  devicesStore.devices.filter((d) => d.platform === 'android' && d.status === 'connected')
)

const filteredModules = computed(() => {
  if (!moduleSearch.value) return modules.value

  const search = moduleSearch.value.toLowerCase()
  const filtered: Record<string, DrozerModule[]> = {}

  for (const [category, mods] of Object.entries(modules.value)) {
    const matching = mods.filter(
      (m) =>
        m.name.toLowerCase().includes(search) ||
        m.description?.toLowerCase().includes(search)
    )
    if (matching.length > 0) {
      filtered[category] = matching
    }
  }

  return filtered
})

// Methods
function formatCategory(category: string): string {
  return category
    .split('.')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(' > ')
}

function selectModule(module: DrozerModule) {
  selectedModule.value = module
  moduleArgs.value = {}
}

function formatTime(dateStr: string): string {
  return new Date(dateStr).toLocaleTimeString()
}

function getResultSeverity(type: string): string {
  switch (type) {
    case 'finding':
    case 'vulnerability':
      return 'danger'
    case 'warning':
      return 'warning'
    case 'info':
      return 'info'
    case 'error':
      return 'danger'
    default:
      return 'secondary'
  }
}

function hasStructuredData(data: Record<string, any>): boolean {
  return !!(data.activities || data.providers || data.vulnerabilities)
}

function clearResults() {
  results.value = []
}

function addResult(result: DrozerResult) {
  results.value.unshift(result)
  nextTick(() => {
    if (resultsContainer.value) {
      resultsContainer.value.scrollTop = 0
    }
  })
}

async function startSession() {
  if (!selectedDevice.value || !packageName.value) return

  startingSession.value = true
  try {
    const response = await drozerApi.startSession({
      device_id: selectedDevice.value,
      package_name: packageName.value,
    })
    activeSession.value = response.data
    toast.add({ severity: 'success', summary: 'Session Started', detail: 'Drozer session is active', life: 2000 })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Failed to Start Session',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    startingSession.value = false
  }
}

async function stopSession() {
  if (!activeSession.value) return

  stoppingSession.value = true
  try {
    await drozerApi.stopSession(activeSession.value.session_id)
    activeSession.value = null
    toast.add({ severity: 'info', summary: 'Session Stopped', life: 2000 })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Failed to Stop Session',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    stoppingSession.value = false
  }
}

async function runSelectedModule() {
  if (!activeSession.value || !selectedModule.value) return

  runningModule.value = true
  try {
    const response = await drozerApi.runModule(activeSession.value.session_id, {
      module_name: selectedModule.value.name,
      args: moduleArgs.value,
    })
    addResult(response.data)
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Module Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningModule.value = false
  }
}

async function quickAttackSurface() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'attack-surface'
  try {
    const response = await drozerApi.quickAttackSurface(selectedDevice.value, packageName.value)
    addResult({
      module_name: 'app.package.attacksurface',
      result_type: 'info',
      result_data: response.data,
      executed_at: new Date().toISOString(),
    })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Attack Surface Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function quickEnumerateProviders() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'providers'
  try {
    const response = await drozerApi.quickEnumerateProviders(selectedDevice.value, packageName.value)
    addResult({
      module_name: 'app.provider.info',
      result_type: 'info',
      result_data: response.data,
      executed_at: new Date().toISOString(),
    })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Enumerate Providers Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function quickTestSQLi() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'sqli'
  try {
    const response = await drozerApi.quickTestSQLi(selectedDevice.value, packageName.value)
    const resultType = response.data.vulnerabilities?.length > 0 ? 'finding' : 'info'
    addResult({
      module_name: 'scanner.provider.injection',
      result_type: resultType,
      result_data: response.data,
      executed_at: new Date().toISOString(),
    })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'SQL Injection Test Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function quickTestTraversal() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'traversal'
  try {
    const response = await drozerApi.quickTestTraversal(selectedDevice.value, packageName.value)
    const resultType = response.data.vulnerabilities?.length > 0 ? 'finding' : 'info'
    addResult({
      module_name: 'scanner.provider.traversal',
      result_type: resultType,
      result_data: response.data,
      executed_at: new Date().toISOString(),
    })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Path Traversal Test Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function loadDrozerStatus() {
  try {
    const response = await drozerApi.getStatus()
    drozerStatus.value = response.data
  } catch (e) {
    console.error('Failed to check Drozer status:', e)
  }
}

async function loadModules() {
  try {
    const response = await drozerApi.listModules()
    modules.value = response.data.modules || {}
  } catch (e) {
    console.error('Failed to load modules:', e)
  }
}

async function loadActiveSessions() {
  try {
    const response = await drozerApi.listSessions({ status: 'active' })
    const sessions = response.data.items || []
    if (sessions.length > 0) {
      activeSession.value = sessions[0]
      selectedDevice.value = sessions[0].device_id
      packageName.value = sessions[0].package_name
    }
  } catch (e) {
    console.error('Failed to load sessions:', e)
  }
}

onMounted(async () => {
  await Promise.all([
    devicesStore.fetchDevices(),
    loadDrozerStatus(),
    loadModules(),
    loadActiveSessions(),
  ])
})
</script>

<style scoped>
.drozer-view {
  padding: 1rem;
  height: calc(100vh - 80px);
  display: flex;
  flex-direction: column;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.75rem;
}

.text-secondary {
  color: var(--text-color-secondary);
  margin-top: 0.25rem;
}

.drozer-container {
  display: grid;
  grid-template-columns: 380px 1fr;
  gap: 1rem;
  flex: 1;
  min-height: 0;
}

.panel {
  display: flex;
  flex-direction: column;
  background: var(--surface-card);
  border-radius: 8px;
  overflow: hidden;
}

.panel-header {
  padding: 1rem;
  border-bottom: 1px solid var(--surface-border);
}

.panel-header h3 {
  margin: 0;
}

.card {
  background: var(--surface-ground);
  border-radius: 8px;
  padding: 1rem;
  margin: 1rem;
}

.field {
  margin-bottom: 1rem;
}

.field label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.field .p-dropdown,
.field .p-inputtext {
  width: 100%;
}

.session-actions {
  display: flex;
  gap: 0.5rem;
}

.active-session {
  background: var(--surface-ground);
}

.session-info-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--surface-border);
}

.session-info-item:last-child {
  border-bottom: none;
}

.session-info-item .label {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.session-info-item .value {
  font-family: monospace;
}

.module-browser {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.module-browser h4 {
  margin: 0 0 0.75rem;
}

.module-search {
  width: 100%;
  margin-bottom: 0.75rem;
}

.module-categories {
  flex: 1;
  overflow-y: auto;
}

.module-list {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.module-item {
  padding: 0.5rem;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.module-item:hover {
  background: var(--surface-hover);
}

.module-item.selected {
  background: var(--primary-color);
  color: white;
}

.module-name {
  display: block;
  font-size: 0.85rem;
  font-weight: 600;
}

.module-desc {
  display: block;
  font-size: 0.75rem;
  color: var(--text-color-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.module-item.selected .module-desc {
  color: rgba(255, 255, 255, 0.8);
}

.quick-actions h4 {
  margin: 0 0 0.75rem;
}

.action-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.selected-module {
  background: var(--surface-ground);
}

.selected-module .module-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.selected-module h4 {
  margin: 0;
  font-family: monospace;
}

.module-description {
  margin: 0.5rem 0;
  font-size: 0.9rem;
  color: var(--text-color-secondary);
}

.module-args h5 {
  margin: 0.75rem 0 0.5rem;
  font-size: 0.85rem;
}

.arg-field {
  margin-bottom: 0.5rem;
}

.arg-field label {
  display: block;
  font-size: 0.8rem;
  margin-bottom: 0.25rem;
  color: var(--text-color-secondary);
}

.arg-field .p-inputtext {
  width: 100%;
}

.results-console {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-height: 300px;
}

.console-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.75rem;
}

.console-header h4 {
  margin: 0;
}

.console-output {
  flex: 1;
  background: #1e1e1e;
  border-radius: 4px;
  padding: 1rem;
  overflow-y: auto;
  font-family: monospace;
  font-size: 0.85rem;
  color: #d4d4d4;
}

.result-item {
  margin-bottom: 1rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid #333;
}

.result-item:last-child {
  border-bottom: none;
}

.result-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.result-module {
  color: #569cd6;
  font-weight: 600;
}

.result-time {
  color: #6a9955;
  font-size: 0.8rem;
}

.result-content pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
}

.result-data ul {
  margin: 0.5rem 0;
  padding-left: 1.5rem;
}

.result-data li {
  margin-bottom: 0.25rem;
}

.vuln-item {
  color: #f48771;
}

.vuln-type {
  font-weight: 600;
  text-transform: uppercase;
}

.results-placeholder {
  color: #6a6a6a;
  font-style: italic;
}

@media (max-width: 992px) {
  .drozer-container {
    grid-template-columns: 1fr;
  }
}
</style>
