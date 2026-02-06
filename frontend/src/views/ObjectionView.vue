<template>
  <div class="objection-view">
    <div class="page-header">
      <div>
        <h1>Objection Console</h1>
        <p class="text-secondary">Runtime mobile app manipulation and exploration</p>
      </div>
      <div class="header-actions">
        <Tag v-if="objectionStatus.installed" value="Objection Available" severity="success" />
        <Tag v-else value="Objection Not Installed" severity="danger" />
      </div>
    </div>

    <div class="objection-container">
      <!-- Left Panel: Session & Commands -->
      <div class="panel session-panel">
        <div class="panel-header">
          <h3>Session</h3>
        </div>

        <!-- Session Form -->
        <div class="session-form card">
          <div class="field">
            <label>Device</label>
            <Dropdown
              v-model="selectedDevice"
              :options="connectedDevices"
              optionLabel="device_name"
              optionValue="device_id"
              placeholder="Select Device"
              :disabled="!!activeSession"
            >
              <template #option="{ option }">
                <div class="device-option">
                  <span>{{ option.device_name }}</span>
                  <Tag :value="option.platform" :severity="option.platform === 'ios' ? 'info' : 'success'" />
                </div>
              </template>
            </Dropdown>
          </div>
          <div class="field">
            <label>Package Name / Bundle ID</label>
            <InputText
              v-model="packageName"
              :placeholder="selectedPlatform === 'ios' ? 'com.example.app' : 'com.example.app'"
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

        <!-- Active Session -->
        <div v-if="activeSession" class="active-session card">
          <div class="session-info-item">
            <span class="label">Platform</span>
            <Tag :value="activeSession.platform" :severity="activeSession.platform === 'ios' ? 'info' : 'success'" />
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

        <!-- Quick Actions -->
        <div class="quick-actions card">
          <h4>Quick Actions</h4>
          <div class="action-buttons">
            <Button
              label="Disable SSL Pinning"
              icon="pi pi-lock-open"
              class="p-button-sm"
              @click="quickDisableSSL"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'ssl'"
            />
            <Button
              label="Disable Root Detection"
              icon="pi pi-shield"
              class="p-button-sm"
              @click="quickDisableRoot"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'root'"
            />
            <Button
              :label="selectedPlatform === 'ios' ? 'Dump Keychain' : 'Dump Keystore'"
              icon="pi pi-key"
              class="p-button-sm p-button-warning"
              @click="quickDumpKeychain"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'keychain'"
            />
            <Button
              label="List Modules"
              icon="pi pi-list"
              class="p-button-sm"
              @click="quickListModules"
              :disabled="!selectedDevice || !packageName"
              :loading="runningQuickAction === 'modules'"
            />
          </div>
        </div>

        <!-- Command Categories -->
        <div class="command-browser card">
          <h4>Commands</h4>
          <InputText
            v-model="commandSearch"
            placeholder="Search commands..."
            class="command-search"
          />
          <div class="command-categories">
            <Accordion :multiple="true">
              <AccordionTab
                v-for="(cmds, category) in filteredCommands"
                :key="category"
                :header="formatCategory(category)"
              >
                <div class="command-list">
                  <div
                    v-for="cmd in cmds"
                    :key="cmd.command"
                    class="command-item"
                    :class="{ selected: selectedCommand?.command === cmd.command }"
                    @click="selectCommand(cmd)"
                  >
                    <span class="command-name">{{ cmd.command }}</span>
                    <span class="command-desc">{{ cmd.description }}</span>
                  </div>
                </div>
              </AccordionTab>
            </Accordion>
          </div>
        </div>
      </div>

      <!-- Right Panel: File Browser & Output -->
      <div class="panel output-panel">
        <!-- Tabs -->
        <TabView v-model:activeIndex="activeTab">
          <!-- Terminal Tab -->
          <TabPanel value="0" header="Terminal">
            <div class="terminal-container">
              <div ref="terminalOutput" class="terminal-output">
                <div v-for="(line, index) in terminalLines" :key="index" :class="['terminal-line', line.type]">
                  <span v-if="line.type === 'input'" class="prompt">objection&gt; </span>
                  <span class="text">{{ line.text }}</span>
                </div>
              </div>
              <div class="terminal-input">
                <span class="prompt">objection&gt;</span>
                <InputText
                  v-model="commandInput"
                  placeholder="Enter command..."
                  @keyup.enter="executeCommand"
                  :disabled="!activeSession"
                />
                <Button
                  icon="pi pi-send"
                  class="p-button-sm"
                  @click="executeCommand"
                  :disabled="!activeSession || !commandInput"
                  :loading="executingCommand"
                />
              </div>
            </div>
          </TabPanel>

          <!-- File Browser Tab -->
          <TabPanel value="1" header="File Browser">
            <div class="file-browser">
              <div class="file-path-bar">
                <Button icon="pi pi-arrow-up" class="p-button-sm p-button-text" v-tooltip="'Navigate Up'" @click="navigateUp" :disabled="!activeSession" />
                <InputText v-model="currentPath" @keyup.enter="navigateToPath" :disabled="!activeSession" />
                <Button icon="pi pi-refresh" class="p-button-sm p-button-text" v-tooltip="'Refresh Files'" @click="refreshFiles" :disabled="!activeSession" :loading="loadingFiles" />
              </div>
              <div class="file-list">
                <div v-if="loadingFiles" class="loading-files">
                  <ProgressSpinner style="width: 30px; height: 30px" />
                </div>
                <div v-else-if="files.length === 0" class="empty-files">
                  No files found or session not active
                </div>
                <div
                  v-for="file in files"
                  :key="file.name"
                  class="file-item"
                  @click="handleFileClick(file)"
                  @dblclick="handleFileDoubleClick(file)"
                >
                  <i :class="getFileIcon(file)" />
                  <span class="file-name">{{ file.name }}</span>
                  <span v-if="file.size" class="file-size">{{ formatFileSize(file.size) }}</span>
                </div>
              </div>
            </div>
          </TabPanel>

          <!-- SQLite Tab -->
          <TabPanel value="2" header="SQLite">
            <div class="sqlite-explorer">
              <div class="sql-input-section">
                <div class="field">
                  <label>Database Path</label>
                  <InputText v-model="sqlDbPath" placeholder="/data/data/com.example/databases/app.db" :disabled="!activeSession" />
                </div>
                <div class="field">
                  <label>SQL Query</label>
                  <Textarea v-model="sqlQuery" rows="3" placeholder="SELECT * FROM table_name LIMIT 10" :disabled="!activeSession" />
                </div>
                <Button
                  label="Execute Query"
                  icon="pi pi-play"
                  @click="executeSqlQuery"
                  :disabled="!activeSession || !sqlDbPath || !sqlQuery"
                  :loading="executingSql"
                />
              </div>
              <div class="sql-results">
                <DataTable v-if="sqlResults.length > 0" :value="sqlResults" :paginator="true" :rows="10" responsiveLayout="scroll">
                  <Column v-for="col in sqlColumns" :key="col" :field="col" :header="col" />
                </DataTable>
                <div v-else class="sql-placeholder">
                  Execute a query to see results...
                </div>
              </div>
            </div>
          </TabPanel>

          <!-- Keychain/Keystore Tab -->
          <TabPanel value="3" :header="selectedPlatform === 'ios' ? 'Keychain' : 'Keystore'">
            <div class="keychain-view">
              <Button
                :label="selectedPlatform === 'ios' ? 'Dump Keychain' : 'Dump Keystore'"
                icon="pi pi-download"
                @click="quickDumpKeychain"
                :disabled="!activeSession"
                :loading="runningQuickAction === 'keychain'"
              />
              <div class="keychain-results">
                <DataTable v-if="keychainItems.length > 0" :value="keychainItems" :paginator="true" :rows="10" responsiveLayout="scroll">
                  <Column field="service" header="Service/Alias" />
                  <Column field="account" header="Account/Key" />
                  <Column field="data" header="Data">
                    <template #body="{ data }">
                      <span class="secret-data">{{ truncateSecret(data.data) }}</span>
                    </template>
                  </Column>
                </DataTable>
                <div v-else class="keychain-placeholder">
                  Click "Dump" to retrieve keychain/keystore contents...
                </div>
              </div>
            </div>
          </TabPanel>
        </TabView>
      </div>
    </div>

    <!-- File Viewer Dialog -->
    <Dialog
      v-model:visible="showFileViewer"
      :header="viewingFile?.name || 'File Viewer'"
      :modal="true"
      :style="{ width: '700px' }"
    >
      <div class="file-viewer">
        <pre v-if="fileContent">{{ fileContent }}</pre>
        <ProgressSpinner v-else-if="loadingFileContent" />
        <div v-else class="file-error">Failed to load file content</div>
      </div>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
/**
 * ObjectionView - Objection framework integration for runtime mobile app exploration.
 *
 * Features:
 * - Session management with device and package selection
 * - Interactive terminal with command input and color-coded output
 * - Quick actions: disable SSL pinning, disable root detection, dump keychain/keystore, list modules
 * - Platform-filtered command browser with searchable accordion categories
 * - File browser with directory navigation, file viewing dialog
 * - SQLite database explorer with query execution and results table
 * - Keychain/Keystore data dump and display
 *
 * @requires objectionApi - session CRUD, command execution, file/SQL operations, quick actions
 * @requires useDevicesStore - provides connected device list for session targeting
 */
import { ref, computed, onMounted, nextTick, watch } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { objectionApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import InputText from 'primevue/inputtext'
import Textarea from 'primevue/textarea'
import Tag from 'primevue/tag'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import Accordion from 'primevue/accordion'
import AccordionTab from 'primevue/accordiontab'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Dialog from 'primevue/dialog'
import ProgressSpinner from 'primevue/progressspinner'
import Toast from 'primevue/toast'

interface ObjectionCommand {
  command: string
  description: string
  category: string
  platform?: string
  args?: string[]
}

interface ObjectionSession {
  session_id: string
  device_id: string
  package_name: string
  platform: string
  status: string
  started_at: string
}

interface FileEntry {
  name: string
  type: 'file' | 'directory'
  size?: number
  permissions?: string
}

interface TerminalLine {
  text: string
  type: 'input' | 'output' | 'error' | 'success'
}

const devicesStore = useDevicesStore()
const toast = useToast()

// State
const objectionStatus = ref({ installed: false })
const selectedDevice = ref<string | null>(null)
const packageName = ref('')
const activeSession = ref<ObjectionSession | null>(null)
const commands = ref<Record<string, ObjectionCommand[]>>({})
const commandSearch = ref('')
const selectedCommand = ref<ObjectionCommand | null>(null)
const activeTab = ref(0)

// Terminal state
const terminalLines = ref<TerminalLine[]>([])
const terminalOutput = ref<HTMLElement | null>(null)
const commandInput = ref('')
const executingCommand = ref(false)

// File browser state
const currentPath = ref('/data/data')
const files = ref<FileEntry[]>([])
const loadingFiles = ref(false)
const showFileViewer = ref(false)
const viewingFile = ref<FileEntry | null>(null)
const fileContent = ref<string | null>(null)
const loadingFileContent = ref(false)

// SQLite state
const sqlDbPath = ref('')
const sqlQuery = ref('')
const sqlResults = ref<Record<string, any>[]>([])
const sqlColumns = ref<string[]>([])
const executingSql = ref(false)

// Keychain state
const keychainItems = ref<Record<string, any>[]>([])

// Loading states
const startingSession = ref(false)
const stoppingSession = ref(false)
const runningQuickAction = ref<string | null>(null)

// Computed
const connectedDevices = computed(() =>
  devicesStore.devices.filter((d) => d.status === 'connected')
)

const selectedPlatform = computed(() => {
  if (!selectedDevice.value) return 'android'
  const device = devicesStore.devices.find((d) => d.device_id === selectedDevice.value)
  return device?.platform || 'android'
})

const filteredCommands = computed(() => {
  let cmds = commands.value

  // Filter by platform
  const platform = selectedPlatform.value
  const filtered: Record<string, ObjectionCommand[]> = {}

  for (const [category, cmdList] of Object.entries(cmds)) {
    const matching = cmdList.filter((c) => {
      if (commandSearch.value) {
        const search = commandSearch.value.toLowerCase()
        if (!c.command.toLowerCase().includes(search) && !c.description?.toLowerCase().includes(search)) {
          return false
        }
      }
      if (c.platform && c.platform !== platform) {
        return false
      }
      return true
    })
    if (matching.length > 0) {
      filtered[category] = matching
    }
  }

  return filtered
})

// Watch for device changes
watch(selectedDevice, () => {
  // Update default path based on platform
  if (selectedPlatform.value === 'ios') {
    currentPath.value = '/var/mobile/Containers/Data/Application'
  } else {
    currentPath.value = '/data/data'
  }
})

// Methods
function formatCategory(category: string): string {
  return category
    .split('_')
    .map((s) => s.charAt(0).toUpperCase() + s.slice(1))
    .join(' ')
}

function selectCommand(cmd: ObjectionCommand) {
  selectedCommand.value = cmd
  commandInput.value = cmd.command
}

function addTerminalLine(text: string, type: TerminalLine['type'] = 'output') {
  terminalLines.value.push({ text, type })
  nextTick(() => {
    if (terminalOutput.value) {
      terminalOutput.value.scrollTop = terminalOutput.value.scrollHeight
    }
  })
}

function getFileIcon(file: FileEntry): string {
  if (file.type === 'directory') return 'pi pi-folder'
  const ext = file.name.split('.').pop()?.toLowerCase()
  switch (ext) {
    case 'db':
    case 'sqlite':
    case 'sqlite3':
      return 'pi pi-database'
    case 'plist':
    case 'xml':
    case 'json':
      return 'pi pi-file'
    default:
      return 'pi pi-file'
  }
}

function formatFileSize(size: number): string {
  if (size < 1024) return `${size} B`
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`
  return `${(size / (1024 * 1024)).toFixed(1)} MB`
}

function truncateSecret(data: string): string {
  if (!data) return '-'
  if (data.length > 50) return data.slice(0, 47) + '...'
  return data
}

async function startSession() {
  if (!selectedDevice.value || !packageName.value) return

  startingSession.value = true
  try {
    const response = await objectionApi.startSession({
      device_id: selectedDevice.value,
      package_name: packageName.value,
    })
    activeSession.value = response.data
    addTerminalLine('Session started successfully', 'success')
    toast.add({ severity: 'success', summary: 'Session Started', life: 2000 })
  } catch (e: any) {
    addTerminalLine(`Failed to start session: ${e.response?.data?.detail || 'Unknown error'}`, 'error')
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
    await objectionApi.stopSession(activeSession.value.session_id)
    activeSession.value = null
    addTerminalLine('Session stopped', 'output')
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

async function executeCommand() {
  if (!activeSession.value || !commandInput.value) return

  const cmd = commandInput.value
  addTerminalLine(cmd, 'input')
  commandInput.value = ''
  executingCommand.value = true

  try {
    const response = await objectionApi.executeCommand(activeSession.value.session_id, {
      command: cmd,
      args: [],
    })

    if (response.data.output) {
      addTerminalLine(response.data.output, 'output')
    }
    if (response.data.error) {
      addTerminalLine(response.data.error, 'error')
    }
  } catch (e: any) {
    addTerminalLine(`Error: ${e.response?.data?.detail || 'Command failed'}`, 'error')
  } finally {
    executingCommand.value = false
  }
}

async function quickDisableSSL() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'ssl'
  try {
    const response = await objectionApi.quickDisableSSL(selectedDevice.value, packageName.value)
    addTerminalLine('SSL pinning disabled successfully', 'success')
    toast.add({ severity: 'success', summary: 'SSL Pinning Disabled', life: 2000 })
  } catch (e: any) {
    addTerminalLine(`Failed to disable SSL pinning: ${e.response?.data?.detail}`, 'error')
    toast.add({
      severity: 'error',
      summary: 'Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function quickDisableRoot() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'root'
  try {
    const response = await objectionApi.quickDisableRoot(selectedDevice.value, packageName.value)
    addTerminalLine('Root/Jailbreak detection disabled successfully', 'success')
    toast.add({ severity: 'success', summary: 'Root Detection Disabled', life: 2000 })
  } catch (e: any) {
    addTerminalLine(`Failed to disable root detection: ${e.response?.data?.detail}`, 'error')
    toast.add({
      severity: 'error',
      summary: 'Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function quickDumpKeychain() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'keychain'
  try {
    const response = await objectionApi.quickDumpKeychain(selectedDevice.value, packageName.value)
    keychainItems.value = response.data.items || []
    activeTab.value = 3 // Switch to Keychain tab
    toast.add({ severity: 'success', summary: 'Keychain Dumped', life: 2000 })
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function quickListModules() {
  if (!selectedDevice.value || !packageName.value) return

  runningQuickAction.value = 'modules'
  try {
    const response = await objectionApi.quickListModules(selectedDevice.value, packageName.value)
    addTerminalLine('Loaded Modules:', 'output')
    for (const mod of response.data.modules || []) {
      addTerminalLine(`  - ${mod}`, 'output')
    }
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    runningQuickAction.value = null
  }
}

async function refreshFiles() {
  if (!activeSession.value) return

  loadingFiles.value = true
  try {
    const response = await objectionApi.listFiles(activeSession.value.session_id, currentPath.value)
    files.value = response.data.files || []
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'Failed to List Files',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
    files.value = []
  } finally {
    loadingFiles.value = false
  }
}

function navigateUp() {
  const parts = currentPath.value.split('/').filter(Boolean)
  if (parts.length > 1) {
    parts.pop()
    currentPath.value = '/' + parts.join('/')
    refreshFiles()
  }
}

function navigateToPath() {
  refreshFiles()
}

function handleFileClick(file: FileEntry) {
  // Single click selects
}

function handleFileDoubleClick(file: FileEntry) {
  if (file.type === 'directory') {
    currentPath.value = currentPath.value + '/' + file.name
    refreshFiles()
  } else {
    viewFile(file)
  }
}

async function viewFile(file: FileEntry) {
  if (!activeSession.value) return

  viewingFile.value = file
  showFileViewer.value = true
  loadingFileContent.value = true
  fileContent.value = null

  try {
    const filePath = currentPath.value + '/' + file.name
    const response = await objectionApi.readFile(activeSession.value.session_id, filePath)
    fileContent.value = response.data.content || 'Empty file'
  } catch (e: any) {
    fileContent.value = null
    toast.add({
      severity: 'error',
      summary: 'Failed to Read File',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
  } finally {
    loadingFileContent.value = false
  }
}

async function executeSqlQuery() {
  if (!activeSession.value || !sqlDbPath.value || !sqlQuery.value) return

  executingSql.value = true
  try {
    const response = await objectionApi.executeSql(
      activeSession.value.session_id,
      sqlDbPath.value,
      sqlQuery.value
    )
    sqlResults.value = response.data.rows || []
    sqlColumns.value = response.data.columns || Object.keys(sqlResults.value[0] || {})
  } catch (e: any) {
    toast.add({
      severity: 'error',
      summary: 'SQL Query Failed',
      detail: e.response?.data?.detail || 'Unknown error',
      life: 3000,
    })
    sqlResults.value = []
    sqlColumns.value = []
  } finally {
    executingSql.value = false
  }
}

async function loadObjectionStatus() {
  try {
    const response = await objectionApi.getStatus()
    objectionStatus.value = response.data
  } catch (e) {
    console.error('Failed to check Objection status:', e)
  }
}

async function loadCommands() {
  try {
    const response = await objectionApi.listCommands()
    commands.value = response.data.commands || {}
  } catch (e) {
    console.error('Failed to load commands:', e)
  }
}

async function loadActiveSessions() {
  try {
    const response = await objectionApi.listSessions({ status: 'active' })
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
    loadObjectionStatus(),
    loadCommands(),
    loadActiveSessions(),
  ])
})
</script>

<style scoped>
.objection-view {
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

.objection-container {
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
.field .p-inputtext,
.field .p-inputtextarea {
  width: 100%;
}

.device-option {
  display: flex;
  justify-content: space-between;
  align-items: center;
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

.quick-actions h4 {
  margin: 0 0 0.75rem;
}

.action-buttons {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
}

.command-browser {
  flex: 1;
  overflow: hidden;
  display: flex;
  flex-direction: column;
}

.command-browser h4 {
  margin: 0 0 0.75rem;
}

.command-search {
  width: 100%;
  margin-bottom: 0.75rem;
}

.command-categories {
  flex: 1;
  overflow-y: auto;
}

.command-list {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.command-item {
  padding: 0.5rem;
  border-radius: 4px;
  cursor: pointer;
  transition: background-color 0.2s;
}

.command-item:hover {
  background: var(--surface-hover);
}

.command-item.selected {
  background: var(--primary-color);
  color: white;
}

.command-name {
  display: block;
  font-size: 0.85rem;
  font-weight: 600;
  font-family: monospace;
}

.command-desc {
  display: block;
  font-size: 0.75rem;
  color: var(--text-color-secondary);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.command-item.selected .command-desc {
  color: rgba(255, 255, 255, 0.8);
}

/* Terminal styles */
.terminal-container {
  display: flex;
  flex-direction: column;
  height: 500px;
}

.terminal-output {
  flex: 1;
  background: #1e1e1e;
  border-radius: 4px;
  padding: 1rem;
  overflow-y: auto;
  font-family: monospace;
  font-size: 0.85rem;
  color: #d4d4d4;
  margin-bottom: 0.5rem;
}

.terminal-line {
  margin-bottom: 0.25rem;
}

.terminal-line.input .prompt {
  color: #4ec9b0;
}

.terminal-line.output {
  color: #d4d4d4;
}

.terminal-line.error {
  color: #f48771;
}

.terminal-line.success {
  color: #4ec9b0;
}

.terminal-input {
  display: flex;
  gap: 0.5rem;
  align-items: center;
  background: #1e1e1e;
  padding: 0.5rem;
  border-radius: 4px;
}

.terminal-input .prompt {
  color: #4ec9b0;
  font-family: monospace;
  white-space: nowrap;
}

.terminal-input .p-inputtext {
  flex: 1;
  background: transparent;
  border: none;
  color: #d4d4d4;
  font-family: monospace;
}

/* File browser styles */
.file-browser {
  display: flex;
  flex-direction: column;
  height: 500px;
}

.file-path-bar {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.file-path-bar .p-inputtext {
  flex: 1;
  font-family: monospace;
}

.file-list {
  flex: 1;
  border: 1px solid var(--surface-border);
  border-radius: 4px;
  overflow-y: auto;
}

.loading-files,
.empty-files {
  padding: 2rem;
  text-align: center;
  color: var(--text-color-secondary);
}

.file-item {
  display: flex;
  align-items: center;
  padding: 0.5rem 1rem;
  gap: 0.75rem;
  cursor: pointer;
  border-bottom: 1px solid var(--surface-border);
}

.file-item:hover {
  background: var(--surface-hover);
}

.file-item i {
  color: var(--text-color-secondary);
}

.file-name {
  flex: 1;
}

.file-size {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

/* SQLite styles */
.sqlite-explorer {
  display: flex;
  flex-direction: column;
  height: 500px;
}

.sql-input-section {
  margin-bottom: 1rem;
}

.sql-results {
  flex: 1;
  overflow: auto;
}

.sql-placeholder {
  padding: 2rem;
  text-align: center;
  color: var(--text-color-secondary);
}

/* Keychain styles */
.keychain-view {
  display: flex;
  flex-direction: column;
  height: 500px;
  gap: 1rem;
}

.keychain-results {
  flex: 1;
  overflow: auto;
}

.keychain-placeholder {
  padding: 2rem;
  text-align: center;
  color: var(--text-color-secondary);
}

.secret-data {
  font-family: monospace;
  font-size: 0.85rem;
}

/* File viewer dialog */
.file-viewer {
  max-height: 500px;
  overflow: auto;
}

.file-viewer pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-word;
  font-family: monospace;
  font-size: 0.85rem;
}

.file-error {
  text-align: center;
  color: var(--text-color-secondary);
}

@media (max-width: 992px) {
  .objection-container {
    grid-template-columns: 1fr;
  }
}
</style>
