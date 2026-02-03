<template>
  <div class="frida-view">
    <div class="page-header">
      <div>
        <h1>Frida Console</h1>
        <p class="text-secondary">Dynamic instrumentation and runtime analysis</p>
      </div>
    </div>

    <div class="frida-container">
      <!-- Left Panel: Script Editor -->
      <div class="panel script-panel">
        <div class="panel-header">
          <h3>Script Editor</h3>
          <div class="panel-actions">
            <Dropdown
              v-model="selectedScript"
              :options="scripts"
              optionLabel="name"
              placeholder="Load Script"
              @change="loadScript"
            />
            <Button icon="pi pi-save" class="p-button-sm" v-tooltip="'Save Script'" @click="saveScript" />
            <Button icon="pi pi-plus" class="p-button-sm p-button-secondary" v-tooltip="'New Script'" @click="newScript" />
          </div>
        </div>
        <div class="script-info" v-if="currentScript.name">
          <span class="script-name">{{ currentScript.name }}</span>
          <Tag v-if="currentScript.category" :value="currentScript.category" severity="secondary" />
        </div>
        <Textarea
          v-model="currentScript.content"
          :autoResize="false"
          class="code-editor"
          placeholder="// Enter your Frida script here..."
        />
      </div>

      <!-- Right Panel: Injection & Output -->
      <div class="panel output-panel">
        <!-- Injection Controls -->
        <div class="injection-controls card">
          <div class="control-row">
            <div class="control-item">
              <label>Device</label>
              <Dropdown
                v-model="selectedDevice"
                :options="devices"
                optionLabel="device_name"
                optionValue="device_id"
                placeholder="Select Device"
                :disabled="injecting"
              />
            </div>
            <div class="control-item">
              <label>Application</label>
              <Dropdown
                v-model="selectedApp"
                :options="apps"
                optionLabel="app_name"
                optionValue="app_id"
                placeholder="Select App"
                :disabled="injecting"
              />
            </div>
          </div>
          <div class="control-actions">
            <Button
              v-if="!injecting"
              label="Inject"
              icon="pi pi-play"
              @click="injectScript"
              :disabled="!selectedDevice || !selectedApp"
            />
            <Button
              v-else
              label="Detach"
              icon="pi pi-stop"
              class="p-button-danger"
              @click="detachSession"
            />
            <Button
              label="Clear Output"
              icon="pi pi-trash"
              class="p-button-secondary"
              @click="clearOutput"
            />
          </div>
        </div>

        <!-- Active Sessions -->
        <div v-if="sessions.length > 0" class="sessions-card card">
          <h4>Active Sessions</h4>
          <div class="sessions-list">
            <div v-for="session in sessions" :key="session.session_id" class="session-item">
              <div class="session-info">
                <span class="session-app">{{ session.app_name }}</span>
                <span class="session-device">{{ session.device_name }}</span>
              </div>
              <Button
                icon="pi pi-times"
                class="p-button-sm p-button-danger p-button-text"
                @click="detachSessionById(session.session_id)"
              />
            </div>
          </div>
        </div>

        <!-- Output Console -->
        <div class="output-console card">
          <div class="console-header">
            <h4>Output</h4>
            <div class="console-status">
              <Tag v-if="injecting" value="Attached" severity="success" />
              <Tag v-else value="Detached" severity="secondary" />
            </div>
          </div>
          <div ref="outputContainer" class="console-output">
            <div v-for="(line, index) in outputLines" :key="index" :class="['output-line', line.type]">
              <span class="output-timestamp">{{ line.timestamp }}</span>
              <span class="output-text">{{ line.text }}</span>
            </div>
            <div v-if="outputLines.length === 0" class="output-placeholder">
              Output will appear here when script is injected...
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Script Library Dialog -->
    <Dialog
      v-model:visible="showLibraryDialog"
      header="Script Library"
      :modal="true"
      :style="{ width: '700px' }"
    >
      <div class="library-filters">
        <Dropdown
          v-model="libraryCategory"
          :options="categories"
          placeholder="All Categories"
          showClear
        />
        <InputText v-model="librarySearch" placeholder="Search scripts..." />
      </div>
      <DataTable :value="filteredLibraryScripts" :paginator="true" :rows="5">
        <Column field="name" header="Name" />
        <Column field="category" header="Category">
          <template #body="{ data }">
            <Tag :value="data.category" severity="secondary" />
          </template>
        </Column>
        <Column field="description" header="Description" />
        <Column header="Action" style="width: 100px">
          <template #body="{ data }">
            <Button label="Use" class="p-button-sm" @click="useLibraryScript(data)" />
          </template>
        </Column>
      </DataTable>
    </Dialog>

    <!-- Save Script Dialog -->
    <Dialog
      v-model:visible="showSaveDialog"
      header="Save Script"
      :modal="true"
      :style="{ width: '400px' }"
    >
      <div class="save-form">
        <div class="field">
          <label>Name</label>
          <InputText v-model="saveForm.name" placeholder="Script name" />
        </div>
        <div class="field">
          <label>Category</label>
          <Dropdown
            v-model="saveForm.category"
            :options="categories"
            placeholder="Select Category"
            editable
          />
        </div>
        <div class="field">
          <label>Description</label>
          <Textarea v-model="saveForm.description" rows="3" placeholder="What does this script do?" />
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" class="p-button-text" @click="showSaveDialog = false" />
        <Button label="Save" icon="pi pi-save" @click="confirmSaveScript" />
      </template>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, nextTick } from 'vue'
import { useDevicesStore } from '@/stores/devices'
import { useAppsStore } from '@/stores/apps'
import { fridaApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import Textarea from 'primevue/textarea'
import InputText from 'primevue/inputtext'
import Tag from 'primevue/tag'
import Dialog from 'primevue/dialog'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Toast from 'primevue/toast'

const devicesStore = useDevicesStore()
const appsStore = useAppsStore()
const toast = useToast()

const devices = computed(() => devicesStore.devices.filter((d) => d.status === 'connected'))
const apps = computed(() => appsStore.apps)

const selectedDevice = ref<string | null>(null)
const selectedApp = ref<string | null>(null)
const selectedScript = ref<any>(null)
const injecting = ref(false)
const currentSessionId = ref<string | null>(null)

const currentScript = ref({
  id: null as string | null,
  name: '',
  category: '',
  content: '',
  description: '',
})

const scripts = ref<any[]>([])
const sessions = ref<any[]>([])
const categories = ref<string[]>([])

const outputContainer = ref<HTMLElement | null>(null)
const outputLines = ref<Array<{ timestamp: string; text: string; type: string }>>([])

const showLibraryDialog = ref(false)
const showSaveDialog = ref(false)
const libraryCategory = ref<string | null>(null)
const librarySearch = ref('')

const saveForm = ref({
  name: '',
  category: '',
  description: '',
})

const filteredLibraryScripts = computed(() => {
  return scripts.value.filter((s) => {
    if (libraryCategory.value && s.category !== libraryCategory.value) return false
    if (librarySearch.value && !s.name.toLowerCase().includes(librarySearch.value.toLowerCase())) return false
    return true
  })
})

function loadScript() {
  if (selectedScript.value) {
    currentScript.value = {
      id: selectedScript.value.script_id,
      name: selectedScript.value.name,
      category: selectedScript.value.category,
      content: selectedScript.value.content,
      description: selectedScript.value.description || '',
    }
  }
}

function newScript() {
  currentScript.value = {
    id: null,
    name: '',
    category: '',
    content: '',
    description: '',
  }
  selectedScript.value = null
}

function saveScript() {
  saveForm.value = {
    name: currentScript.value.name,
    category: currentScript.value.category,
    description: currentScript.value.description,
  }
  showSaveDialog.value = true
}

async function confirmSaveScript() {
  try {
    const data = {
      name: saveForm.value.name,
      category: saveForm.value.category,
      description: saveForm.value.description,
      content: currentScript.value.content,
    }

    if (currentScript.value.id) {
      await fridaApi.updateScript(currentScript.value.id, data)
    } else {
      const response = await fridaApi.createScript(data)
      currentScript.value.id = response.data.script_id
    }

    currentScript.value.name = saveForm.value.name
    currentScript.value.category = saveForm.value.category
    currentScript.value.description = saveForm.value.description

    await loadScripts()
    showSaveDialog.value = false
    toast.add({ severity: 'success', summary: 'Saved', detail: 'Script saved', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to save script', life: 3000 })
  }
}

function useLibraryScript(script: any) {
  currentScript.value = {
    id: null,
    name: script.name + ' (copy)',
    category: script.category,
    content: script.content,
    description: script.description || '',
  }
  showLibraryDialog.value = false
}

async function injectScript() {
  if (!selectedDevice.value || !selectedApp.value) return

  try {
    injecting.value = true
    addOutput('Injecting script...', 'info')

    const response = await fridaApi.inject({
      device_id: selectedDevice.value,
      app_id: selectedApp.value,
      script_content: currentScript.value.content,
    })

    currentSessionId.value = response.data.session_id
    addOutput('Script injected successfully', 'success')

    await loadSessions()

    // Simulated output - in real implementation, use WebSocket
    simulateOutput()
  } catch (e: any) {
    addOutput(`Injection failed: ${e.response?.data?.detail || e.message}`, 'error')
    injecting.value = false
  }
}

async function detachSession() {
  if (!currentSessionId.value) return

  try {
    await fridaApi.detachSession(currentSessionId.value)
    addOutput('Session detached', 'info')
    currentSessionId.value = null
    injecting.value = false
    await loadSessions()
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to detach session', life: 3000 })
  }
}

async function detachSessionById(sessionId: string) {
  try {
    await fridaApi.detachSession(sessionId)
    if (sessionId === currentSessionId.value) {
      currentSessionId.value = null
      injecting.value = false
    }
    await loadSessions()
    toast.add({ severity: 'success', summary: 'Detached', detail: 'Session detached', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to detach session', life: 3000 })
  }
}

function addOutput(text: string, type: string = 'log') {
  const timestamp = new Date().toLocaleTimeString()
  outputLines.value.push({ timestamp, text, type })
  nextTick(() => {
    if (outputContainer.value) {
      outputContainer.value.scrollTop = outputContainer.value.scrollHeight
    }
  })
}

function clearOutput() {
  outputLines.value = []
}

function simulateOutput() {
  // Simulated Frida output - replace with WebSocket in production
  const messages = [
    '[*] Attaching to process...',
    '[+] Attached successfully',
    '[*] Hooking functions...',
    '[+] SSL Pinning: Found OkHttp3 CertificatePinner',
    '[+] Root Detection: Intercepted file check',
  ]
  let i = 0
  const interval = setInterval(() => {
    if (i >= messages.length || !injecting.value) {
      clearInterval(interval)
      return
    }
    addOutput(messages[i], 'log')
    i++
  }, 500)
}

async function loadScripts() {
  try {
    const response = await fridaApi.listScripts()
    scripts.value = response.data.items || []
  } catch (e) {
    console.error('Failed to load scripts:', e)
  }
}

async function loadSessions() {
  try {
    const response = await fridaApi.listSessions()
    sessions.value = response.data || []
  } catch (e) {
    console.error('Failed to load sessions:', e)
  }
}

async function loadCategories() {
  try {
    const response = await fridaApi.getCategories()
    categories.value = response.data || []
  } catch (e) {
    categories.value = ['bypass', 'monitor', 'exploit', 'crypto', 'network', 'custom']
  }
}

onMounted(async () => {
  await Promise.all([
    devicesStore.fetchDevices(),
    appsStore.fetchApps(),
    loadScripts(),
    loadSessions(),
    loadCategories(),
  ])
})
</script>

<style scoped>
.frida-view {
  padding: 1rem;
  height: calc(100vh - 80px);
  display: flex;
  flex-direction: column;
}

.page-header {
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

.frida-container {
  display: grid;
  grid-template-columns: 1fr 1fr;
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
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem;
  border-bottom: 1px solid var(--surface-border);
}

.panel-header h3 {
  margin: 0;
}

.panel-actions {
  display: flex;
  gap: 0.5rem;
}

.script-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: var(--surface-ground);
}

.script-name {
  font-weight: 600;
}

.code-editor {
  flex: 1;
  font-family: monospace;
  font-size: 0.9rem;
  border: none;
  border-radius: 0;
  resize: none;
  background: var(--surface-ground);
}

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1rem;
  margin-bottom: 1rem;
}

.injection-controls .control-row {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
}

.control-item {
  flex: 1;
}

.control-item label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.control-item .p-dropdown {
  width: 100%;
}

.control-actions {
  display: flex;
  gap: 0.5rem;
}

.sessions-card h4 {
  margin: 0 0 0.75rem;
}

.sessions-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.session-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.session-app {
  font-weight: 600;
}

.session-device {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
  margin-left: 0.5rem;
}

.output-console {
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
  font-family: monospace;
  font-size: 0.85rem;
  overflow-y: auto;
  color: #d4d4d4;
}

.output-line {
  margin-bottom: 0.25rem;
}

.output-line.success { color: #4ec9b0; }
.output-line.error { color: #f48771; }
.output-line.info { color: #569cd6; }
.output-line.log { color: #d4d4d4; }

.output-timestamp {
  color: #6a9955;
  margin-right: 0.5rem;
}

.output-placeholder {
  color: #6a6a6a;
  font-style: italic;
}

.library-filters {
  display: flex;
  gap: 1rem;
  margin-bottom: 1rem;
}

.save-form .field {
  margin-bottom: 1rem;
}

.save-form label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 600;
}

.save-form .p-inputtext,
.save-form .p-dropdown,
.save-form .p-inputtextarea {
  width: 100%;
}

@media (max-width: 992px) {
  .frida-container {
    grid-template-columns: 1fr;
  }
}
</style>
