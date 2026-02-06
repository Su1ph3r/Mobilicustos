<template>
  <div class="settings">
    <div class="page-header">
      <h1>Settings</h1>
      <p class="text-secondary">System configuration and status</p>
    </div>

    <!-- Connection Status -->
    <div class="section">
      <h2 class="section-title">
        <i class="pi pi-wifi"></i>
        Connection Status
      </h2>
      <div class="grid">
        <div class="col-12 md:col-6 lg:col-3" v-for="(service, key) in statusServices" :key="key">
          <Card class="status-card">
            <template #content>
              <div class="status-card-content">
                <div class="status-header">
                  <i :class="service.icon" class="status-icon"></i>
                  <span class="status-label">{{ service.label }}</span>
                </div>
                <div class="status-indicator">
                  <ProgressSpinner
                    v-if="loadingStatus"
                    style="width: 24px; height: 24px"
                    strokeWidth="4"
                  />
                  <template v-else>
                    <Tag
                      :value="getServiceStatus(key).connected ? 'Connected' : 'Disconnected'"
                      :severity="getServiceStatus(key).connected ? 'success' : 'danger'"
                    />
                  </template>
                </div>
                <p class="status-message" v-if="!loadingStatus">
                  {{ getServiceStatus(key).message || 'Not checked' }}
                </p>
              </div>
            </template>
          </Card>
        </div>
      </div>
      <div class="section-actions">
        <Button
          label="Refresh Status"
          icon="pi pi-refresh"
          :loading="loadingStatus"
          @click="fetchStatus"
          severity="secondary"
          size="small"
        />
      </div>
    </div>

    <Divider />

    <!-- Configuration -->
    <div class="section">
      <h2 class="section-title">
        <i class="pi pi-sliders-h"></i>
        Configuration
      </h2>
      <ProgressSpinner v-if="loadingConfig" style="width: 40px; height: 40px" strokeWidth="4" />
      <div v-else class="grid">
        <!-- Database -->
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-database"></i>
                Database
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Host</span>
                  <span class="config-value">{{ config?.database?.host || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Port</span>
                  <span class="config-value">{{ config?.database?.port || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Database</span>
                  <span class="config-value">{{ config?.database?.database || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">User</span>
                  <span class="config-value">{{ config?.database?.user || '-' }}</span>
                </div>
              </div>
            </template>
          </Card>
        </div>

        <!-- API -->
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-server"></i>
                API
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Host</span>
                  <span class="config-value">{{ config?.api?.host || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Port</span>
                  <span class="config-value">{{ config?.api?.port || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Debug</span>
                  <span class="config-value">{{ config?.api?.debug ? 'Enabled' : 'Disabled' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Log Level</span>
                  <span class="config-value">{{ config?.api?.log_level || '-' }}</span>
                </div>
              </div>
            </template>
          </Card>
        </div>

        <!-- Frida -->
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-code"></i>
                Frida
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Server Version</span>
                  <span class="config-value">{{ config?.frida?.server_version || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Server Host</span>
                  <span class="config-value">{{ config?.frida?.server_host || 'Not configured' }}</span>
                </div>
              </div>
            </template>
          </Card>
        </div>

        <!-- Analysis -->
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-search"></i>
                Analysis
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Max APK Size</span>
                  <span class="config-value">{{ config?.analysis?.max_apk_size_mb || '-' }} MB</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Max IPA Size</span>
                  <span class="config-value">{{ config?.analysis?.max_ipa_size_mb || '-' }} MB</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Timeout</span>
                  <span class="config-value">{{ config?.analysis?.timeout_seconds || '-' }}s</span>
                </div>
              </div>
            </template>
          </Card>
        </div>

        <!-- Paths -->
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-folder"></i>
                Paths
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Uploads</span>
                  <span class="config-value monospace">{{ config?.paths?.uploads || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Reports</span>
                  <span class="config-value monospace">{{ config?.paths?.reports || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Frida Scripts</span>
                  <span class="config-value monospace">{{ config?.paths?.frida_scripts || '-' }}</span>
                </div>
              </div>
            </template>
          </Card>
        </div>

        <!-- Tools -->
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-wrench"></i>
                Tools
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">JADX</span>
                  <span class="config-value monospace">{{ config?.tools?.jadx || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">APKTool</span>
                  <span class="config-value monospace">{{ config?.tools?.apktool || '-' }}</span>
                </div>
              </div>
            </template>
          </Card>
        </div>
      </div>
    </div>

    <Divider />

    <!-- Registered Devices -->
    <div class="section">
      <h2 class="section-title">
        <i class="pi pi-tablet"></i>
        Registered Devices
      </h2>
      <ProgressSpinner v-if="loadingDevices" style="width: 40px; height: 40px" strokeWidth="4" />
      <div v-else-if="devices.length === 0" class="empty-state">
        <i class="pi pi-tablet"></i>
        <p>No devices registered</p>
        <Button label="Go to Devices" icon="pi pi-arrow-right" size="small" severity="secondary" @click="$router.push('/devices')" />
      </div>
      <DataTable v-else :value="devices" stripedRows class="devices-table" :rows="5" :paginator="devices.length > 5">
        <Column field="device_name" header="Name">
          <template #body="{ data }">
            <div class="device-name-cell">
              <i :class="data.platform === 'ios' ? 'pi pi-apple' : 'pi pi-android'"></i>
              {{ data.device_name || data.device_id }}
            </div>
          </template>
        </Column>
        <Column field="platform" header="Platform">
          <template #body="{ data }">
            <Tag :value="(data.platform || 'unknown').toUpperCase()" :severity="data.platform === 'ios' ? 'info' : 'success'" />
          </template>
        </Column>
        <Column field="status" header="Status">
          <template #body="{ data }">
            <Tag :value="data.status || 'unknown'" :severity="data.status === 'connected' ? 'success' : 'warn'" />
          </template>
        </Column>
        <Column field="device_id" header="ID">
          <template #body="{ data }">
            <span class="config-value monospace">{{ data.device_id?.substring(0, 16) }}...</span>
          </template>
        </Column>
      </DataTable>
      <div class="section-actions">
        <Button label="Manage Devices" icon="pi pi-external-link" size="small" severity="secondary" @click="$router.push('/devices')" />
      </div>
    </div>

    <Divider />

    <!-- Frida Configuration -->
    <div class="section">
      <h2 class="section-title">
        <i class="pi pi-code"></i>
        Frida Configuration
      </h2>
      <div class="grid">
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-server"></i>
                Server
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Server Version</span>
                  <span class="config-value">{{ config?.frida?.server_version || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Server Host</span>
                  <span class="config-value monospace">{{ config?.frida?.server_host || 'Not configured' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Connection</span>
                  <Tag
                    :value="getServiceStatus('frida').connected ? 'Connected' : 'Disconnected'"
                    :severity="getServiceStatus('frida').connected ? 'success' : 'danger'"
                  />
                </div>
              </div>
            </template>
          </Card>
        </div>
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-list"></i>
                Scripts
              </div>
            </template>
            <template #content>
              <div class="config-list">
                <div class="config-item">
                  <span class="config-key">Script Directory</span>
                  <span class="config-value monospace">{{ config?.paths?.frida_scripts || '-' }}</span>
                </div>
                <div class="config-item">
                  <span class="config-key">Manage Scripts</span>
                  <Button label="Open Frida View" icon="pi pi-external-link" size="small" text @click="$router.push('/frida')" />
                </div>
              </div>
            </template>
          </Card>
        </div>
      </div>
    </div>

    <Divider />

    <!-- Preferences -->
    <div class="section">
      <h2 class="section-title">
        <i class="pi pi-palette"></i>
        Preferences
      </h2>
      <div class="grid">
        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-moon"></i>
                Theme
              </div>
            </template>
            <template #content>
              <div class="preference-row">
                <span>Dark Mode</span>
                <InputSwitch v-model="darkMode" @change="toggleDarkMode" />
              </div>
            </template>
          </Card>
        </div>

        <div class="col-12 md:col-6">
          <Card>
            <template #title>
              <div class="config-card-title">
                <i class="pi pi-download"></i>
                Export
              </div>
            </template>
            <template #content>
              <div class="preference-row">
                <span>Default Export Format</span>
                <Dropdown
                  v-model="defaultExportFormat"
                  :options="exportFormatOptions"
                  optionLabel="label"
                  optionValue="value"
                  placeholder="Select format"
                  @change="saveExportFormat"
                  style="width: 150px"
                />
              </div>
            </template>
          </Card>
        </div>
      </div>
    </div>

    <Divider />

    <!-- About -->
    <div class="section">
      <h2 class="section-title">
        <i class="pi pi-info-circle"></i>
        About
      </h2>
      <Card>
        <template #content>
          <div class="about-content">
            <div class="about-logo">
              <i class="pi pi-shield"></i>
              <div>
                <h3>Mobilicustos</h3>
                <p class="text-secondary">Mobile Security Penetration Testing Platform</p>
              </div>
            </div>
            <div class="about-details">
              <div class="config-item">
                <span class="config-key">Version</span>
                <span class="config-value">0.1.0</span>
              </div>
              <div class="config-item">
                <span class="config-key">Source</span>
                <a
                  href="https://github.com/su1ph3r/mobilicustos"
                  target="_blank"
                  rel="noopener noreferrer"
                  class="github-link"
                >
                  <i class="pi pi-github"></i>
                  github.com/su1ph3r/mobilicustos
                </a>
              </div>
            </div>
          </div>
        </template>
      </Card>
    </div>

    <Toast />
  </div>
</template>

<script setup lang="ts">
/**
 * SettingsView - Application settings, service connection status, and system configuration.
 *
 * Features:
 * - Connection status cards for PostgreSQL, Neo4j, Redis, and Frida
 * - Configuration display for database, API, Frida, analysis limits, paths, and tools
 * - Registered devices table with platform and status badges
 * - Frida server configuration and script directory details
 * - User preferences: dark mode toggle and default export format selection
 * - About section with version and GitHub repository link
 *
 * @requires settingsApi - fetches system configuration and service connection status
 * @requires devicesApi - fetches registered device list for display
 */
import { ref, onMounted } from 'vue'
import { settingsApi, devicesApi } from '@/services/api'
import Card from 'primevue/card'
import Tag from 'primevue/tag'
import InputSwitch from 'primevue/inputswitch'
import Dropdown from 'primevue/dropdown'
import Divider from 'primevue/divider'
import Button from 'primevue/button'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import ProgressSpinner from 'primevue/progressspinner'
import Toast from 'primevue/toast'
import { useToast } from 'primevue/usetoast'

const toast = useToast()

const config = ref<Record<string, any> | null>(null)
const status = ref<Record<string, any>>({})
const devices = ref<any[]>([])
const loadingConfig = ref(false)
const loadingStatus = ref(false)
const loadingDevices = ref(false)
const darkMode = ref(false)
const defaultExportFormat = ref('json')

const exportFormatOptions = [
  { label: 'CSV', value: 'csv' },
  { label: 'JSON', value: 'json' },
  { label: 'HTML', value: 'html' },
  { label: 'PDF', value: 'pdf' },
  { label: 'SARIF', value: 'sarif' },
]

const statusServices: Record<string, { label: string; icon: string }> = {
  postgres: { label: 'PostgreSQL', icon: 'pi pi-database' },
  neo4j: { label: 'Neo4j', icon: 'pi pi-sitemap' },
  redis: { label: 'Redis', icon: 'pi pi-bolt' },
  frida: { label: 'Frida', icon: 'pi pi-code' },
}

function getServiceStatus(key: string): { connected: boolean; message: string } {
  return status.value[key] || { connected: false, message: 'Not checked' }
}

async function fetchConfig() {
  loadingConfig.value = true
  try {
    const response = await settingsApi.getSettings()
    config.value = response.data
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to load configuration',
      life: 5000,
    })
  } finally {
    loadingConfig.value = false
  }
}

async function fetchStatus() {
  loadingStatus.value = true
  try {
    const response = await settingsApi.getStatus()
    status.value = response.data
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to check service status',
      life: 5000,
    })
  } finally {
    loadingStatus.value = false
  }
}

function toggleDarkMode() {
  localStorage.setItem('darkMode', String(darkMode.value))
  document.documentElement.classList.toggle('dark-mode', darkMode.value)
}

function saveExportFormat() {
  localStorage.setItem('defaultExportFormat', defaultExportFormat.value)
}

function loadPreferences() {
  const savedDarkMode = localStorage.getItem('darkMode')
  if (savedDarkMode === 'true') {
    darkMode.value = true
  }

  const savedFormat = localStorage.getItem('defaultExportFormat')
  if (savedFormat) {
    defaultExportFormat.value = savedFormat
  }
}

async function fetchDevices() {
  loadingDevices.value = true
  try {
    const response = await devicesApi.list()
    devices.value = response.data.items || response.data || []
  } catch (error) {
    // Devices loading is non-critical
    console.error('Failed to load devices:', error)
  } finally {
    loadingDevices.value = false
  }
}

onMounted(() => {
  loadPreferences()
  fetchConfig()
  fetchStatus()
  fetchDevices()
})
</script>

<style scoped>
.settings {
  padding: 1rem;
}

.page-header {
  margin-bottom: 1.5rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.75rem;
}

.text-secondary {
  color: var(--text-color-secondary);
  margin-top: 0.25rem;
}

.section {
  margin-bottom: 1rem;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1.25rem;
  margin-bottom: 1rem;
  color: var(--text-color);
}

.section-title i {
  color: var(--primary-color);
}

.section-actions {
  margin-top: 1rem;
}

/* Status Cards */
.status-card {
  height: 100%;
}

.status-card-content {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  text-align: center;
}

.status-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.status-icon {
  font-size: 1.25rem;
  color: var(--primary-color);
}

.status-label {
  font-weight: 600;
  font-size: 1rem;
}

.status-message {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
  margin: 0;
  word-break: break-all;
}

/* Config Cards */
.config-card-title {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 1rem;
}

.config-card-title i {
  color: var(--primary-color);
}

.config-list {
  display: flex;
  flex-direction: column;
  gap: 0.625rem;
}

.config-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem 0;
  border-bottom: 1px solid var(--surface-border);
}

.config-item:last-child {
  border-bottom: none;
}

.config-key {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.config-value {
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text-color);
}

.config-value.monospace {
  font-family: monospace;
  font-size: 0.8rem;
}

/* Preferences */
.preference-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

/* About */
.about-content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.about-logo {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.about-logo > i {
  font-size: 2.5rem;
  color: var(--primary-color);
}

.about-logo h3 {
  margin: 0;
  font-size: 1.25rem;
}

.about-logo p {
  margin: 0.25rem 0 0 0;
}

.about-details {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.github-link {
  display: flex;
  align-items: center;
  gap: 0.375rem;
  color: var(--primary-color);
  text-decoration: none;
  font-size: 0.875rem;
  font-weight: 500;
}

.github-link:hover {
  text-decoration: underline;
}

/* Devices Table */
.devices-table {
  border-radius: 10px;
  overflow: hidden;
}

.device-name-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.device-name-cell i {
  color: var(--primary-color);
}

/* Empty State */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.75rem;
  padding: 2rem;
  color: var(--text-color-secondary);
  background: var(--surface-card);
  border: 1px dashed var(--surface-border);
  border-radius: 10px;
}

.empty-state i {
  font-size: 2rem;
  opacity: 0.5;
}

.empty-state p {
  margin: 0;
}
</style>
