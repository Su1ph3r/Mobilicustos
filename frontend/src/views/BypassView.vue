<template>
  <div class="bypass-view">
    <div class="bypass-header">
      <div class="header-content">
        <h2>Security Bypass Testing</h2>
        <p class="subtitle">Analyze and bypass app protections using Frida scripts</p>
      </div>
    </div>

    <!-- Setup Section -->
    <div class="setup-section">
      <div class="setup-card">
        <div class="setup-row">
          <div class="field">
            <label for="app-select">Target App</label>
            <Dropdown
              id="app-select"
              v-model="selectedAppId"
              :options="apps"
              optionLabel="app_name"
              optionValue="app_id"
              placeholder="Select an app"
              class="w-full"
              :loading="loadingApps"
              filter
            />
          </div>
          <div class="field">
            <label for="device-select">Device</label>
            <Dropdown
              id="device-select"
              v-model="selectedDeviceId"
              :options="devices"
              optionLabel="label"
              optionValue="device_id"
              placeholder="Select a device"
              class="w-full"
              :loading="loadingDevices"
            />
          </div>
          <div class="field actions-field">
            <label>&nbsp;</label>
            <div class="action-buttons">
              <Button
                label="Analyze Protections"
                icon="pi pi-search"
                @click="analyzeProtections"
                :loading="analyzing"
                :disabled="!selectedAppId"
                v-tooltip.top="'Detect security protections in the app'"
              />
              <Button
                label="Auto Bypass All"
                icon="pi pi-bolt"
                severity="warning"
                @click="autoBypassAll"
                :loading="autoBypassRunning"
                :disabled="!selectedAppId || !selectedDeviceId"
                v-tooltip.top="'Attempt to bypass all detected protections automatically'"
              />
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Error Message -->
    <div v-if="error" class="error-message">
      <i class="pi pi-exclamation-triangle" />
      {{ error }}
      <Button label="Dismiss" size="small" text @click="error = ''" />
    </div>

    <!-- Detections Section -->
    <div v-if="detections.length > 0" class="detections-section">
      <h3>Detected Protections</h3>
      <div class="detections-grid">
        <div
          v-for="detection in detections"
          :key="detection.detection_type + detection.detection_method"
          class="detection-card"
          :class="getDetectionStatusClass(detection)"
        >
          <div class="detection-header">
            <div class="detection-icon">
              <i :class="getDetectionIcon(detection.detection_type)" />
            </div>
            <div class="detection-info">
              <div class="detection-type">{{ formatDetectionType(detection.detection_type) }}</div>
              <div class="detection-method">{{ detection.detection_method }}</div>
            </div>
            <Tag
              :value="formatConfidence(detection.confidence)"
              :severity="getConfidenceSeverity(detection.confidence)"
            />
          </div>

          <div v-if="detection.detection_library" class="detection-library">
            <i class="pi pi-box" />
            {{ detection.detection_library }}
          </div>

          <div v-if="detection.evidence" class="detection-evidence">
            <small>{{ detection.evidence }}</small>
          </div>

          <div class="detection-actions">
            <Button
              :label="getBypassButtonLabel(detection)"
              :icon="getBypassButtonIcon(detection)"
              size="small"
              :severity="getBypassButtonSeverity(detection)"
              :loading="bypassingType === detection.detection_type"
              :disabled="!selectedDeviceId || bypassingType !== null"
              @click="attemptBypass(detection)"
              v-tooltip.top="'Run bypass script against this protection'"
            />
            <Tag
              v-if="detection.bypass_status"
              :value="detection.bypass_status"
              :severity="getBypassStatusSeverity(detection.bypass_status)"
              class="status-tag"
            />
          </div>

          <div v-if="detection.bypass_notes" class="bypass-notes">
            <pre>{{ detection.bypass_notes }}</pre>
          </div>
        </div>
      </div>
    </div>

    <!-- Auto Bypass Results -->
    <div v-if="autoBypassResults" class="auto-bypass-section">
      <h3>Auto Bypass Results</h3>
      <div class="summary-cards">
        <div class="summary-card total">
          <div class="summary-value">{{ autoBypassResults.summary.total }}</div>
          <div class="summary-label">Total</div>
        </div>
        <div class="summary-card success">
          <div class="summary-value">{{ autoBypassResults.summary.success }}</div>
          <div class="summary-label">Success</div>
        </div>
        <div class="summary-card partial">
          <div class="summary-value">{{ autoBypassResults.summary.partial }}</div>
          <div class="summary-label">Partial</div>
        </div>
        <div class="summary-card failed">
          <div class="summary-value">{{ autoBypassResults.summary.failed }}</div>
          <div class="summary-label">Failed</div>
        </div>
      </div>
    </div>

    <!-- Past Results Table -->
    <div class="results-section">
      <h3>Bypass History</h3>
      <DataTable
        :value="results"
        :loading="loadingResults"
        :paginator="true"
        :rows="10"
        :rowsPerPageOptions="[10, 25, 50]"
        stripedRows
        sortField="created_at"
        :sortOrder="-1"
        class="results-table"
        :emptyMessage="'No bypass attempts recorded yet'"
      >
        <Column field="detection_type" header="Protection" sortable>
          <template #body="{ data }">
            <div class="type-cell">
              <i :class="getDetectionIcon(data.detection_type)" />
              {{ formatDetectionType(data.detection_type) }}
            </div>
          </template>
        </Column>
        <Column field="detection_method" header="Method" sortable />
        <Column field="bypass_status" header="Status" sortable>
          <template #body="{ data }">
            <Tag
              :value="data.bypass_status"
              :severity="getBypassStatusSeverity(data.bypass_status)"
            />
          </template>
        </Column>
        <Column field="bypass_notes" header="Notes">
          <template #body="{ data }">
            <span class="notes-cell">{{ data.bypass_notes?.substring(0, 80) }}{{ data.bypass_notes?.length > 80 ? '...' : '' }}</span>
          </template>
        </Column>
        <Column field="created_at" header="Date" sortable>
          <template #body="{ data }">
            {{ formatDate(data.created_at) }}
          </template>
        </Column>
      </DataTable>
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * BypassView - Security bypass orchestration for root, jailbreak, SSL pinning, and Frida detection.
 *
 * Features:
 * - App and device selection for targeted bypass testing
 * - Protection analysis detecting root, jailbreak, frida, emulator, debugger, and SSL pinning checks
 * - Per-detection bypass attempt with status feedback (success/partial/failed)
 * - Auto-bypass-all mode with summary cards (total, success, partial, failed)
 * - Bypass history table with sortable columns and date tracking
 * - Detection cards showing confidence level, library, and evidence
 *
 * @requires bypassApi - analyze protections, attempt bypass, auto-bypass, and results listing
 * @requires appsApi - provides the application list for selection
 * @requires devicesApi - provides the device list for bypass targeting
 */
import { ref, onMounted, watch } from 'vue'
import { bypassApi, appsApi, devicesApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'

const toast = useToast()

// State
const selectedAppId = ref('')
const selectedDeviceId = ref('')
const apps = ref<any[]>([])
const devices = ref<any[]>([])
const detections = ref<any[]>([])
const results = ref<any[]>([])
const autoBypassResults = ref<any>(null)
const error = ref('')

// Loading states
const loadingApps = ref(false)
const loadingDevices = ref(false)
const loadingResults = ref(false)
const analyzing = ref(false)
const autoBypassRunning = ref(false)
const bypassingType = ref<string | null>(null)

// Load apps and devices on mount
onMounted(async () => {
  await Promise.all([loadApps(), loadDevices()])
})

// When app changes, load results
watch(selectedAppId, () => {
  if (selectedAppId.value) {
    loadResults()
    detections.value = []
    autoBypassResults.value = null
  }
})

async function loadApps() {
  loadingApps.value = true
  try {
    const response = await appsApi.list()
    apps.value = response.data.items || response.data || []
  } catch (e) {
    console.error('Failed to load apps:', e)
  } finally {
    loadingApps.value = false
  }
}

async function loadDevices() {
  loadingDevices.value = true
  try {
    const response = await devicesApi.list()
    const deviceList = response.data.items || response.data || []
    devices.value = deviceList.map((d: any) => ({
      ...d,
      label: `${d.device_name || d.device_id} (${d.platform || 'unknown'})`,
    }))
  } catch (e) {
    console.error('Failed to load devices:', e)
  } finally {
    loadingDevices.value = false
  }
}

async function loadResults() {
  loadingResults.value = true
  try {
    const response = await bypassApi.listResults({ app_id: selectedAppId.value })
    results.value = response.data.items || response.data || []
  } catch (e) {
    console.error('Failed to load results:', e)
  } finally {
    loadingResults.value = false
  }
}

async function analyzeProtections() {
  if (!selectedAppId.value) return
  analyzing.value = true
  error.value = ''
  try {
    const response = await bypassApi.analyzeProtections(selectedAppId.value)
    detections.value = (response.data.detections || []).map((d: any) => ({
      ...d,
      bypass_status: null,
      bypass_notes: null,
    }))
    toast.add({
      severity: 'success',
      summary: 'Analysis Complete',
      detail: `Found ${detections.value.length} protection(s)`,
      life: 3000,
    })
  } catch (e: any) {
    const detail = e.response?.data?.detail || 'Failed to analyze protections'
    error.value = detail
    toast.add({ severity: 'error', summary: 'Error', detail, life: 3000 })
  } finally {
    analyzing.value = false
  }
}

async function attemptBypass(detection: any) {
  if (!selectedAppId.value || !selectedDeviceId.value) return
  bypassingType.value = detection.detection_type
  try {
    const response = await bypassApi.attemptBypass({
      app_id: selectedAppId.value,
      device_id: selectedDeviceId.value,
      detection_type: detection.detection_type,
    })
    const result = response.data
    detection.bypass_status = result.bypass_status
    detection.bypass_notes = result.bypass_notes || result.poc_evidence

    const severity = result.bypass_status === 'success' ? 'success'
      : result.bypass_status === 'partial' ? 'warn' : 'error'
    toast.add({
      severity,
      summary: `Bypass ${result.bypass_status}`,
      detail: `${formatDetectionType(detection.detection_type)}: ${result.bypass_status}`,
      life: 3000,
    })

    loadResults()
  } catch (e: any) {
    const detail = e.response?.data?.detail || 'Bypass attempt failed'
    detection.bypass_status = 'failed'
    detection.bypass_notes = detail
    toast.add({ severity: 'error', summary: 'Error', detail, life: 3000 })
  } finally {
    bypassingType.value = null
  }
}

async function autoBypassAll() {
  if (!selectedAppId.value || !selectedDeviceId.value) return
  autoBypassRunning.value = true
  autoBypassResults.value = null
  error.value = ''
  try {
    const response = await bypassApi.autoBypass(selectedAppId.value, selectedDeviceId.value)
    autoBypassResults.value = response.data

    // Update detection cards with results
    if (response.data.results) {
      for (const result of response.data.results) {
        const detection = detections.value.find(
          (d: any) => d.detection_type === result.detection_type
        )
        if (detection) {
          detection.bypass_status = result.bypass_status
          detection.bypass_notes = result.bypass_notes || result.poc_evidence
        }
      }
    }

    const summary = response.data.summary || {}
    toast.add({
      severity: summary.failed === 0 ? 'success' : 'warn',
      summary: 'Auto Bypass Complete',
      detail: `${summary.success} success, ${summary.partial} partial, ${summary.failed} failed`,
      life: 5000,
    })

    loadResults()
  } catch (e: any) {
    const detail = e.response?.data?.detail || 'Auto bypass failed'
    error.value = detail
    toast.add({ severity: 'error', summary: 'Error', detail, life: 3000 })
  } finally {
    autoBypassRunning.value = false
  }
}

// Helpers
function formatDetectionType(type: string): string {
  const map: Record<string, string> = {
    root: 'Root Detection',
    jailbreak: 'Jailbreak Detection',
    frida: 'Frida Detection',
    emulator: 'Emulator Detection',
    debugger: 'Debugger Detection',
    ssl_pinning: 'SSL Pinning',
  }
  return map[type] || type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())
}

function getDetectionIcon(type: string): string {
  const map: Record<string, string> = {
    root: 'pi pi-shield',
    jailbreak: 'pi pi-shield',
    frida: 'pi pi-code',
    emulator: 'pi pi-desktop',
    debugger: 'pi pi-bug',
    ssl_pinning: 'pi pi-lock',
  }
  return map[type] || 'pi pi-question-circle'
}

function formatConfidence(confidence: number | string): string {
  if (typeof confidence === 'number') {
    return `${Math.round(confidence * 100)}%`
  }
  return String(confidence)
}

function getConfidenceSeverity(confidence: number | string): string {
  const val = typeof confidence === 'number' ? confidence : parseFloat(String(confidence))
  if (val >= 0.8) return 'danger'
  if (val >= 0.5) return 'warn'
  return 'info'
}

function getDetectionStatusClass(detection: any): string {
  if (!detection.bypass_status) return ''
  return `status-${detection.bypass_status}`
}

function getBypassButtonLabel(detection: any): string {
  if (detection.bypass_status === 'success') return 'Bypassed'
  if (detection.bypass_status === 'partial') return 'Retry'
  if (detection.bypass_status === 'failed') return 'Retry'
  return 'Attempt Bypass'
}

function getBypassButtonIcon(detection: any): string {
  if (detection.bypass_status === 'success') return 'pi pi-check'
  if (detection.bypass_status === 'failed') return 'pi pi-replay'
  return 'pi pi-play'
}

function getBypassButtonSeverity(detection: any): string {
  if (detection.bypass_status === 'success') return 'success'
  if (detection.bypass_status === 'failed') return 'danger'
  return 'secondary'
}

function getBypassStatusSeverity(status: string): string {
  if (status === 'success') return 'success'
  if (status === 'partial') return 'warn'
  if (status === 'failed') return 'danger'
  return 'info'
}

function formatDate(date: string): string {
  if (!date) return ''
  return new Date(date).toLocaleString()
}
</script>

<style scoped>
.bypass-view {
  padding: 1rem;
  max-width: 1400px;
  margin: 0 auto;
}

.bypass-header {
  margin-bottom: var(--spacing-lg, 24px);
}

.bypass-header h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary, var(--text-color));
  margin: 0;
}

.bypass-header .subtitle {
  color: var(--text-secondary, var(--text-color-secondary));
  font-size: 0.875rem;
  margin-top: var(--spacing-xs, 4px);
}

/* Setup Section */
.setup-section {
  margin-bottom: var(--spacing-lg, 24px);
}

.setup-card {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius-md, 10px);
  padding: var(--spacing-lg, 24px);
}

.setup-row {
  display: flex;
  gap: var(--spacing-md, 16px);
  align-items: flex-end;
}

.field {
  flex: 1;
}

.field label {
  display: block;
  font-size: 0.875rem;
  font-weight: 500;
  color: var(--text-secondary, var(--text-color-secondary));
  margin-bottom: 0.5rem;
}

.actions-field {
  flex: 1.5;
}

.action-buttons {
  display: flex;
  gap: var(--spacing-sm, 8px);
}

/* Error Message */
.error-message {
  display: flex;
  align-items: center;
  gap: var(--spacing-md, 16px);
  padding: var(--spacing-md, 16px);
  background: rgba(231, 76, 60, 0.2);
  color: var(--text-primary, var(--text-color));
  border-radius: var(--radius-md, 10px);
  margin-bottom: var(--spacing-lg, 24px);
}

.error-message i {
  color: #e74c3c;
}

/* Detections Section */
.detections-section {
  margin-bottom: var(--spacing-lg, 24px);
}

.detections-section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-primary, var(--text-color));
  margin: 0 0 var(--spacing-md, 16px) 0;
}

.detections-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: var(--spacing-md, 16px);
}

.detection-card {
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius-md, 10px);
  padding: var(--spacing-md, 16px);
  transition: border-color 0.2s ease;
}

.detection-card.status-success {
  border-color: #27ae60;
}

.detection-card.status-partial {
  border-color: #f39c12;
}

.detection-card.status-failed {
  border-color: #e74c3c;
}

.detection-header {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm, 8px);
  margin-bottom: var(--spacing-sm, 8px);
}

.detection-icon {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 8px;
  background: var(--surface-100, rgba(99, 102, 241, 0.1));
}

.detection-icon i {
  font-size: 1.1rem;
  color: var(--primary-color);
}

.detection-info {
  flex: 1;
}

.detection-type {
  font-weight: 600;
  font-size: 0.95rem;
  color: var(--text-primary, var(--text-color));
}

.detection-method {
  font-size: 0.8rem;
  color: var(--text-secondary, var(--text-color-secondary));
}

.detection-library {
  font-size: 0.8rem;
  color: var(--text-secondary, var(--text-color-secondary));
  margin-bottom: var(--spacing-xs, 4px);
  display: flex;
  align-items: center;
  gap: 4px;
}

.detection-evidence {
  font-size: 0.8rem;
  color: var(--text-secondary, var(--text-color-secondary));
  background: var(--surface-ground, rgba(0,0,0,0.05));
  padding: var(--spacing-xs, 4px) var(--spacing-sm, 8px);
  border-radius: 4px;
  margin-bottom: var(--spacing-sm, 8px);
}

.detection-actions {
  display: flex;
  align-items: center;
  gap: var(--spacing-sm, 8px);
  margin-top: var(--spacing-sm, 8px);
}

.status-tag {
  font-size: 0.75rem;
}

.bypass-notes {
  margin-top: var(--spacing-sm, 8px);
  background: var(--surface-ground, rgba(0,0,0,0.05));
  border-radius: 4px;
  padding: var(--spacing-sm, 8px);
  max-height: 120px;
  overflow-y: auto;
}

.bypass-notes pre {
  margin: 0;
  font-size: 0.75rem;
  white-space: pre-wrap;
  word-break: break-word;
  color: var(--text-primary, var(--text-color));
}

/* Auto Bypass Summary */
.auto-bypass-section {
  margin-bottom: var(--spacing-lg, 24px);
}

.auto-bypass-section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-primary, var(--text-color));
  margin: 0 0 var(--spacing-md, 16px) 0;
}

.summary-cards {
  display: flex;
  gap: var(--spacing-md, 16px);
}

.summary-card {
  flex: 1;
  background: var(--surface-card);
  border: 1px solid var(--surface-border);
  border-radius: var(--radius-md, 10px);
  padding: var(--spacing-md, 16px);
  text-align: center;
}

.summary-value {
  font-size: 2rem;
  font-weight: 700;
}

.summary-label {
  font-size: 0.875rem;
  color: var(--text-secondary, var(--text-color-secondary));
  margin-top: 4px;
}

.summary-card.total .summary-value { color: var(--primary-color); }
.summary-card.success .summary-value { color: #27ae60; }
.summary-card.partial .summary-value { color: #f39c12; }
.summary-card.failed .summary-value { color: #e74c3c; }

/* Results Section */
.results-section {
  margin-bottom: var(--spacing-lg, 24px);
}

.results-section h3 {
  font-size: 1.25rem;
  font-weight: 600;
  color: var(--text-primary, var(--text-color));
  margin: 0 0 var(--spacing-md, 16px) 0;
}

.results-table {
  background: var(--surface-card);
  border-radius: var(--radius-md, 10px);
  overflow: hidden;
}

.type-cell {
  display: flex;
  align-items: center;
  gap: 8px;
}

.type-cell i {
  color: var(--primary-color);
}

.notes-cell {
  font-size: 0.85rem;
  color: var(--text-secondary, var(--text-color-secondary));
}

/* Dark mode dropdown fix */
:deep(.p-dropdown-panel) {
  background: var(--surface-overlay) !important;
}

:deep(.p-dropdown-items .p-dropdown-item) {
  color: var(--text-color) !important;
}

:deep(.p-dropdown-items .p-dropdown-item:hover) {
  background: var(--surface-hover) !important;
}

/* Responsive */
@media (max-width: 768px) {
  .setup-row {
    flex-direction: column;
  }

  .action-buttons {
    flex-direction: column;
  }

  .summary-cards {
    flex-wrap: wrap;
  }

  .summary-card {
    min-width: calc(50% - 8px);
  }

  .detections-grid {
    grid-template-columns: 1fr;
  }
}
</style>
