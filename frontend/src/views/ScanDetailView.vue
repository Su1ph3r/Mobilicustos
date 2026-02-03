<template>
  <div class="scan-detail-view">
    <div class="page-header">
      <div class="header-content">
        <Button icon="pi pi-arrow-left" class="p-button-text" @click="$router.back()" />
        <div>
          <h1>Scan Details</h1>
          <p class="text-secondary">{{ scan?.scan_id }}</p>
        </div>
      </div>
      <div class="header-actions">
        <Button
          v-if="scan?.status === 'running'"
          label="Cancel Scan"
          icon="pi pi-stop"
          class="p-button-danger"
          @click="cancelScan"
        />
        <Button
          v-if="scan?.status === 'completed'"
          label="View Findings"
          icon="pi pi-flag"
          @click="viewFindings"
        />
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <ProgressSpinner />
    </div>

    <div v-else-if="scan" class="grid">
      <!-- Status Card -->
      <div class="col-12 lg:col-4">
        <div class="card status-card">
          <div class="status-indicator" :class="scan.status">
            <i :class="getStatusIcon(scan.status)"></i>
          </div>
          <h2>{{ formatStatus(scan.status) }}</h2>
          <ProgressBar
            v-if="scan.status === 'running'"
            :value="scan.progress"
            :showValue="true"
            class="progress-bar"
          />
          <div v-if="scan.current_analyzer" class="current-task">
            Currently: {{ scan.current_analyzer }}
          </div>
          <div class="scan-meta">
            <Tag :value="scan.scan_type" :severity="getScanTypeSeverity(scan.scan_type)" />
          </div>
        </div>
      </div>

      <!-- Findings Summary -->
      <div class="col-12 lg:col-8">
        <div class="card">
          <h3>Findings Summary</h3>
          <div class="findings-grid">
            <div class="finding-stat critical">
              <span class="finding-count">{{ scan.findings_count.critical }}</span>
              <span class="finding-label">Critical</span>
            </div>
            <div class="finding-stat high">
              <span class="finding-count">{{ scan.findings_count.high }}</span>
              <span class="finding-label">High</span>
            </div>
            <div class="finding-stat medium">
              <span class="finding-count">{{ scan.findings_count.medium }}</span>
              <span class="finding-label">Medium</span>
            </div>
            <div class="finding-stat low">
              <span class="finding-count">{{ scan.findings_count.low }}</span>
              <span class="finding-label">Low</span>
            </div>
            <div class="finding-stat info">
              <span class="finding-count">{{ scan.findings_count.info }}</span>
              <span class="finding-label">Info</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Scan Information -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3>Scan Information</h3>
          <div class="info-list">
            <div class="info-item">
              <span class="info-label">Scan ID</span>
              <span class="info-value mono">{{ scan.scan_id }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Application</span>
              <router-link :to="`/apps/${scan.app_id}`" class="info-value link">
                {{ scan.app_id }}
              </router-link>
            </div>
            <div class="info-item">
              <span class="info-label">Type</span>
              <span class="info-value">{{ scan.scan_type }}</span>
            </div>
            <div class="info-item">
              <span class="info-label">Created</span>
              <span class="info-value">{{ formatDate(scan.created_at) }}</span>
            </div>
            <div v-if="scan.started_at" class="info-item">
              <span class="info-label">Started</span>
              <span class="info-value">{{ formatDate(scan.started_at) }}</span>
            </div>
            <div v-if="scan.completed_at" class="info-item">
              <span class="info-label">Completed</span>
              <span class="info-value">{{ formatDate(scan.completed_at) }}</span>
            </div>
            <div v-if="scan.started_at && scan.completed_at" class="info-item">
              <span class="info-label">Duration</span>
              <span class="info-value">{{ calculateDuration(scan.started_at, scan.completed_at) }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Analyzers -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3>Analyzers</h3>
          <div class="analyzers-list">
            <div
              v-for="analyzer in scan.analyzers_enabled"
              :key="analyzer"
              :class="['analyzer-item', getAnalyzerStatus(analyzer)]"
            >
              <i :class="getAnalyzerIcon(analyzer)"></i>
              <span class="analyzer-name">{{ formatAnalyzerName(analyzer) }}</span>
              <Tag
                :value="getAnalyzerStatusLabel(analyzer)"
                :severity="getAnalyzerStatusSeverity(analyzer)"
              />
            </div>
          </div>
        </div>
      </div>

      <!-- Error Section -->
      <div v-if="scan.error_message || (scan.analyzer_errors && scan.analyzer_errors.length > 0)" class="col-12">
        <div class="card error-card">
          <h3><i class="pi pi-exclamation-triangle"></i> Errors</h3>
          <div v-if="scan.error_message" class="main-error">
            {{ scan.error_message }}
          </div>
          <div v-if="scan.analyzer_errors && scan.analyzer_errors.length > 0" class="analyzer-errors">
            <div v-for="(error, index) in scan.analyzer_errors" :key="index" class="error-item">
              <strong>{{ error.analyzer }}:</strong> {{ error.error }}
            </div>
          </div>
        </div>
      </div>
    </div>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useScansStore } from '@/stores/scans'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import ProgressBar from 'primevue/progressbar'
import ProgressSpinner from 'primevue/progressspinner'
import Toast from 'primevue/toast'

const route = useRoute()
const router = useRouter()
const scansStore = useScansStore()
const toast = useToast()

const loading = ref(true)
let refreshInterval: number | null = null

const scan = computed(() => scansStore.currentScan)

function getStatusIcon(status: string) {
  switch (status) {
    case 'completed': return 'pi pi-check-circle'
    case 'running': return 'pi pi-spin pi-spinner'
    case 'failed': return 'pi pi-times-circle'
    case 'cancelled': return 'pi pi-ban'
    default: return 'pi pi-clock'
  }
}

function formatStatus(status: string) {
  return status.charAt(0).toUpperCase() + status.slice(1)
}

function getScanTypeSeverity(type: string) {
  switch (type) {
    case 'full': return 'danger'
    case 'dynamic': return 'warning'
    case 'static': return 'info'
    default: return 'secondary'
  }
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

function calculateDuration(start: string, end: string) {
  const startDate = new Date(start)
  const endDate = new Date(end)
  const diffMs = endDate.getTime() - startDate.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffSecs = Math.floor((diffMs % 60000) / 1000)
  if (diffMins > 0) {
    return `${diffMins}m ${diffSecs}s`
  }
  return `${diffSecs}s`
}

function formatAnalyzerName(analyzer: string) {
  return analyzer.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())
}

function getAnalyzerIcon(analyzer: string) {
  if (analyzer.includes('manifest')) return 'pi pi-file'
  if (analyzer.includes('dex')) return 'pi pi-code'
  if (analyzer.includes('secret')) return 'pi pi-key'
  if (analyzer.includes('frida')) return 'pi pi-bolt'
  return 'pi pi-cog'
}

function getAnalyzerStatus(analyzer: string) {
  if (!scan.value) return 'pending'
  if (scan.value.analyzer_errors?.some((e) => e.analyzer === analyzer)) return 'error'
  if (scan.value.current_analyzer === analyzer) return 'running'
  if (scan.value.status === 'completed') return 'completed'
  return 'pending'
}

function getAnalyzerStatusLabel(analyzer: string) {
  const status = getAnalyzerStatus(analyzer)
  return status.charAt(0).toUpperCase() + status.slice(1)
}

function getAnalyzerStatusSeverity(analyzer: string) {
  const status = getAnalyzerStatus(analyzer)
  switch (status) {
    case 'completed': return 'success'
    case 'running': return 'info'
    case 'error': return 'danger'
    default: return 'secondary'
  }
}

async function cancelScan() {
  if (!scan.value) return
  try {
    await scansStore.cancelScan(scan.value.scan_id)
    toast.add({ severity: 'success', summary: 'Cancelled', detail: 'Scan cancelled', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to cancel', life: 3000 })
  }
}

function viewFindings() {
  if (!scan.value) return
  router.push({ path: '/findings', query: { scan_id: scan.value.scan_id } })
}

function startAutoRefresh() {
  refreshInterval = window.setInterval(async () => {
    if (scan.value?.status === 'running') {
      await scansStore.refreshScanProgress(scan.value.scan_id)
    }
  }, 3000)
}

onMounted(async () => {
  const scanId = route.params.id as string
  loading.value = true
  try {
    await scansStore.fetchScan(scanId)
  } finally {
    loading.value = false
  }
  startAutoRefresh()
})

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
})
</script>

<style scoped>
.scan-detail-view {
  padding: 1rem;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
}

.header-content {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.page-header h1 {
  margin: 0;
  font-size: 1.75rem;
}

.text-secondary {
  color: var(--text-color-secondary);
  margin: 0;
  font-family: monospace;
  font-size: 0.85rem;
}

.header-actions {
  display: flex;
  gap: 0.5rem;
}

.loading-state {
  display: flex;
  justify-content: center;
  padding: 3rem;
}

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  height: 100%;
}

.card h3 {
  margin: 0 0 1rem;
  font-size: 1.1rem;
}

.status-card {
  text-align: center;
}

.status-indicator {
  width: 80px;
  height: 80px;
  margin: 0 auto 1rem;
  border-radius: 50%;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 2.5rem;
  color: white;
}

.status-indicator.completed { background: #28a745; }
.status-indicator.running { background: #007bff; }
.status-indicator.failed { background: #dc3545; }
.status-indicator.cancelled { background: #ffc107; color: #212529; }
.status-indicator.pending { background: #6c757d; }

.status-card h2 {
  margin: 0 0 1rem;
}

.progress-bar {
  margin-bottom: 1rem;
}

.current-task {
  font-size: 0.9rem;
  color: var(--text-color-secondary);
  margin-bottom: 1rem;
}

.scan-meta {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
}

.findings-grid {
  display: grid;
  grid-template-columns: repeat(5, 1fr);
  gap: 1rem;
}

.finding-stat {
  text-align: center;
  padding: 1rem;
  border-radius: 8px;
  color: white;
}

.finding-stat.critical { background: linear-gradient(135deg, #dc3545, #c82333); }
.finding-stat.high { background: linear-gradient(135deg, #fd7e14, #e8590c); }
.finding-stat.medium { background: linear-gradient(135deg, #ffc107, #e0a800); color: #212529; }
.finding-stat.low { background: linear-gradient(135deg, #28a745, #1e7e34); }
.finding-stat.info { background: linear-gradient(135deg, #6c757d, #5a6268); }

.finding-count {
  display: block;
  font-size: 2rem;
  font-weight: 700;
}

.finding-label {
  font-size: 0.8rem;
}

.info-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.info-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.info-label {
  color: var(--text-color-secondary);
}

.info-value {
  font-weight: 500;
}

.info-value.mono {
  font-family: monospace;
  font-size: 0.85rem;
}

.info-value.link {
  color: var(--primary-color);
  text-decoration: none;
}

.analyzers-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.analyzer-item {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.analyzer-item i {
  font-size: 1.25rem;
  color: var(--primary-color);
}

.analyzer-name {
  flex: 1;
}

.error-card {
  border-left: 4px solid #dc3545;
}

.error-card h3 {
  color: #dc3545;
}

.error-card h3 i {
  margin-right: 0.5rem;
}

.main-error {
  padding: 1rem;
  background: rgba(220, 53, 69, 0.1);
  border-radius: 4px;
  margin-bottom: 1rem;
}

.analyzer-errors {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.error-item {
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
  font-size: 0.9rem;
}

@media (max-width: 768px) {
  .findings-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>
