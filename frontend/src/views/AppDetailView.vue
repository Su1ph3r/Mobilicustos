<template>
  <div class="app-detail-view">
    <div class="page-header">
      <div class="header-content">
        <Button icon="pi pi-arrow-left" class="p-button-text" v-tooltip="'Go Back'" @click="$router.back()" />
        <div>
          <h1>{{ app?.app_name || app?.package_name || 'Application Details' }}</h1>
          <p class="text-secondary">{{ app?.package_name }}</p>
        </div>
      </div>
      <div class="header-actions">
        <Button label="Start Scan" icon="pi pi-search" @click="showScanDialog = true" />
        <Button label="Delete" icon="pi pi-trash" class="p-button-danger" @click="confirmDelete" />
      </div>
    </div>

    <div v-if="loading" class="loading-state">
      <ProgressSpinner />
    </div>

    <div v-else-if="app" class="grid">
      <!-- App Info Card -->
      <div class="col-12 lg:col-4">
        <div class="card info-card">
          <div class="app-icon">
            <i :class="app.platform === 'android' ? 'pi pi-android' : 'pi pi-apple'"></i>
          </div>
          <h2>{{ app.app_name || app.package_name }}</h2>
          <div class="app-version">
            v{{ app.version_name || '1.0' }}
            <span v-if="app.version_code">({{ app.version_code }})</span>
          </div>
          <div class="app-tags">
            <Tag :value="app.platform" :severity="app.platform === 'android' ? 'success' : 'info'" />
            <Tag v-if="app.framework" :value="app.framework" severity="secondary" />
            <Tag :value="app.status" :severity="getStatusSeverity(app.status)" />
          </div>
        </div>
      </div>

      <!-- Stats Card -->
      <div class="col-12 lg:col-8">
        <div class="card stats-card">
          <h3>Security Overview</h3>
          <div v-if="stats" class="stats-grid">
            <div class="stat-item">
              <span class="stat-value">{{ stats.scan_count }}</span>
              <span class="stat-label">Scans</span>
            </div>
            <div class="stat-item">
              <span class="stat-value">{{ stats.total_findings }}</span>
              <span class="stat-label">Findings</span>
            </div>
            <div class="stat-item critical">
              <span class="stat-value">{{ stats.findings_by_severity?.critical || 0 }}</span>
              <span class="stat-label">Critical</span>
            </div>
            <div class="stat-item high">
              <span class="stat-value">{{ stats.findings_by_severity?.high || 0 }}</span>
              <span class="stat-label">High</span>
            </div>
            <div class="stat-item medium">
              <span class="stat-value">{{ stats.findings_by_severity?.medium || 0 }}</span>
              <span class="stat-label">Medium</span>
            </div>
            <div class="stat-item low">
              <span class="stat-value">{{ stats.findings_by_severity?.low || 0 }}</span>
              <span class="stat-label">Low</span>
            </div>
          </div>
          <div v-else class="empty-stats">
            <p>No scans performed yet</p>
            <Button label="Start First Scan" icon="pi pi-search" @click="showScanDialog = true" />
          </div>
        </div>
      </div>

      <!-- Technical Details -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3>Technical Details</h3>
          <div class="detail-list">
            <div class="detail-item">
              <span class="detail-label">Package Name</span>
              <span class="detail-value">{{ app.package_name }}</span>
            </div>
            <div v-if="app.platform === 'android'" class="detail-item">
              <span class="detail-label">Min SDK</span>
              <span class="detail-value">{{ app.min_sdk_version || 'N/A' }}</span>
            </div>
            <div v-if="app.platform === 'android'" class="detail-item">
              <span class="detail-label">Target SDK</span>
              <span class="detail-value">{{ app.target_sdk_version || 'N/A' }}</span>
            </div>
            <div v-if="app.platform === 'ios'" class="detail-item">
              <span class="detail-label">Min iOS Version</span>
              <span class="detail-value">{{ app.min_ios_version || 'N/A' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Framework</span>
              <span class="detail-value">{{ app.framework || 'Native' }}</span>
            </div>
            <div v-if="app.framework_version" class="detail-item">
              <span class="detail-label">Framework Version</span>
              <span class="detail-value">{{ app.framework_version }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">File Size</span>
              <span class="detail-value">{{ formatFileSize(app.file_size_bytes) }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">SHA-256</span>
              <span class="detail-value hash">{{ app.file_hash_sha256 || 'N/A' }}</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Signing Info -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <h3>Signing Information</h3>
          <div v-if="app.signing_info && Object.keys(app.signing_info).length > 0" class="detail-list">
            <div v-for="(value, key) in app.signing_info" :key="key" class="detail-item">
              <span class="detail-label">{{ formatKey(key) }}</span>
              <span class="detail-value">{{ value }}</span>
            </div>
          </div>
          <div v-else class="empty-state-small">
            No signing information available
          </div>
        </div>
      </div>

      <!-- Framework Details -->
      <div v-if="app.framework && app.framework_details" class="col-12">
        <div class="card">
          <h3>Framework Details</h3>
          <div class="framework-details">
            <pre>{{ JSON.stringify(app.framework_details, null, 2) }}</pre>
          </div>
        </div>
      </div>

      <!-- Findings by Category -->
      <div v-if="stats && stats.findings_by_category" class="col-12">
        <div class="card">
          <h3>Findings by Category</h3>
          <div class="category-bars">
            <div v-for="(count, category) in stats.findings_by_category" :key="category" class="category-bar">
              <span class="category-name">{{ category }}</span>
              <div class="bar-container">
                <div class="bar" :style="{ width: getCategoryWidth(count) + '%' }"></div>
              </div>
              <span class="category-count">{{ count }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Scan Dialog -->
    <Dialog
      v-model:visible="showScanDialog"
      header="Start Security Scan"
      :modal="true"
      :style="{ width: '500px' }"
    >
      <div class="scan-options">
        <div class="field">
          <label>Scan Type</label>
          <div class="scan-type-options">
            <div
              v-for="type in scanTypes"
              :key="type.value"
              :class="['scan-type-option', { selected: selectedScanType === type.value }]"
              @click="selectedScanType = type.value"
            >
              <i :class="type.icon"></i>
              <div>
                <div class="option-label">{{ type.label }}</div>
                <div class="option-desc">{{ type.description }}</div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" class="p-button-text" @click="showScanDialog = false" />
        <Button label="Start Scan" icon="pi pi-play" @click="startScan" />
      </template>
    </Dialog>

    <ConfirmDialog />
    <Toast />
  </div>
</template>

<script setup lang="ts">
/**
 * AppDetailView - Single application detail page with security overview and scan controls.
 *
 * Features:
 * - App identity card with platform, framework, and status tags
 * - Security overview grid showing scan count and findings by severity
 * - Technical details (package name, SDK versions, file size, SHA-256 hash)
 * - Signing information display
 * - Framework details (for cross-platform apps)
 * - Findings by category bar chart
 * - Scan initiation dialog and app deletion with confirmation
 *
 * @requires useAppsStore - fetches app details and per-app statistics
 * @requires useScansStore - creates scans for the current application
 */
import { ref, computed, onMounted } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useAppsStore } from '@/stores/apps'
import { useScansStore } from '@/stores/scans'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dialog from 'primevue/dialog'
import ProgressSpinner from 'primevue/progressspinner'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'

const route = useRoute()
const router = useRouter()
const appsStore = useAppsStore()
const scansStore = useScansStore()
const confirm = useConfirm()
const toast = useToast()

const loading = ref(true)
const showScanDialog = ref(false)
const selectedScanType = ref('static')

const app = computed(() => appsStore.currentApp)
const stats = computed(() => appsStore.currentAppStats)

const scanTypes = [
  { value: 'static', label: 'Static Analysis', icon: 'pi pi-file-edit', description: 'Analyze app without running it' },
  { value: 'dynamic', label: 'Dynamic Analysis', icon: 'pi pi-play', description: 'Runtime analysis with Frida' },
  { value: 'full', label: 'Full Analysis', icon: 'pi pi-check-circle', description: 'Complete static + dynamic analysis' },
]

function getStatusSeverity(status: string) {
  switch (status) {
    case 'ready': return 'success'
    case 'processing': return 'info'
    case 'error': return 'danger'
    default: return 'secondary'
  }
}

function formatFileSize(bytes: number | null) {
  if (!bytes) return 'N/A'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  while (bytes >= 1024 && i < units.length - 1) {
    bytes /= 1024
    i++
  }
  return `${bytes.toFixed(1)} ${units[i]}`
}

function formatKey(key: string) {
  return key.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())
}

function getCategoryWidth(count: number) {
  if (!stats.value || !stats.value.findings_by_category) return 0
  const values = Object.values(stats.value.findings_by_category)
  if (values.length === 0) return 0
  const maxCount = Math.max(...values)
  if (maxCount === 0) return 0
  return (count / maxCount) * 100
}

async function startScan() {
  if (!app.value) return

  try {
    await scansStore.createScan({
      app_id: app.value.app_id,
      scan_type: selectedScanType.value,
    })
    toast.add({ severity: 'success', summary: 'Success', detail: 'Scan started', life: 3000 })
    showScanDialog.value = false
    router.push('/scans')
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to start scan', life: 3000 })
  }
}

function confirmDelete() {
  confirm.require({
    message: `Are you sure you want to delete ${app.value?.app_name || 'this app'}?`,
    header: 'Delete Application',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await appsStore.deleteApp(app.value!.app_id)
        toast.add({ severity: 'success', summary: 'Deleted', detail: 'App deleted', life: 2000 })
        router.push('/apps')
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete', life: 3000 })
      }
    },
  })
}

onMounted(async () => {
  const appId = route.params.id as string
  loading.value = true
  try {
    await Promise.all([
      appsStore.fetchApp(appId),
      appsStore.fetchAppStats(appId),
    ])
  } finally {
    loading.value = false
  }
})
</script>

<style scoped>
.app-detail-view {
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

.info-card {
  text-align: center;
}

.app-icon {
  width: 80px;
  height: 80px;
  margin: 0 auto 1rem;
  border-radius: 20px;
  background: var(--primary-color);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 2.5rem;
}

.info-card h2 {
  margin: 0 0 0.25rem;
  font-size: 1.25rem;
}

.app-version {
  color: var(--text-color-secondary);
  margin-bottom: 1rem;
}

.app-tags {
  display: flex;
  justify-content: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.stats-card h3 {
  margin-bottom: 1.5rem;
}

.stats-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 1rem;
}

.stat-item {
  text-align: center;
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
}

.stat-value {
  display: block;
  font-size: 1.5rem;
  font-weight: 700;
  color: var(--primary-color);
}

.stat-item.critical .stat-value { color: #dc3545; }
.stat-item.high .stat-value { color: #fd7e14; }
.stat-item.medium .stat-value { color: #ffc107; }
.stat-item.low .stat-value { color: #28a745; }

.stat-label {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.empty-stats {
  text-align: center;
  padding: 2rem;
}

.empty-stats p {
  color: var(--text-color-secondary);
  margin-bottom: 1rem;
}

.detail-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.detail-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.detail-label {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.detail-value {
  font-weight: 500;
  text-align: right;
  word-break: break-all;
}

.detail-value.hash {
  font-family: monospace;
  font-size: 0.75rem;
  max-width: 200px;
  overflow: hidden;
  text-overflow: ellipsis;
}

.empty-state-small {
  text-align: center;
  padding: 1rem;
  color: var(--text-color-secondary);
}

.framework-details pre {
  background: var(--surface-ground);
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.85rem;
}

.category-bars {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.category-bar {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.category-name {
  width: 150px;
  font-size: 0.85rem;
}

.bar-container {
  flex: 1;
  height: 8px;
  background: var(--surface-ground);
  border-radius: 4px;
  overflow: hidden;
}

.bar {
  height: 100%;
  background: var(--primary-color);
  border-radius: 4px;
}

.category-count {
  width: 40px;
  text-align: right;
  font-weight: 600;
}

.scan-options .field {
  margin-bottom: 1rem;
}

.scan-options label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 600;
}

.scan-type-options {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.scan-type-option {
  display: flex;
  align-items: center;
  gap: 1rem;
  padding: 1rem;
  border: 1px solid var(--surface-border);
  border-radius: 8px;
  cursor: pointer;
  transition: all 0.2s;
}

.scan-type-option:hover {
  border-color: var(--primary-color);
}

.scan-type-option.selected {
  border-color: var(--primary-color);
  background: rgba(var(--primary-color-rgb), 0.1);
}

.scan-type-option i {
  font-size: 1.5rem;
  color: var(--primary-color);
}

.option-label {
  font-weight: 600;
}

.option-desc {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

@media (max-width: 992px) {
  .stats-grid {
    grid-template-columns: repeat(3, 1fr);
  }
}
</style>
