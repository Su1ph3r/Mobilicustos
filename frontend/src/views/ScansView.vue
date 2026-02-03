<template>
  <div class="scans-view">
    <div class="page-header">
      <div>
        <h1>Scans</h1>
        <p class="text-secondary">Security scan history and status</p>
      </div>
    </div>

    <!-- Filters -->
    <div class="card filters-card">
      <div class="filters-row">
        <Dropdown
          v-model="selectedStatus"
          :options="statusOptions"
          placeholder="All Statuses"
          showClear
          @change="applyFilters"
        />
        <Dropdown
          v-model="selectedScanType"
          :options="scanTypeOptions"
          placeholder="All Types"
          showClear
          @change="applyFilters"
        />
      </div>
    </div>

    <!-- Scans Table -->
    <div class="card">
      <DataTable
        :value="scansStore.scans"
        :loading="scansStore.loading"
        responsiveLayout="scroll"
        :paginator="true"
        :rows="scansStore.pagination.pageSize"
        :totalRecords="scansStore.pagination.total"
        :lazy="true"
        @page="onPage"
      >
        <Column field="scan_id" header="Scan ID">
          <template #body="{ data }">
            <router-link :to="`/scans/${data.scan_id}`" class="scan-link">
              {{ data.scan_id.substring(0, 8) }}...
            </router-link>
          </template>
        </Column>
        <Column field="app_id" header="Application">
          <template #body="{ data }">
            <router-link :to="`/apps/${data.app_id}`" class="app-link">
              {{ data.app_id.substring(0, 8) }}...
            </router-link>
          </template>
        </Column>
        <Column field="scan_type" header="Type">
          <template #body="{ data }">
            <Tag :value="data.scan_type" :severity="getScanTypeSeverity(data.scan_type)" />
          </template>
        </Column>
        <Column field="status" header="Status">
          <template #body="{ data }">
            <div class="status-cell">
              <Tag :value="data.status" :severity="getStatusSeverity(data.status)" />
              <ProgressBar
                v-if="data.status === 'running'"
                :value="data.progress"
                :showValue="false"
                style="height: 6px; width: 80px"
              />
            </div>
          </template>
        </Column>
        <Column field="current_analyzer" header="Current Task">
          <template #body="{ data }">
            <span v-if="data.current_analyzer">{{ data.current_analyzer }}</span>
            <span v-else class="text-secondary">-</span>
          </template>
        </Column>
        <Column header="Findings">
          <template #body="{ data }">
            <div class="findings-summary">
              <span v-if="data.findings_count.critical" class="finding-badge critical">
                {{ data.findings_count.critical }}
              </span>
              <span v-if="data.findings_count.high" class="finding-badge high">
                {{ data.findings_count.high }}
              </span>
              <span v-if="data.findings_count.medium" class="finding-badge medium">
                {{ data.findings_count.medium }}
              </span>
              <span v-if="data.findings_count.low" class="finding-badge low">
                {{ data.findings_count.low }}
              </span>
              <span v-if="data.findings_count.info" class="finding-badge info">
                {{ data.findings_count.info }}
              </span>
              <span v-if="getTotalFindings(data) === 0" class="text-secondary">-</span>
            </div>
          </template>
        </Column>
        <Column field="started_at" header="Started">
          <template #body="{ data }">
            {{ data.started_at ? formatDate(data.started_at) : '-' }}
          </template>
        </Column>
        <Column header="Actions" style="width: 120px">
          <template #body="{ data }">
            <div class="action-buttons">
              <Button
                v-if="data.status === 'running'"
                icon="pi pi-stop"
                class="p-button-sm p-button-danger p-button-text"
                v-tooltip="'Cancel Scan'"
                @click="cancelScan(data)"
              />
              <Button
                v-if="data.status === 'running'"
                icon="pi pi-refresh"
                class="p-button-sm p-button-text"
                v-tooltip="'Refresh Progress'"
                @click="refreshProgress(data)"
              />
              <Button
                icon="pi pi-eye"
                class="p-button-sm p-button-text"
                v-tooltip="'View Details'"
                @click="$router.push(`/scans/${data.scan_id}`)"
              />
              <Button
                v-if="data.status !== 'running'"
                icon="pi pi-trash"
                class="p-button-sm p-button-danger p-button-text"
                v-tooltip="'Delete'"
                @click="confirmDelete(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </div>

    <ConfirmDialog />
    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useScansStore, type Scan } from '@/stores/scans'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import ProgressBar from 'primevue/progressbar'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'

const scansStore = useScansStore()
const confirm = useConfirm()
const toast = useToast()

const selectedStatus = ref<string | null>(null)
const selectedScanType = ref<string | null>(null)

let refreshInterval: number | null = null

const statusOptions = [
  { label: 'Pending', value: 'pending' },
  { label: 'Running', value: 'running' },
  { label: 'Completed', value: 'completed' },
  { label: 'Failed', value: 'failed' },
  { label: 'Cancelled', value: 'cancelled' },
]

const scanTypeOptions = [
  { label: 'Static', value: 'static' },
  { label: 'Dynamic', value: 'dynamic' },
  { label: 'Full', value: 'full' },
]

function getScanTypeSeverity(type: string) {
  switch (type) {
    case 'full': return 'danger'
    case 'dynamic': return 'warning'
    case 'static': return 'info'
    default: return 'secondary'
  }
}

function getStatusSeverity(status: string) {
  switch (status) {
    case 'completed': return 'success'
    case 'running': return 'info'
    case 'failed': return 'danger'
    case 'cancelled': return 'warning'
    default: return 'secondary'
  }
}

function getTotalFindings(scan: Scan) {
  return Object.values(scan.findings_count).reduce((a, b) => a + b, 0)
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

function applyFilters() {
  scansStore.setFilters({
    status: selectedStatus.value,
    scan_type: selectedScanType.value,
  })
}

function onPage(event: { page: number }) {
  scansStore.setPage(event.page + 1)
}

async function cancelScan(scan: Scan) {
  try {
    await scansStore.cancelScan(scan.scan_id)
    toast.add({ severity: 'success', summary: 'Cancelled', detail: 'Scan cancelled', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to cancel scan', life: 3000 })
  }
}

async function refreshProgress(scan: Scan) {
  await scansStore.refreshScanProgress(scan.scan_id)
}

function confirmDelete(scan: Scan) {
  confirm.require({
    message: 'Are you sure you want to delete this scan?',
    header: 'Delete Scan',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await scansStore.deleteScan(scan.scan_id)
        toast.add({ severity: 'success', summary: 'Deleted', detail: 'Scan deleted', life: 2000 })
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete scan', life: 3000 })
      }
    },
  })
}

function startAutoRefresh() {
  refreshInterval = window.setInterval(async () => {
    const runningScans = scansStore.scans.filter((s) => s.status === 'running')
    for (const scan of runningScans) {
      await scansStore.refreshScanProgress(scan.scan_id)
    }
  }, 5000)
}

onMounted(() => {
  scansStore.fetchScans()
  startAutoRefresh()
})

onUnmounted(() => {
  if (refreshInterval) {
    clearInterval(refreshInterval)
  }
})
</script>

<style scoped>
.scans-view {
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

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  margin-bottom: 1rem;
}

.filters-card {
  padding: 1rem;
}

.filters-row {
  display: flex;
  gap: 1rem;
}

.scan-link,
.app-link {
  color: var(--primary-color);
  text-decoration: none;
  font-family: monospace;
}

.status-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.findings-summary {
  display: flex;
  gap: 0.25rem;
}

.finding-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 20px;
  height: 20px;
  padding: 0 6px;
  border-radius: 10px;
  font-size: 0.75rem;
  font-weight: 600;
  color: white;
}

.finding-badge.critical { background: #dc3545; }
.finding-badge.high { background: #fd7e14; }
.finding-badge.medium { background: #ffc107; color: #212529; }
.finding-badge.low { background: #28a745; }
.finding-badge.info { background: #6c757d; }

.action-buttons {
  display: flex;
  gap: 0.25rem;
}
</style>
