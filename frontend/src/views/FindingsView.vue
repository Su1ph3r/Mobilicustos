<template>
  <div class="findings-view">
    <div class="findings-header">
      <div class="header-content">
        <h2>Security Findings</h2>
        <p class="subtitle">
          {{ findingsStore.pagination.total }} findings
          <span v-if="findingsStore.hasFilters">(filtered)</span>
        </p>
      </div>
      <div class="header-actions">
        <SplitButton
          label="Export CSV"
          icon="pi pi-download"
          severity="secondary"
          @click="exportFindings('csv')"
          :model="exportMenuItems"
        />
        <Button
          label="Purge All"
          icon="pi pi-trash"
          severity="danger"
          @click="confirmPurge"
        />
      </div>
    </div>

    <FindingFilters @filter-change="handleFilterChange" />

    <div v-if="findingsStore.error" class="error-message">
      <i class="pi pi-exclamation-triangle" />
      {{ findingsStore.error }}
      <Button label="Retry" size="small" @click="loadFindings" />
    </div>

    <FindingsTable
      :findings="findingsStore.findings"
      :total="findingsStore.pagination.total"
      :page="findingsStore.pagination.page"
      :page-size="findingsStore.pagination.pageSize"
      :loading="findingsStore.loading"
      :has-filters="findingsStore.hasFilters"
      :sort-field="findingsStore.sorting.sortBy"
      :sort-order="findingsStore.sorting.sortOrder === 'asc' ? 1 : -1"
      @page-change="handlePageChange"
      @sort-change="handleSortChange"
    />

    <ConfirmDialog />
  </div>
</template>

<script setup lang="ts">
/**
 * FindingsView - Security findings browser with filtering, sorting, and multi-format export.
 *
 * Features:
 * - Paginated and sortable findings table via FindingsTable component
 * - Advanced filter panel (severity, status, app, category) via FindingFilters
 * - Export to CSV, JSON, HTML, PDF, and SARIF formats
 * - Bulk purge of findings per application with confirmation
 * - Query-param driven severity filter (e.g., from dashboard click-through)
 *
 * @requires useFindingsStore - manages findings state, pagination, filters, and sorting
 * @requires exportsApi - downloads findings in various export formats
 * @requires findingsApi - purge endpoint for bulk deletion
 */
import { onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useFindingsStore } from '@/stores/findings'
import { exportsApi, findingsApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import { useConfirm } from 'primevue/useconfirm'
import Button from 'primevue/button'
import SplitButton from 'primevue/splitbutton'
import ConfirmDialog from 'primevue/confirmdialog'
import FindingFilters from '@/components/findings/FindingFilters.vue'
import FindingsTable from '@/components/findings/FindingsTable.vue'

const route = useRoute()
const findingsStore = useFindingsStore()
const toast = useToast()
const confirm = useConfirm()

const loadFindings = () => {
  findingsStore.fetchFindings()
}

const handleFilterChange = () => {
  loadFindings()
}

const handlePageChange = ({ page, pageSize }: { page: number; pageSize: number }) => {
  if (pageSize !== findingsStore.pagination.pageSize) {
    findingsStore.setPageSize(pageSize)
  } else if (page !== findingsStore.pagination.page) {
    findingsStore.setPage(page)
  }
}

const handleSortChange = ({ field, order }: { field: string; order: number }) => {
  findingsStore.setSort(field, order === 1 ? 'asc' : 'desc')
}

const formatMimeTypes: Record<string, string> = {
  csv: 'text/csv',
  json: 'application/json',
  html: 'text/html',
  pdf: 'application/pdf',
  sarif: 'application/json',
}

const exportMenuItems = [
  { label: 'CSV', icon: 'pi pi-file', command: () => exportFindings('csv') },
  { label: 'JSON', icon: 'pi pi-file', command: () => exportFindings('json') },
  { label: 'HTML Report', icon: 'pi pi-globe', command: () => exportFindings('html') },
  { label: 'PDF Report', icon: 'pi pi-file-pdf', command: () => exportFindings('pdf') },
  { label: 'SARIF', icon: 'pi pi-code', command: () => exportFindings('sarif') },
]

const exportFindings = async (format: string) => {
  try {
    const appId = findingsStore.filters.app_id || 'all'

    const exportParams: Record<string, any> = {}
    if (findingsStore.filters.severity?.length) {
      exportParams.severity = findingsStore.filters.severity
    }
    if (findingsStore.filters.status?.length) {
      exportParams.status = findingsStore.filters.status
    }

    const response = await exportsApi.exportFindings(appId, format, exportParams)

    const mimeType = formatMimeTypes[format] || 'application/octet-stream'
    const blob = new Blob([response.data], { type: mimeType })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    const ext = format === 'sarif' ? 'sarif' : format
    link.download = appId === 'all' ? `all_findings.${ext}` : `${appId}_findings.${ext}`
    link.click()
    window.URL.revokeObjectURL(url)

    toast.add({ severity: 'success', summary: 'Exported', detail: `Findings exported as ${format.toUpperCase()}`, life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Export failed', life: 3000 })
  }
}

const confirmPurge = () => {
  const appId = findingsStore.filters.app_id || 'all'
  confirm.require({
    message: `Are you sure you want to delete ALL findings${appId !== 'all' ? ` for app ${appId.substring(0, 8)}...` : ''}? This action cannot be undone.`,
    header: 'Purge All Findings',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        if (!findingsStore.filters.app_id) {
          toast.add({ severity: 'warn', summary: 'Warning', detail: 'Please select an app to purge findings for', life: 3000 })
          return
        }
        const response = await findingsApi.purge(findingsStore.filters.app_id)
        toast.add({ severity: 'success', summary: 'Purged', detail: response.data.message, life: 3000 })
        loadFindings()
        findingsStore.fetchSummary()
      } catch (e: any) {
        const detail = e.response?.data?.detail || 'Failed to purge findings'
        toast.add({ severity: 'error', summary: 'Error', detail, life: 3000 })
      }
    },
  })
}

// Handle query params for filtering
onMounted(async () => {
  // Fetch summary first to populate filter options
  await Promise.all([findingsStore.fetchSummary(), findingsStore.fetchFilterOptions()])

  // Check for severity filter in query params (from dashboard click)
  if (route.query.severity) {
    findingsStore.setFilters({ severity: [route.query.severity as string] })
  }
  loadFindings()
})

// Watch for route query changes
watch(
  () => route.query,
  (newQuery) => {
    if (newQuery.severity) {
      findingsStore.setFilters({ severity: [newQuery.severity as string] })
      loadFindings()
    }
  }
)
</script>

<style scoped>
.findings-view {
  padding: 1rem;
  max-width: 1400px;
  margin: 0 auto;
  display: flex;
  flex-direction: column;
  height: calc(100vh - 180px);
}

.findings-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--spacing-lg, 24px);
}

.findings-header h2 {
  font-size: 1.75rem;
  font-weight: 700;
  color: var(--text-primary, var(--text-color));
  margin: 0;
}

.findings-header .subtitle {
  color: var(--text-secondary, var(--text-color-secondary));
  font-size: 0.875rem;
  margin-top: var(--spacing-xs, 4px);
}

.header-actions {
  display: flex;
  gap: var(--spacing-sm, 8px);
}

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
</style>
