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
        <Button
          label="Export CSV"
          icon="pi pi-download"
          severity="secondary"
          @click="exportCsv"
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
  </div>
</template>

<script setup lang="ts">
import { onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useFindingsStore } from '@/stores/findings'
import { exportsApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import FindingFilters from '@/components/findings/FindingFilters.vue'
import FindingsTable from '@/components/findings/FindingsTable.vue'

const route = useRoute()
const findingsStore = useFindingsStore()
const toast = useToast()

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

const exportCsv = async () => {
  try {
    const response = await exportsApi.exportFindings('all', 'csv', {
      include_remediation: true,
      include_poc: true,
    })

    const blob = new Blob([response.data], { type: 'text/csv' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'findings.csv'
    link.click()
    window.URL.revokeObjectURL(url)

    toast.add({ severity: 'success', summary: 'Exported', detail: 'Findings exported', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Export failed', life: 3000 })
  }
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
