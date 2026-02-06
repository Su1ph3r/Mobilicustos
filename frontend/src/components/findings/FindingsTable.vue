<template>
  <div class="findings-table-container">
    <DataTable
      v-model:expandedRows="expandedRows"
      :value="findings"
      :loading="loading"
      :rows="pageSize"
      :totalRecords="total"
      :lazy="true"
      :sortField="sortField"
      :sortOrder="sortOrder"
      dataKey="finding_id"
      scrollable
      scrollHeight="flex"
      stripedRows
      showGridlines
      class="findings-table"
      @page="onPage"
      @sort="onSort"
    >
      <template #empty>
        <div class="empty-state">
          <i class="pi pi-inbox" />
          <p>No findings found</p>
          <span v-if="hasFilters">Try adjusting your filters</span>
        </div>
      </template>

      <template #loading>
        <div class="loading-state">
          <ProgressSpinner />
          <span>Loading findings...</span>
        </div>
      </template>

      <!-- Expander Column -->
      <Column expander style="width: 3rem" />

      <!-- Severity -->
      <Column field="severity" header="Severity" :sortable="true" style="width: 100px">
        <template #body="{ data }">
          <span class="severity-badge" :class="data.severity">
            {{ data.severity }}
          </span>
        </template>
      </Column>

      <!-- Tool -->
      <Column field="tool" header="Tool" :sortable="true" style="width: 120px">
        <template #body="{ data }">
          <span class="tool-badge">{{ data.tool }}</span>
        </template>
      </Column>

      <!-- Title -->
      <Column field="title" header="Finding" :sortable="true" style="min-width: 300px">
        <template #body="{ data }">
          <div class="finding-title-cell">
            <span class="title">{{ data.title }}</span>
            <span v-if="data.file_path" class="resource-name">
              {{ truncatePath(data.file_path) }}
            </span>
          </div>
        </template>
      </Column>

      <!-- Platform -->
      <Column field="platform" header="Platform" :sortable="true" style="width: 100px">
        <template #body="{ data }">
          <span v-if="data.platform" :class="['platform-badge', `platform-${data.platform}`]">
            {{ data.platform }}
          </span>
          <span v-else class="text-muted">-</span>
        </template>
      </Column>

      <!-- Status -->
      <Column field="status" header="Status" :sortable="true" style="width: 100px">
        <template #body="{ data }">
          <span class="status-badge" :class="data.status">
            {{ formatStatus(data.status) }}
          </span>
        </template>
      </Column>

      <!-- Date -->
      <Column field="created_at" header="Date" :sortable="true" style="width: 120px">
        <template #body="{ data }">
          {{ formatDate(data.created_at) }}
        </template>
      </Column>

      <!-- Row Expansion Template -->
      <template #expansion="{ data }">
        <FindingDetail :finding="data" />
      </template>
    </DataTable>

    <!-- Pagination -->
    <div class="pagination-container">
      <div class="pagination-info">
        Showing {{ startItem }} to {{ endItem }} of {{ total }} findings
      </div>
      <Paginator
        :rows="pageSize"
        :totalRecords="total"
        :first="(page - 1) * pageSize"
        :rowsPerPageOptions="[25, 50, 100]"
        @page="onPageChange"
      />
    </div>
  </div>
</template>

<script setup lang="ts">
/**
 * FindingsTable - Reusable, paginated data table for displaying security findings.
 *
 * Features:
 * - Sortable columns for severity, tool, title, platform, status, and date
 * - Expandable rows with FindingDetail inline component
 * - Severity, status, platform, and tool badges with color coding
 * - Lazy pagination with configurable page size (25/50/100)
 * - Empty state and loading spinner display
 * - Emits page-change and sort-change events for parent-driven data fetching
 *
 * @requires FindingDetail - renders expanded finding details inline
 */
import { ref, computed } from 'vue'
import type { Finding } from '@/stores/findings'
import DataTable, { type DataTableSortEvent } from 'primevue/datatable'
import Column from 'primevue/column'
import Paginator from 'primevue/paginator'
import ProgressSpinner from 'primevue/progressspinner'
import FindingDetail from './FindingDetail.vue'

const props = defineProps<{
  findings: Finding[]
  total: number
  page: number
  pageSize: number
  loading: boolean
  hasFilters: boolean
  sortField: string
  sortOrder: number
}>()

const emit = defineEmits<{
  (e: 'page-change', payload: { page: number; pageSize: number }): void
  (e: 'sort-change', payload: { field: string; order: number }): void
}>()

const expandedRows = ref<Finding[]>([])

const startItem = computed(() => {
  if (props.total === 0) return 0
  return (props.page - 1) * props.pageSize + 1
})

const endItem = computed(() => {
  const end = props.page * props.pageSize
  return end > props.total ? props.total : end
})

const formatDate = (dateStr: string) => {
  if (!dateStr) return 'N/A'
  return new Date(dateStr).toLocaleDateString()
}

const formatStatus = (status: string) => {
  if (!status) return 'Unknown'
  return status.replace(/_/g, ' ')
}

const truncatePath = (path: string) => {
  if (!path) return ''
  if (path.length > 40) {
    return '...' + path.slice(-37)
  }
  return path
}

const onPage = (event: { page: number; rows: number }) => {
  emit('page-change', {
    page: event.page + 1,
    pageSize: event.rows,
  })
}

const onPageChange = (event: { page: number; rows: number }) => {
  emit('page-change', {
    page: event.page + 1,
    pageSize: event.rows,
  })
}

const onSort = (event: DataTableSortEvent) => {
  const field = typeof event.sortField === 'function' ? 'severity' : (event.sortField || 'severity')
  emit('sort-change', {
    field,
    order: event.sortOrder ?? -1,
  })
}
</script>

<style scoped>
.findings-table-container {
  display: flex;
  flex-direction: column;
  flex: 1;
  min-height: 0;
}

.findings-table {
  flex: 1;
}

:deep(.p-datatable) {
  background: var(--bg-secondary, var(--surface-card));
  border-radius: var(--radius-md);
  overflow: hidden;
}

:deep(.p-datatable-thead > tr > th) {
  background: var(--bg-tertiary, var(--surface-ground));
  color: var(--text-primary, var(--text-color));
  font-weight: 600;
  font-size: 0.8125rem;
  text-transform: uppercase;
  padding: var(--spacing-md);
}

:deep(.p-datatable-tbody > tr > td) {
  padding: var(--spacing-md);
  font-size: 0.875rem;
}

:deep(.p-datatable-tbody > tr.p-datatable-row-expansion > td) {
  padding: 0;
}

.finding-title-cell {
  display: flex;
  flex-direction: column;
  gap: var(--spacing-xs);
}

.finding-title-cell .title {
  font-weight: 500;
  color: var(--text-primary, var(--text-color));
}

.finding-title-cell .resource-name {
  font-size: 0.75rem;
  color: var(--text-secondary, var(--text-color-secondary));
  font-family: 'Consolas', monospace;
}

.tool-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  background: var(--accent-primary-bg);
  color: var(--accent-primary, var(--primary-color));
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 500;
}

.severity-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 600;
  text-transform: capitalize;
}

.severity-badge.critical {
  background: var(--severity-critical-bg);
  color: var(--severity-critical);
  border: 1px solid var(--severity-critical-border);
}

.severity-badge.high {
  background: var(--severity-high-bg);
  color: var(--severity-high);
  border: 1px solid var(--severity-high-border);
}

.severity-badge.medium {
  background: var(--severity-medium-bg);
  color: var(--severity-medium);
  border: 1px solid var(--severity-medium-border);
}

.severity-badge.low {
  background: var(--severity-low-bg);
  color: var(--severity-low);
  border: 1px solid var(--severity-low-border);
}

.severity-badge.info {
  background: var(--severity-info-bg);
  color: var(--severity-info);
  border: 1px solid var(--severity-info-border);
}

.status-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: capitalize;
}

.status-badge.open {
  background: rgba(239, 68, 68, 0.1);
  color: var(--status-open);
}

.status-badge.confirmed {
  background: rgba(249, 115, 22, 0.1);
  color: #f97316;
}

.status-badge.false_positive {
  background: rgba(107, 114, 128, 0.1);
  color: #6b7280;
}

.status-badge.remediated {
  background: rgba(59, 130, 246, 0.1);
  color: var(--status-remediated);
}

.status-badge.accepted_risk {
  background: rgba(139, 92, 246, 0.1);
  color: var(--status-accepted_risk);
}

.platform-badge {
  display: inline-block;
  padding: var(--spacing-xs) var(--spacing-sm);
  border-radius: var(--radius-sm);
  font-size: 0.75rem;
  font-weight: 500;
  text-transform: capitalize;
}

.platform-badge.platform-android {
  background: rgba(76, 175, 80, 0.1);
  color: #4caf50;
}

.platform-badge.platform-ios {
  background: rgba(0, 122, 255, 0.1);
  color: #007aff;
}

.text-muted {
  color: var(--text-tertiary, var(--text-color-secondary));
}

.empty-state,
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: var(--spacing-xl);
  color: var(--text-secondary, var(--text-color-secondary));
  gap: var(--spacing-md);
}

.empty-state i {
  font-size: 3rem;
  opacity: 0.5;
}

.pagination-container {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--spacing-md);
  background: var(--bg-secondary, var(--surface-card));
  border-top: 1px solid var(--border-color);
}

.pagination-info {
  font-size: 0.875rem;
  color: var(--text-secondary, var(--text-color-secondary));
}

@media (max-width: 768px) {
  .pagination-container {
    flex-direction: column;
    gap: var(--spacing-md);
  }
}
</style>
