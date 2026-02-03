<template>
  <div class="dashboard">
    <div class="page-header">
      <h1>Dashboard</h1>
      <p class="text-secondary">Mobile Security Analysis Overview</p>
    </div>

    <div class="grid">
      <!-- Severity Summary Cards -->
      <div class="col-12 md:col-6 lg:col-3">
        <div class="card severity-card critical">
          <div class="card-content">
            <span class="severity-count">{{ summary?.by_severity?.critical || 0 }}</span>
            <span class="severity-label">Critical</span>
          </div>
          <i class="pi pi-exclamation-triangle severity-icon"></i>
        </div>
      </div>
      <div class="col-12 md:col-6 lg:col-3">
        <div class="card severity-card high">
          <div class="card-content">
            <span class="severity-count">{{ summary?.by_severity?.high || 0 }}</span>
            <span class="severity-label">High</span>
          </div>
          <i class="pi pi-exclamation-circle severity-icon"></i>
        </div>
      </div>
      <div class="col-12 md:col-6 lg:col-3">
        <div class="card severity-card medium">
          <div class="card-content">
            <span class="severity-count">{{ summary?.by_severity?.medium || 0 }}</span>
            <span class="severity-label">Medium</span>
          </div>
          <i class="pi pi-info-circle severity-icon"></i>
        </div>
      </div>
      <div class="col-12 md:col-6 lg:col-3">
        <div class="card severity-card low">
          <div class="card-content">
            <span class="severity-count">{{ summary?.by_severity?.low || 0 }}</span>
            <span class="severity-label">Low</span>
          </div>
          <i class="pi pi-minus-circle severity-icon"></i>
        </div>
      </div>

      <!-- Stats Cards -->
      <div class="col-12 md:col-4">
        <div class="card stats-card">
          <div class="stats-header">
            <i class="pi pi-box"></i>
            <span>Total Apps</span>
          </div>
          <div class="stats-value">{{ stats.totalApps }}</div>
        </div>
      </div>
      <div class="col-12 md:col-4">
        <div class="card stats-card">
          <div class="stats-header">
            <i class="pi pi-search"></i>
            <span>Total Scans</span>
          </div>
          <div class="stats-value">{{ stats.totalScans }}</div>
        </div>
      </div>
      <div class="col-12 md:col-4">
        <div class="card stats-card">
          <div class="stats-header">
            <i class="pi pi-flag"></i>
            <span>Total Findings</span>
          </div>
          <div class="stats-value">{{ summary?.total || 0 }}</div>
        </div>
      </div>

      <!-- Recent Scans -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <div class="card-header">
            <h3>Recent Scans</h3>
            <router-link to="/scans" class="view-all">View All</router-link>
          </div>
          <DataTable :value="recentScans" :loading="loadingScans" responsiveLayout="scroll">
            <Column field="scan_id" header="Scan ID">
              <template #body="{ data }">
                <router-link :to="`/scans/${data.scan_id}`">
                  {{ data.scan_id.substring(0, 8) }}...
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
                <Tag :value="data.status" :severity="getStatusSeverity(data.status)" />
              </template>
            </Column>
            <Column field="progress" header="Progress">
              <template #body="{ data }">
                <ProgressBar :value="data.progress" :showValue="true" style="height: 8px" />
              </template>
            </Column>
          </DataTable>
        </div>
      </div>

      <!-- Findings by Category -->
      <div class="col-12 lg:col-6">
        <div class="card">
          <div class="card-header">
            <h3>Findings by Category</h3>
          </div>
          <div class="category-list">
            <div
              v-for="(count, category) in summary?.by_category"
              :key="category"
              class="category-item"
            >
              <span class="category-name">{{ category }}</span>
              <span class="category-count">{{ count }}</span>
            </div>
            <div v-if="!summary?.by_category || Object.keys(summary.by_category).length === 0" class="empty-state">
              No findings yet
            </div>
          </div>
        </div>
      </div>

      <!-- MASVS Compliance Overview -->
      <div class="col-12">
        <div class="card">
          <div class="card-header">
            <h3>OWASP MASVS Categories</h3>
            <router-link to="/compliance" class="view-all">View Compliance</router-link>
          </div>
          <div class="masvs-grid">
            <div
              v-for="(count, category) in summary?.by_masvs"
              :key="category"
              class="masvs-item"
            >
              <div class="masvs-category">{{ category }}</div>
              <div class="masvs-count">{{ count }} findings</div>
            </div>
            <div v-if="!summary?.by_masvs || Object.keys(summary.by_masvs).length === 0" class="empty-state">
              No MASVS mappings yet
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useFindingsStore } from '@/stores/findings'
import { useScansStore } from '@/stores/scans'
import { useAppsStore } from '@/stores/apps'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Tag from 'primevue/tag'
import ProgressBar from 'primevue/progressbar'

const findingsStore = useFindingsStore()
const scansStore = useScansStore()
const appsStore = useAppsStore()

const summary = ref(findingsStore.summary)
const recentScans = ref(scansStore.scans.slice(0, 5))
const loadingScans = ref(false)
const stats = ref({
  totalApps: 0,
  totalScans: 0,
})

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

onMounted(async () => {
  loadingScans.value = true
  try {
    await Promise.all([
      findingsStore.fetchSummary(),
      scansStore.fetchScans(),
      appsStore.fetchApps(),
    ])
    summary.value = findingsStore.summary
    recentScans.value = scansStore.scans.slice(0, 5)
    stats.value = {
      totalApps: appsStore.pagination.total,
      totalScans: scansStore.pagination.total,
    }
  } finally {
    loadingScans.value = false
  }
})
</script>

<style scoped>
.dashboard {
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
}

.severity-card {
  display: flex;
  justify-content: space-between;
  align-items: center;
  color: white;
}

.severity-card.critical { background: linear-gradient(135deg, #dc3545, #c82333); }
.severity-card.high { background: linear-gradient(135deg, #fd7e14, #e8590c); }
.severity-card.medium { background: linear-gradient(135deg, #ffc107, #e0a800); color: #212529; }
.severity-card.low { background: linear-gradient(135deg, #28a745, #1e7e34); }

.severity-count {
  font-size: 2rem;
  font-weight: 700;
}

.severity-label {
  display: block;
  font-size: 0.875rem;
  opacity: 0.9;
}

.severity-icon {
  font-size: 2.5rem;
  opacity: 0.3;
}

.stats-card {
  text-align: center;
}

.stats-header {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.5rem;
  color: var(--text-color-secondary);
  margin-bottom: 0.5rem;
}

.stats-value {
  font-size: 2rem;
  font-weight: 700;
  color: var(--primary-color);
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.card-header h3 {
  margin: 0;
  font-size: 1.1rem;
}

.view-all {
  color: var(--primary-color);
  text-decoration: none;
  font-size: 0.875rem;
}

.category-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.category-item {
  display: flex;
  justify-content: space-between;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.category-count {
  font-weight: 600;
  color: var(--primary-color);
}

.masvs-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 1rem;
}

.masvs-item {
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 4px;
  text-align: center;
}

.masvs-category {
  font-weight: 600;
  margin-bottom: 0.25rem;
}

.masvs-count {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.empty-state {
  text-align: center;
  padding: 2rem;
  color: var(--text-color-secondary);
}
</style>
