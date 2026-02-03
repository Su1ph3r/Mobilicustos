<template>
  <div class="compliance-view">
    <div class="page-header">
      <div>
        <h1>OWASP MASVS Compliance</h1>
        <p class="text-secondary">Mobile Application Security Verification Standard assessment</p>
      </div>
      <div class="header-actions">
        <Dropdown
          v-model="selectedApp"
          :options="apps"
          optionLabel="app_name"
          optionValue="app_id"
          placeholder="Select Application"
          @change="loadCompliance"
        />
        <Button
          v-if="selectedApp"
          label="Generate Report"
          icon="pi pi-file-pdf"
          @click="generateReport"
        />
      </div>
    </div>

    <div v-if="!selectedApp" class="empty-state">
      <i class="pi pi-shield"></i>
      <h3>Select an Application</h3>
      <p>Choose an application to view its MASVS compliance status</p>
    </div>

    <div v-else-if="loading" class="loading-state">
      <ProgressSpinner />
    </div>

    <div v-else class="grid">
      <!-- Compliance Overview -->
      <div class="col-12">
        <div class="card overview-card">
          <div class="compliance-score">
            <CircularProgress :value="overallScore" :size="120" />
            <div class="score-label">Overall Compliance</div>
          </div>
          <div class="category-summary">
            <div v-for="cat in categories" :key="cat.id" class="category-chip" :class="getCategoryStatus(cat.id)">
              <span class="category-name">{{ cat.id }}</span>
              <span class="category-score">{{ getCategoryScore(cat.id) }}%</span>
            </div>
          </div>
        </div>
      </div>

      <!-- Category Cards -->
      <div v-for="category in categories" :key="category.id" class="col-12 lg:col-6">
        <div class="card category-card" :class="getCategoryStatus(category.id)">
          <div class="category-header">
            <div class="category-info">
              <h3>{{ category.id }}</h3>
              <p>{{ category.name }}</p>
            </div>
            <div class="category-progress">
              <span class="progress-text">{{ getCategoryScore(category.id) }}%</span>
              <ProgressBar :value="getCategoryScore(category.id)" :showValue="false" />
            </div>
          </div>
          <div class="controls-list">
            <div
              v-for="control in category.controls"
              :key="control.id"
              :class="['control-item', getControlStatus(control.id)]"
            >
              <div class="control-info">
                <span class="control-id">{{ control.id }}</span>
                <span class="control-name">{{ control.name }}</span>
              </div>
              <div class="control-status">
                <Tag
                  :value="getControlStatusLabel(control.id)"
                  :severity="getControlStatusSeverity(control.id)"
                />
              </div>
            </div>
          </div>
          <Button
            label="View Details"
            class="p-button-sm p-button-text"
            @click="showCategoryDetails(category.id)"
          />
        </div>
      </div>
    </div>

    <!-- Category Details Dialog -->
    <Dialog
      v-model:visible="showDetailsDialog"
      :header="selectedCategory?.name || 'Category Details'"
      :modal="true"
      :style="{ width: '800px' }"
    >
      <div v-if="categoryDetails" class="category-details">
        <div v-for="control in categoryDetails.controls" :key="control.id" class="detail-control">
          <div class="detail-header">
            <div>
              <h4>{{ control.id }}: {{ control.name }}</h4>
              <p>{{ control.description }}</p>
            </div>
            <Tag
              :value="control.status"
              :severity="getStatusSeverity(control.status)"
            />
          </div>
          <div v-if="control.findings && control.findings.length > 0" class="control-findings">
            <h5>Related Findings</h5>
            <div v-for="finding in control.findings" :key="finding.id" class="finding-link">
              <Tag :value="finding.severity" :severity="getSeverityColor(finding.severity)" />
              <router-link :to="`/findings/${finding.finding_id}`">{{ finding.title }}</router-link>
            </div>
          </div>
          <div v-else class="no-findings">
            <i class="pi pi-check-circle"></i>
            No violations found
          </div>
        </div>
      </div>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useAppsStore } from '@/stores/apps'
import { complianceApi, exportsApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import Tag from 'primevue/tag'
import ProgressBar from 'primevue/progressbar'
import ProgressSpinner from 'primevue/progressspinner'
import Dialog from 'primevue/dialog'
import Toast from 'primevue/toast'

const appsStore = useAppsStore()
const toast = useToast()

const selectedApp = ref<string | null>(null)
const loading = ref(false)
const compliance = ref<any>(null)
const showDetailsDialog = ref(false)
const selectedCategory = ref<any>(null)
const categoryDetails = ref<any>(null)

const apps = computed(() => appsStore.apps)

interface Control {
  id: string
  name: string
}

interface Category {
  id: string
  name: string
  controls: Control[]
}

function createCategory(id: string, name: string): Category {
  const controls: Control[] = []
  for (let i = 1; i <= 4; i++) {
    controls.push({ id: `${id}-${i}`, name: `Control ${i}` })
  }
  return { id, name, controls }
}

const categories: Category[] = [
  createCategory('MASVS-STORAGE', 'Data Storage'),
  createCategory('MASVS-CRYPTO', 'Cryptography'),
  createCategory('MASVS-AUTH', 'Authentication'),
  createCategory('MASVS-NETWORK', 'Network Communication'),
  createCategory('MASVS-PLATFORM', 'Platform Interaction'),
  createCategory('MASVS-CODE', 'Code Quality'),
  createCategory('MASVS-RESILIENCE', 'Resilience'),
  createCategory('MASVS-PRIVACY', 'Privacy'),
]

const overallScore = computed(() => {
  if (!compliance.value) return 0
  return compliance.value.overall_score || 0
})

function getCategoryScore(categoryId: string) {
  if (!compliance.value?.categories) return 0
  const cat = compliance.value.categories[categoryId]
  return cat?.score || 0
}

function getCategoryStatus(categoryId: string) {
  const score = getCategoryScore(categoryId)
  if (score >= 80) return 'pass'
  if (score >= 50) return 'partial'
  return 'fail'
}

function getControlStatus(controlId: string) {
  if (!compliance.value?.controls) return 'unknown'
  return compliance.value.controls[controlId]?.status || 'unknown'
}

function getControlStatusLabel(controlId: string) {
  const status = getControlStatus(controlId)
  switch (status) {
    case 'pass': return 'Pass'
    case 'fail': return 'Fail'
    case 'partial': return 'Partial'
    default: return 'N/A'
  }
}

function getControlStatusSeverity(controlId: string) {
  const status = getControlStatus(controlId)
  switch (status) {
    case 'pass': return 'success'
    case 'fail': return 'danger'
    case 'partial': return 'warning'
    default: return 'secondary'
  }
}

function getStatusSeverity(status: string) {
  switch (status) {
    case 'pass': return 'success'
    case 'fail': return 'danger'
    case 'partial': return 'warning'
    default: return 'secondary'
  }
}

function getSeverityColor(severity: string) {
  switch (severity) {
    case 'critical': return 'danger'
    case 'high': return 'danger'
    case 'medium': return 'warning'
    case 'low': return 'info'
    default: return 'secondary'
  }
}

async function loadCompliance() {
  if (!selectedApp.value) return
  loading.value = true
  try {
    const response = await complianceApi.getAppCompliance(selectedApp.value)
    compliance.value = response.data
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load compliance', life: 3000 })
  } finally {
    loading.value = false
  }
}

async function showCategoryDetails(categoryId: string) {
  if (!selectedApp.value) return
  selectedCategory.value = categories.find((c) => c.id === categoryId)
  try {
    const response = await complianceApi.getCategoryDetails(selectedApp.value, categoryId)
    categoryDetails.value = response.data
    showDetailsDialog.value = true
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load details', life: 3000 })
  }
}

async function generateReport() {
  if (!selectedApp.value) return
  try {
    // Use JSON format since PDF is not implemented
    const response = await exportsApi.exportReport(selectedApp.value, 'json')
    const blob = new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
    const url = window.URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `compliance-report-${selectedApp.value}.json`
    link.click()
    window.URL.revokeObjectURL(url)
    toast.add({ severity: 'success', summary: 'Success', detail: 'Report generated', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to generate report', life: 3000 })
  }
}

// Simple circular progress component
const CircularProgress = {
  props: {
    value: { type: Number, default: 0 },
    size: { type: Number, default: 100 },
  },
  template: `
    <div class="circular-progress" :style="{ width: size + 'px', height: size + 'px' }">
      <svg :width="size" :height="size" viewBox="0 0 100 100">
        <circle cx="50" cy="50" r="45" fill="none" stroke="#e0e0e0" stroke-width="8" />
        <circle
          cx="50" cy="50" r="45" fill="none"
          :stroke="getColor(value)"
          stroke-width="8"
          stroke-linecap="round"
          :stroke-dasharray="circumference"
          :stroke-dashoffset="getOffset(value)"
          transform="rotate(-90 50 50)"
        />
      </svg>
      <div class="progress-value">{{ value }}%</div>
    </div>
  `,
  setup() {
    const circumference = 2 * Math.PI * 45
    const getOffset = (val: number) => circumference - (val / 100) * circumference
    const getColor = (val: number) => {
      if (val >= 80) return '#28a745'
      if (val >= 50) return '#ffc107'
      return '#dc3545'
    }
    return { circumference, getOffset, getColor }
  },
}

onMounted(() => {
  appsStore.fetchApps()
})
</script>

<style scoped>
.compliance-view {
  padding: 1rem;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
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

.header-actions {
  display: flex;
  gap: 0.5rem;
}

.empty-state,
.loading-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 4rem;
  text-align: center;
}

.empty-state i {
  font-size: 4rem;
  color: var(--text-color-secondary);
  margin-bottom: 1rem;
}

.empty-state h3 {
  margin: 0 0 0.5rem;
}

.empty-state p {
  color: var(--text-color-secondary);
}

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
}

.overview-card {
  display: flex;
  align-items: center;
  gap: 2rem;
  flex-wrap: wrap;
}

.compliance-score {
  text-align: center;
}

.score-label {
  margin-top: 0.5rem;
  font-weight: 600;
}

.category-summary {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  flex: 1;
}

.category-chip {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  min-width: 100px;
}

.category-chip.pass { background: rgba(40, 167, 69, 0.1); border: 1px solid #28a745; }
.category-chip.partial { background: rgba(255, 193, 7, 0.1); border: 1px solid #ffc107; }
.category-chip.fail { background: rgba(220, 53, 69, 0.1); border: 1px solid #dc3545; }

.category-name {
  font-size: 0.75rem;
  color: var(--text-color-secondary);
}

.category-score {
  font-size: 1.25rem;
  font-weight: 700;
}

.category-card {
  border-left: 4px solid var(--surface-border);
}

.category-card.pass { border-left-color: #28a745; }
.category-card.partial { border-left-color: #ffc107; }
.category-card.fail { border-left-color: #dc3545; }

.category-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1rem;
}

.category-info h3 {
  margin: 0;
  font-size: 1rem;
}

.category-info p {
  margin: 0;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.category-progress {
  text-align: right;
  min-width: 100px;
}

.progress-text {
  font-weight: 700;
  font-size: 1.25rem;
}

.controls-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.control-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.5rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.control-id {
  font-family: monospace;
  font-size: 0.8rem;
  color: var(--text-color-secondary);
  margin-right: 0.5rem;
}

.control-name {
  font-size: 0.85rem;
}

.category-details .detail-control {
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
  margin-bottom: 1rem;
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}

.detail-header h4 {
  margin: 0 0 0.25rem;
}

.detail-header p {
  margin: 0;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.control-findings {
  margin-top: 1rem;
  padding-top: 1rem;
  border-top: 1px solid var(--surface-border);
}

.control-findings h5 {
  margin: 0 0 0.5rem;
  font-size: 0.85rem;
}

.finding-link {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 0;
}

.finding-link a {
  color: var(--primary-color);
  text-decoration: none;
}

.no-findings {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-top: 1rem;
  color: #28a745;
}

.circular-progress {
  position: relative;
  display: flex;
  align-items: center;
  justify-content: center;
}

.progress-value {
  position: absolute;
  font-size: 1.5rem;
  font-weight: 700;
}

/* Fix dropdown styling in dark mode */
:deep(.p-dropdown) {
  background: var(--surface-card);
  border-color: var(--surface-border);
}

:deep(.p-dropdown .p-dropdown-label) {
  color: var(--text-color);
}

:deep(.p-dropdown-panel) {
  background: var(--surface-card);
  border-color: var(--surface-border);
}

:deep(.p-dropdown-panel .p-dropdown-items .p-dropdown-item) {
  color: var(--text-color);
}

:deep(.p-dropdown-panel .p-dropdown-items .p-dropdown-item:hover) {
  background: var(--surface-hover);
}

:deep(.p-dropdown-panel .p-dropdown-items .p-dropdown-item.p-highlight) {
  background: var(--primary-color);
  color: #ffffff;
}
</style>
