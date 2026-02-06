<template>
  <div class="attack-paths-view">
    <div class="page-header">
      <div>
        <h1>Attack Paths</h1>
        <p class="text-secondary">Visualize potential attack chains across vulnerabilities</p>
      </div>
      <div class="header-actions">
        <Dropdown
          v-model="selectedApp"
          :options="apps"
          optionLabel="app_name"
          optionValue="app_id"
          placeholder="Select Application"
          @change="loadAttackPaths"
        />
        <Button
          v-if="selectedApp"
          label="Generate Paths"
          icon="pi pi-refresh"
          :loading="generating"
          @click="generatePaths"
        />
      </div>
    </div>

    <div v-if="!selectedApp" class="empty-state">
      <i class="pi pi-sitemap"></i>
      <h3>Select an Application</h3>
      <p>Choose an application to view and generate attack paths</p>
    </div>

    <div v-else-if="loading" class="loading-state">
      <ProgressSpinner />
    </div>

    <div v-else class="grid">
      <!-- Attack Paths List -->
      <div class="col-12 lg:col-4">
        <div class="card paths-list-card">
          <h3>Attack Paths</h3>
          <div v-if="attackPaths.length === 0" class="empty-list">
            <p>No attack paths generated yet</p>
            <Button label="Generate Now" @click="generatePaths" />
          </div>
          <div v-else class="paths-list">
            <div
              v-for="path in attackPaths"
              :key="path.path_id"
              :class="['path-item', { selected: selectedPath?.path_id === path.path_id }]"
              @click="selectPath(path)"
            >
              <div class="path-header">
                <Tag :value="path.risk_level" :severity="getRiskSeverity(path.risk_level)" />
                <span class="path-score">{{ path.risk_score }}</span>
              </div>
              <div class="path-title">{{ path.title }}</div>
              <div class="path-meta">
                <span><i class="pi pi-flag"></i> {{ path.findings_count }} findings</span>
                <span><i class="pi pi-arrow-right"></i> {{ path.steps_count }} steps</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Path Details -->
      <div class="col-12 lg:col-8">
        <div v-if="!selectedPath" class="card empty-detail">
          <i class="pi pi-arrow-left"></i>
          <p>Select an attack path to view details</p>
        </div>
        <div v-else class="card path-detail-card">
          <div class="detail-header">
            <div>
              <h2>{{ selectedPath.title }}</h2>
              <p>{{ selectedPath.description }}</p>
            </div>
            <div class="detail-meta">
              <Tag :value="selectedPath.risk_level" :severity="getRiskSeverity(selectedPath.risk_level)" />
              <span class="risk-score">Risk: {{ selectedPath.risk_score }}</span>
            </div>
          </div>

          <!-- Attack Chain Visualization -->
          <div class="attack-chain">
            <h3>Attack Chain</h3>
            <div class="chain-steps">
              <div v-for="(step, index) in selectedPath.steps" :key="index" class="chain-step">
                <div class="step-connector" v-if="index > 0">
                  <i class="pi pi-arrow-down"></i>
                </div>
                <div :class="['step-card', step.type]">
                  <div class="step-number">{{ index + 1 }}</div>
                  <div class="step-content">
                    <div class="step-type">{{ formatStepType(step.type) }}</div>
                    <div class="step-title">{{ step.title }}</div>
                    <div class="step-description">{{ step.description }}</div>
                    <div v-if="step.finding_id" class="step-finding">
                      <router-link :to="`/findings/${step.finding_id}`">
                        View Finding <i class="pi pi-external-link"></i>
                      </router-link>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- Impact Assessment -->
          <div class="impact-section">
            <h3>Impact Assessment</h3>
            <div class="impact-grid">
              <div class="impact-item">
                <span class="impact-label">Confidentiality</span>
                <ProgressBar :value="selectedPath.impact?.confidentiality || 0" :showValue="true" />
              </div>
              <div class="impact-item">
                <span class="impact-label">Integrity</span>
                <ProgressBar :value="selectedPath.impact?.integrity || 0" :showValue="true" />
              </div>
              <div class="impact-item">
                <span class="impact-label">Availability</span>
                <ProgressBar :value="selectedPath.impact?.availability || 0" :showValue="true" />
              </div>
            </div>
          </div>

          <!-- Related Findings -->
          <div class="findings-section">
            <h3>Related Findings</h3>
            <DataTable :value="pathFindings" responsiveLayout="scroll">
              <Column field="severity" header="Severity" style="width: 100px">
                <template #body="{ data }">
                  <Tag :value="data.severity" :severity="getSeverityColor(data.severity)" />
                </template>
              </Column>
              <Column field="title" header="Finding">
                <template #body="{ data }">
                  <router-link :to="`/findings/${data.finding_id}`">{{ data.title }}</router-link>
                </template>
              </Column>
              <Column field="category" header="Category" />
            </DataTable>
          </div>

          <!-- Actions -->
          <div class="path-actions">
            <Button label="Export Path" icon="pi pi-download" class="p-button-secondary" v-tooltip.top="'Export as JSON'" @click="exportPath" />
            <Button label="Delete" icon="pi pi-trash" class="p-button-danger p-button-text" v-tooltip.top="'Delete this attack path'" @click="confirmDelete" />
          </div>
        </div>
      </div>
    </div>

    <ConfirmDialog />
    <Toast />
  </div>
</template>

<script setup lang="ts">
/**
 * AttackPathsView - Attack chain visualization and analysis across vulnerabilities.
 *
 * Features:
 * - Per-app attack path listing with risk level and score
 * - Detailed attack chain step-by-step visualization with typed step cards
 * - Impact assessment bars for confidentiality, integrity, and availability
 * - Related findings table linked to each attack path
 * - Attack path generation, JSON export, and deletion
 *
 * @requires attackPathsApi - list, get, generate, delete, and findings endpoints
 * @requires useAppsStore - provides the application list for selection
 */
import { ref, computed, onMounted } from 'vue'
import { useAppsStore } from '@/stores/apps'
import { attackPathsApi } from '@/services/api'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import Button from 'primevue/button'
import Dropdown from 'primevue/dropdown'
import Tag from 'primevue/tag'
import ProgressBar from 'primevue/progressbar'
import ProgressSpinner from 'primevue/progressspinner'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'

const appsStore = useAppsStore()
const confirm = useConfirm()
const toast = useToast()

const selectedApp = ref<string | null>(null)
const loading = ref(false)
const generating = ref(false)
const attackPaths = ref<any[]>([])
const selectedPath = ref<any>(null)
const pathFindings = ref<any[]>([])

const apps = computed(() => appsStore.apps)

function getRiskSeverity(risk: string) {
  switch (risk?.toLowerCase()) {
    case 'critical': return 'danger'
    case 'high': return 'danger'
    case 'medium': return 'warning'
    case 'low': return 'info'
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

function formatStepType(type: string) {
  return type.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())
}

async function loadAttackPaths() {
  if (!selectedApp.value) return
  loading.value = true
  selectedPath.value = null
  try {
    const response = await attackPathsApi.list({ app_id: selectedApp.value })
    attackPaths.value = response.data.items || []
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load attack paths', life: 3000 })
  } finally {
    loading.value = false
  }
}

async function selectPath(path: any) {
  selectedPath.value = path
  try {
    const [detailResponse, findingsResponse] = await Promise.all([
      attackPathsApi.get(path.path_id),
      attackPathsApi.getFindings(path.path_id),
    ])
    selectedPath.value = detailResponse.data
    pathFindings.value = findingsResponse.data || []
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to load path details', life: 3000 })
  }
}

async function generatePaths() {
  if (!selectedApp.value) return
  generating.value = true
  try {
    await attackPathsApi.generate(selectedApp.value)
    toast.add({ severity: 'success', summary: 'Success', detail: 'Attack paths generated', life: 2000 })
    await loadAttackPaths()
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to generate paths', life: 3000 })
  } finally {
    generating.value = false
  }
}

function exportPath() {
  if (!selectedPath.value) return
  const data = JSON.stringify(selectedPath.value, null, 2)
  const blob = new Blob([data], { type: 'application/json' })
  const url = window.URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = `attack-path-${selectedPath.value.path_id}.json`
  link.click()
  window.URL.revokeObjectURL(url)
}

function confirmDelete() {
  if (!selectedPath.value) return
  confirm.require({
    message: 'Are you sure you want to delete this attack path?',
    header: 'Delete Attack Path',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await attackPathsApi.delete(selectedPath.value.path_id)
        toast.add({ severity: 'success', summary: 'Deleted', detail: 'Attack path deleted', life: 2000 })
        selectedPath.value = null
        await loadAttackPaths()
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete', life: 3000 })
      }
    },
  })
}

onMounted(() => {
  appsStore.fetchApps()
})
</script>

<style scoped>
.attack-paths-view {
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

.paths-list-card {
  max-height: calc(100vh - 200px);
  overflow-y: auto;
}

.empty-list {
  text-align: center;
  padding: 2rem;
}

.empty-list p {
  color: var(--text-color-secondary);
  margin-bottom: 1rem;
}

.paths-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.path-item {
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
  cursor: pointer;
  border: 2px solid transparent;
  transition: all 0.2s;
}

.path-item:hover {
  border-color: var(--primary-color);
}

.path-item.selected {
  border-color: var(--primary-color);
  background: rgba(var(--primary-color-rgb), 0.1);
}

.path-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 0.5rem;
}

.path-score {
  font-weight: 700;
  font-size: 1.25rem;
}

.path-title {
  font-weight: 600;
  margin-bottom: 0.25rem;
}

.path-meta {
  display: flex;
  gap: 1rem;
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.path-meta i {
  margin-right: 0.25rem;
}

.empty-detail {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 400px;
  color: var(--text-color-secondary);
}

.empty-detail i {
  font-size: 3rem;
  margin-bottom: 1rem;
}

.detail-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  margin-bottom: 1.5rem;
  padding-bottom: 1rem;
  border-bottom: 1px solid var(--surface-border);
}

.detail-header h2 {
  margin: 0 0 0.25rem;
}

.detail-header p {
  margin: 0;
  color: var(--text-color-secondary);
}

.detail-meta {
  text-align: right;
}

.risk-score {
  display: block;
  font-size: 1.5rem;
  font-weight: 700;
  margin-top: 0.25rem;
}

.attack-chain {
  margin-bottom: 1.5rem;
}

.chain-steps {
  display: flex;
  flex-direction: column;
}

.chain-step {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.step-connector {
  padding: 0.5rem 0;
  color: var(--text-color-secondary);
}

.step-card {
  display: flex;
  width: 100%;
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
  border-left: 4px solid var(--primary-color);
}

.step-card.entry_point { border-left-color: #28a745; }
.step-card.vulnerability { border-left-color: #dc3545; }
.step-card.exploit { border-left-color: #fd7e14; }
.step-card.impact { border-left-color: #007bff; }

.step-number {
  width: 32px;
  height: 32px;
  border-radius: 50%;
  background: var(--primary-color);
  color: white;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  margin-right: 1rem;
  flex-shrink: 0;
}

.step-content {
  flex: 1;
}

.step-type {
  font-size: 0.75rem;
  color: var(--text-color-secondary);
  text-transform: uppercase;
}

.step-title {
  font-weight: 600;
  margin: 0.25rem 0;
}

.step-description {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.step-finding {
  margin-top: 0.5rem;
}

.step-finding a {
  color: var(--primary-color);
  text-decoration: none;
  font-size: 0.85rem;
}

.impact-section {
  margin-bottom: 1.5rem;
}

.impact-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.impact-item {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.impact-label {
  width: 120px;
  font-size: 0.9rem;
}

.findings-section {
  margin-bottom: 1.5rem;
}

.findings-section a {
  color: var(--primary-color);
  text-decoration: none;
}

.path-actions {
  display: flex;
  gap: 0.5rem;
  justify-content: flex-end;
  padding-top: 1rem;
  border-top: 1px solid var(--surface-border);
}
</style>
