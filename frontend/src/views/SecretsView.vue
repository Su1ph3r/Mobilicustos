<template>
  <div class="secrets-view">
    <div class="page-header">
      <div>
        <h1>Secrets & Credentials</h1>
        <p class="text-secondary">Detected API keys, tokens, and hardcoded credentials</p>
      </div>
    </div>

    <!-- Summary Cards -->
    <div class="grid summary-grid">
      <div class="col-12 md:col-3">
        <div class="summary-card total">
          <span class="count">{{ summary?.total || 0 }}</span>
          <span class="label">Total Secrets</span>
        </div>
      </div>
      <div class="col-12 md:col-3">
        <div class="summary-card validated">
          <span class="count">{{ summary?.validated || 0 }}</span>
          <span class="label">Validated</span>
        </div>
      </div>
      <div class="col-12 md:col-3">
        <div class="summary-card active">
          <span class="count">{{ summary?.active || 0 }}</span>
          <span class="label">Active</span>
        </div>
      </div>
      <div class="col-12 md:col-3">
        <div class="summary-card revoked">
          <span class="count">{{ summary?.revoked || 0 }}</span>
          <span class="label">Revoked</span>
        </div>
      </div>
    </div>

    <!-- Filters -->
    <div class="card filters-card">
      <div class="filters-row">
        <Dropdown
          v-model="selectedType"
          :options="secretTypes"
          placeholder="All Types"
          showClear
          @change="applyFilters"
        />
        <Dropdown
          v-model="selectedProvider"
          :options="providers"
          placeholder="All Providers"
          showClear
          @change="applyFilters"
        />
        <Dropdown
          v-model="selectedStatus"
          :options="statuses"
          placeholder="All Statuses"
          showClear
          @change="applyFilters"
        />
        <span class="p-input-icon-left flex-grow">
          <i class="pi pi-search" />
          <InputText v-model="searchQuery" placeholder="Search secrets..." @input="debouncedSearch" />
        </span>
      </div>
    </div>

    <!-- Secrets Table -->
    <div class="card">
      <DataTable
        :value="secrets"
        :loading="loading"
        responsiveLayout="scroll"
        :paginator="true"
        :rows="20"
        :totalRecords="pagination.total"
        :lazy="true"
        @page="onPage"
      >
        <Column field="secret_type" header="Type" style="width: 150px">
          <template #body="{ data }">
            <div class="type-cell">
              <i :class="getTypeIcon(data.secret_type)"></i>
              <span>{{ formatType(data.secret_type) }}</span>
            </div>
          </template>
        </Column>
        <Column field="provider" header="Provider" style="width: 120px">
          <template #body="{ data }">
            <Tag v-if="data.provider" :value="data.provider" severity="secondary" />
            <span v-else class="text-secondary">Unknown</span>
          </template>
        </Column>
        <Column field="value" header="Secret">
          <template #body="{ data }">
            <div class="secret-cell">
              <code class="secret-value">{{ maskSecret(data.value) }}</code>
              <Button
                :icon="visibleSecrets.has(data.secret_id) ? 'pi pi-eye-slash' : 'pi pi-eye'"
                class="p-button-sm p-button-text"
                @click="toggleSecretVisibility(data.secret_id)"
              />
              <Button
                icon="pi pi-copy"
                class="p-button-sm p-button-text"
                @click="copySecret(data.value)"
              />
            </div>
          </template>
        </Column>
        <Column field="file_path" header="Location" style="width: 200px">
          <template #body="{ data }">
            <div v-if="data.file_path" class="location-cell">
              <span class="file-path">{{ truncatePath(data.file_path) }}</span>
              <span v-if="data.line_number" class="line-number">:{{ data.line_number }}</span>
            </div>
            <span v-else class="text-secondary">-</span>
          </template>
        </Column>
        <Column field="validation_status" header="Status" style="width: 120px">
          <template #body="{ data }">
            <Tag
              :value="data.validation_status || 'unknown'"
              :severity="getValidationSeverity(data.validation_status)"
            />
          </template>
        </Column>
        <Column header="Actions" style="width: 120px">
          <template #body="{ data }">
            <div class="action-buttons">
              <Button
                v-if="data.validation_status !== 'validated'"
                icon="pi pi-check"
                class="p-button-sm p-button-text"
                v-tooltip="'Validate'"
                @click="validateSecret(data)"
              />
              <Button
                icon="pi pi-eye"
                class="p-button-sm p-button-text"
                v-tooltip="'View Details'"
                @click="showDetails(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- Secret Details Dialog -->
    <Dialog
      v-model:visible="showDetailsDialog"
      header="Secret Details"
      :modal="true"
      :style="{ width: '600px' }"
    >
      <div v-if="selectedSecret" class="secret-details">
        <div class="detail-section">
          <h4>Basic Information</h4>
          <div class="detail-grid">
            <div class="detail-item">
              <span class="detail-label">Type</span>
              <span class="detail-value">{{ formatType(selectedSecret.secret_type) }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Provider</span>
              <span class="detail-value">{{ selectedSecret.provider || 'Unknown' }}</span>
            </div>
            <div class="detail-item">
              <span class="detail-label">Status</span>
              <Tag
                :value="selectedSecret.validation_status || 'unknown'"
                :severity="getValidationSeverity(selectedSecret.validation_status)"
              />
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h4>Secret Value</h4>
          <div class="secret-display">
            <code>{{ visibleSecrets.has(selectedSecret.secret_id) ? selectedSecret.value : maskSecret(selectedSecret.value) }}</code>
            <div class="secret-actions">
              <Button
                :label="visibleSecrets.has(selectedSecret.secret_id) ? 'Hide' : 'Show'"
                :icon="visibleSecrets.has(selectedSecret.secret_id) ? 'pi pi-eye-slash' : 'pi pi-eye'"
                class="p-button-sm"
                @click="toggleSecretVisibility(selectedSecret.secret_id)"
              />
              <Button
                label="Copy"
                icon="pi pi-copy"
                class="p-button-sm p-button-secondary"
                @click="copySecret(selectedSecret.value)"
              />
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h4>Location</h4>
          <div class="location-display">
            <code>{{ selectedSecret.file_path }}{{ selectedSecret.line_number ? ':' + selectedSecret.line_number : '' }}</code>
          </div>
          <div v-if="selectedSecret.context" class="context-display">
            <pre>{{ selectedSecret.context }}</pre>
          </div>
        </div>

        <div v-if="selectedSecret.validation_result" class="detail-section">
          <h4>Validation Result</h4>
          <div class="validation-result">
            <div v-if="selectedSecret.validation_result.is_valid" class="result-valid">
              <i class="pi pi-check-circle"></i>
              <span>Secret is active and valid</span>
            </div>
            <div v-else class="result-invalid">
              <i class="pi pi-times-circle"></i>
              <span>Secret is inactive or invalid</span>
            </div>
            <div v-if="selectedSecret.validation_result.details" class="result-details">
              {{ selectedSecret.validation_result.details }}
            </div>
          </div>
        </div>

        <div class="detail-section">
          <h4>Remediation</h4>
          <div class="remediation-steps">
            <ol>
              <li>Revoke or rotate this credential immediately</li>
              <li>Remove the hardcoded secret from the source code</li>
              <li>Use environment variables or a secrets manager</li>
              <li>Audit access logs for unauthorized usage</li>
            </ol>
          </div>
        </div>
      </div>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { secretsApi } from '@/services/api'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import InputText from 'primevue/inputtext'
import Dialog from 'primevue/dialog'
import Toast from 'primevue/toast'

const toast = useToast()

const loading = ref(false)
const secrets = ref<any[]>([])
const summary = ref<any>(null)
const pagination = ref({ page: 1, pageSize: 20, total: 0 })
const visibleSecrets = ref(new Set<string>())
const showDetailsDialog = ref(false)
const selectedSecret = ref<any>(null)

const selectedType = ref<string | null>(null)
const selectedProvider = ref<string | null>(null)
const selectedStatus = ref<string | null>(null)
const searchQuery = ref('')

const secretTypes = ref<string[]>([])
const providers = ref<string[]>([])
const statuses = ['unknown', 'validated', 'active', 'inactive', 'revoked']

let searchTimeout: number | null = null

function getTypeIcon(type: string) {
  switch (type?.toLowerCase()) {
    case 'api_key': return 'pi pi-key'
    case 'aws_access_key': return 'pi pi-cloud'
    case 'private_key': return 'pi pi-lock'
    case 'password': return 'pi pi-shield'
    case 'token': return 'pi pi-ticket'
    default: return 'pi pi-lock'
  }
}

function formatType(type: string) {
  if (!type) return 'Unknown'
  return type.replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase())
}

function maskSecret(value: string) {
  if (!value) return ''
  if (value.length <= 8) return '********'
  return value.substring(0, 4) + '****' + value.substring(value.length - 4)
}

function truncatePath(path: string) {
  if (path.length > 30) {
    return '...' + path.slice(-27)
  }
  return path
}

function getValidationSeverity(status: string | null) {
  switch (status) {
    case 'active': return 'danger'
    case 'validated': return 'warning'
    case 'inactive': return 'info'
    case 'revoked': return 'success'
    default: return 'secondary'
  }
}

function toggleSecretVisibility(secretId: string) {
  if (visibleSecrets.value.has(secretId)) {
    visibleSecrets.value.delete(secretId)
  } else {
    visibleSecrets.value.add(secretId)
  }
  visibleSecrets.value = new Set(visibleSecrets.value)
}

function copySecret(value: string) {
  navigator.clipboard.writeText(value)
  toast.add({ severity: 'success', summary: 'Copied', detail: 'Secret copied to clipboard', life: 2000 })
}

function debouncedSearch() {
  if (searchTimeout) clearTimeout(searchTimeout)
  searchTimeout = window.setTimeout(() => {
    applyFilters()
  }, 300)
}

async function applyFilters() {
  loading.value = true
  try {
    const params: any = {
      page: pagination.value.page,
      page_size: pagination.value.pageSize,
    }
    if (selectedType.value) params.secret_type = selectedType.value
    if (selectedProvider.value) params.provider = selectedProvider.value
    if (selectedStatus.value) params.validation_status = selectedStatus.value
    if (searchQuery.value) params.search = searchQuery.value

    const response = await secretsApi.list(params)
    secrets.value = response.data.items || []
    pagination.value.total = response.data.total || 0
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to fetch secrets', life: 3000 })
  } finally {
    loading.value = false
  }
}

function onPage(event: { page: number }) {
  pagination.value.page = event.page + 1
  applyFilters()
}

function showDetails(secret: any) {
  selectedSecret.value = secret
  showDetailsDialog.value = true
}

async function validateSecret(secret: any) {
  try {
    const response = await secretsApi.validate(secret.secret_id)
    const idx = secrets.value.findIndex((s) => s.secret_id === secret.secret_id)
    if (idx !== -1) {
      secrets.value[idx].validation_status = response.data.status
      secrets.value[idx].validation_result = response.data
    }
    toast.add({
      severity: response.data.is_valid ? 'warning' : 'success',
      summary: 'Validated',
      detail: response.data.is_valid ? 'Secret is active!' : 'Secret is inactive',
      life: 3000,
    })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Validation failed', life: 3000 })
  }
}

async function loadMetadata() {
  try {
    const [typesResponse, providersResponse] = await Promise.all([
      secretsApi.getTypes(),
      secretsApi.getProviders(),
    ])
    secretTypes.value = typesResponse.data || []
    providers.value = providersResponse.data || []
  } catch (e) {
    console.error('Failed to load metadata:', e)
  }
}

async function loadSummary() {
  try {
    const response = await secretsApi.getSummary()
    summary.value = response.data
  } catch (e) {
    console.error('Failed to load summary:', e)
  }
}

onMounted(async () => {
  await Promise.all([applyFilters(), loadMetadata(), loadSummary()])
})
</script>

<style scoped>
.secrets-view {
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

.summary-grid {
  margin-bottom: 1rem;
}

.summary-card {
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 1.25rem;
  border-radius: 8px;
  color: white;
}

.summary-card .count {
  font-size: 2rem;
  font-weight: 700;
}

.summary-card .label {
  font-size: 0.85rem;
  opacity: 0.9;
}

.summary-card.total { background: linear-gradient(135deg, #007bff, #0056b3); }
.summary-card.validated { background: linear-gradient(135deg, #ffc107, #e0a800); color: #212529; }
.summary-card.active { background: linear-gradient(135deg, #dc3545, #c82333); }
.summary-card.revoked { background: linear-gradient(135deg, #28a745, #1e7e34); }

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
  gap: 0.75rem;
  flex-wrap: wrap;
  align-items: center;
}

.flex-grow {
  flex-grow: 1;
  min-width: 200px;
}

.type-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.type-cell i {
  color: var(--primary-color);
}

.secret-cell {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.secret-value {
  font-family: monospace;
  font-size: 0.85rem;
  background: var(--surface-ground);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.location-cell {
  font-family: monospace;
  font-size: 0.85rem;
}

.file-path {
  color: var(--text-color-secondary);
}

.line-number {
  color: var(--primary-color);
}

.action-buttons {
  display: flex;
  gap: 0.25rem;
}

.secret-details .detail-section {
  margin-bottom: 1.5rem;
}

.detail-section h4 {
  margin: 0 0 0.75rem;
  font-size: 0.95rem;
  color: var(--text-color-secondary);
}

.detail-grid {
  display: grid;
  grid-template-columns: repeat(3, 1fr);
  gap: 1rem;
}

.detail-item {
  display: flex;
  flex-direction: column;
  gap: 0.25rem;
}

.detail-label {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.detail-value {
  font-weight: 500;
}

.secret-display {
  background: var(--surface-ground);
  padding: 1rem;
  border-radius: 8px;
}

.secret-display code {
  display: block;
  font-family: monospace;
  word-break: break-all;
  margin-bottom: 0.75rem;
}

.secret-actions {
  display: flex;
  gap: 0.5rem;
}

.location-display code {
  display: block;
  font-family: monospace;
  background: var(--surface-ground);
  padding: 0.5rem;
  border-radius: 4px;
  margin-bottom: 0.5rem;
}

.context-display pre {
  background: #1e1e1e;
  color: #d4d4d4;
  padding: 1rem;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 0.85rem;
}

.validation-result {
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
}

.result-valid,
.result-invalid {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-weight: 600;
}

.result-valid {
  color: #dc3545;
}

.result-invalid {
  color: #28a745;
}

.result-details {
  margin-top: 0.5rem;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.remediation-steps ol {
  margin: 0;
  padding-left: 1.5rem;
}

.remediation-steps li {
  margin-bottom: 0.5rem;
}
</style>
