<template>
  <div class="apps-view">
    <div class="page-header">
      <div>
        <h1>Applications</h1>
        <p class="text-secondary">Manage mobile applications for security analysis</p>
      </div>
      <Button label="Upload App" icon="pi pi-upload" @click="showUploadDialog = true" />
    </div>

    <!-- Filters -->
    <div class="filters card">
      <div class="filter-row">
        <div class="filter-item">
          <label>Platform</label>
          <Dropdown
            v-model="selectedPlatform"
            :options="platforms"
            optionLabel="label"
            optionValue="value"
            placeholder="All Platforms"
            showClear
            @change="applyFilters"
          />
        </div>
        <div class="filter-item">
          <label>Framework</label>
          <Dropdown
            v-model="selectedFramework"
            :options="frameworks"
            optionLabel="label"
            optionValue="value"
            placeholder="All Frameworks"
            showClear
            @change="applyFilters"
          />
        </div>
        <div class="filter-item">
          <label>Search</label>
          <InputText v-model="searchQuery" placeholder="Search apps..." @input="debouncedSearch" />
        </div>
      </div>
    </div>

    <!-- Apps Table -->
    <div class="card">
      <DataTable
        :value="appsStore.apps"
        :loading="appsStore.loading"
        responsiveLayout="scroll"
        :paginator="true"
        :rows="appsStore.pagination.pageSize"
        :totalRecords="appsStore.pagination.total"
        :lazy="true"
        @page="onPage"
      >
        <Column field="app_name" header="Application">
          <template #body="{ data }">
            <div class="app-info">
              <i :class="getPlatformIcon(data.platform)" class="platform-icon"></i>
              <div>
                <router-link :to="`/apps/${data.app_id}`" class="app-name">
                  {{ data.app_name || data.package_name }}
                </router-link>
                <div class="package-name">{{ data.package_name }}</div>
              </div>
            </div>
          </template>
        </Column>
        <Column field="version_name" header="Version">
          <template #body="{ data }">
            {{ data.version_name || '-' }}
            <span v-if="data.version_code" class="version-code">({{ data.version_code }})</span>
          </template>
        </Column>
        <Column field="platform" header="Platform">
          <template #body="{ data }">
            <Tag :value="data.platform" :severity="data.platform === 'android' ? 'success' : 'info'" />
          </template>
        </Column>
        <Column field="framework" header="Framework">
          <template #body="{ data }">
            <Tag v-if="data.framework" :value="data.framework" severity="secondary" />
            <span v-else class="text-secondary">Native</span>
          </template>
        </Column>
        <Column field="status" header="Status">
          <template #body="{ data }">
            <Tag :value="data.status" :severity="getStatusSeverity(data.status)" />
          </template>
        </Column>
        <Column field="upload_date" header="Uploaded">
          <template #body="{ data }">
            {{ formatDate(data.upload_date) }}
          </template>
        </Column>
        <Column header="Actions" style="width: 150px">
          <template #body="{ data }">
            <div class="action-buttons">
              <Button
                icon="pi pi-search"
                class="p-button-sm p-button-text"
                v-tooltip="'Start Scan'"
                @click="startScan(data)"
              />
              <Button
                icon="pi pi-eye"
                class="p-button-sm p-button-text"
                v-tooltip="'View Details'"
                @click="$router.push(`/apps/${data.app_id}`)"
              />
              <Button
                icon="pi pi-trash"
                class="p-button-sm p-button-text p-button-danger"
                v-tooltip="'Delete'"
                @click="confirmDelete(data)"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </div>

    <!-- Upload Dialog -->
    <Dialog
      v-model:visible="showUploadDialog"
      header="Upload Application"
      :modal="true"
      :style="{ width: '500px' }"
    >
      <div class="upload-area" @drop="onDrop" @dragover.prevent @dragenter.prevent>
        <FileUpload
          ref="fileUpload"
          mode="basic"
          :auto="false"
          accept=".apk,.ipa,.aab"
          :maxFileSize="500000000"
          chooseLabel="Select APK or IPA"
          @select="onFileSelect"
        />
        <p class="upload-hint">Drag and drop or click to select an APK, IPA, or AAB file</p>
      </div>
      <template #footer>
        <Button label="Cancel" class="p-button-text" @click="showUploadDialog = false" />
        <Button
          label="Upload"
          icon="pi pi-upload"
          :loading="uploading"
          :disabled="!selectedFile"
          @click="uploadApp"
        />
      </template>
    </Dialog>

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
        <Button label="Start Scan" icon="pi pi-play" @click="executeScan" />
      </template>
    </Dialog>

  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAppsStore, type MobileApp } from '@/stores/apps'
import { useScansStore } from '@/stores/scans'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dropdown from 'primevue/dropdown'
import InputText from 'primevue/inputtext'
import Dialog from 'primevue/dialog'
import FileUpload from 'primevue/fileupload'

const router = useRouter()
const appsStore = useAppsStore()
const scansStore = useScansStore()
const confirm = useConfirm()
const toast = useToast()

const showUploadDialog = ref(false)
const showScanDialog = ref(false)
const uploading = ref(false)
const selectedFile = ref<File | null>(null)
const selectedApp = ref<MobileApp | null>(null)
const selectedScanType = ref('static')

const selectedPlatform = ref<string | null>(null)
const selectedFramework = ref<string | null>(null)
const searchQuery = ref('')

const platforms = [
  { label: 'Android', value: 'android' },
  { label: 'iOS', value: 'ios' },
]

const frameworks = [
  { label: 'Flutter', value: 'flutter' },
  { label: 'React Native', value: 'react_native' },
  { label: 'Xamarin', value: 'xamarin' },
  { label: 'Cordova', value: 'cordova' },
  { label: '.NET MAUI', value: 'maui' },
]

const scanTypes = [
  {
    value: 'static',
    label: 'Static Analysis',
    icon: 'pi pi-file-edit',
    description: 'Analyze app without running it',
  },
  {
    value: 'dynamic',
    label: 'Dynamic Analysis',
    icon: 'pi pi-play',
    description: 'Runtime analysis with Frida',
  },
  {
    value: 'full',
    label: 'Full Analysis',
    icon: 'pi pi-check-circle',
    description: 'Complete static + dynamic analysis',
  },
]

let searchTimeout: number | null = null

function debouncedSearch() {
  if (searchTimeout) clearTimeout(searchTimeout)
  searchTimeout = window.setTimeout(() => {
    applyFilters()
  }, 300)
}

function applyFilters() {
  appsStore.setFilters({
    platform: selectedPlatform.value,
    framework: selectedFramework.value,
    search: searchQuery.value || null,
  })
}

function getPlatformIcon(platform: string) {
  return platform === 'android' ? 'pi pi-android' : 'pi pi-apple'
}

function getStatusSeverity(status: string) {
  switch (status) {
    case 'ready': return 'success'
    case 'processing': return 'info'
    case 'error': return 'danger'
    default: return 'secondary'
  }
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleDateString()
}

function onPage(event: { page: number }) {
  appsStore.setPage(event.page + 1)
}

function onFileSelect(event: { files: File[] }) {
  selectedFile.value = event.files[0]
}

function onDrop(event: DragEvent) {
  event.preventDefault()
  const files = event.dataTransfer?.files
  if (files && files.length > 0) {
    selectedFile.value = files[0]
  }
}

async function uploadApp() {
  if (!selectedFile.value) return

  uploading.value = true
  try {
    await appsStore.uploadApp(selectedFile.value)
    toast.add({ severity: 'success', summary: 'Success', detail: 'App uploaded successfully', life: 3000 })
    showUploadDialog.value = false
    selectedFile.value = null
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to upload app', life: 3000 })
  } finally {
    uploading.value = false
  }
}

function startScan(app: MobileApp) {
  selectedApp.value = app
  showScanDialog.value = true
}

async function executeScan() {
  if (!selectedApp.value) return

  try {
    await scansStore.createScan({
      app_id: selectedApp.value.app_id,
      scan_type: selectedScanType.value,
    })
    toast.add({ severity: 'success', summary: 'Success', detail: 'Scan started', life: 3000 })
    showScanDialog.value = false
    router.push('/scans')
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to start scan', life: 3000 })
  }
}

function confirmDelete(app: MobileApp) {
  confirm.require({
    message: `Are you sure you want to delete ${app.app_name || app.package_name}?`,
    header: 'Delete Application',
    icon: 'pi pi-exclamation-triangle',
    rejectLabel: 'Cancel',
    acceptLabel: 'Delete',
    rejectClass: 'p-button-secondary p-button-outlined',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await appsStore.deleteApp(app.app_id)
        toast.add({ severity: 'success', summary: 'Deleted', detail: 'App deleted successfully', life: 3000 })
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to delete app', life: 3000 })
      }
    },
    reject: () => {
      // Dialog closes automatically
    },
  })
}

onMounted(() => {
  appsStore.fetchApps()
})
</script>

<style scoped>
.apps-view {
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

.card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  margin-bottom: 1rem;
}

.filters .filter-row {
  display: flex;
  gap: 1rem;
  flex-wrap: wrap;
}

.filter-item {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  min-width: 200px;
}

.filter-item label {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.app-info {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.platform-icon {
  font-size: 1.5rem;
  color: var(--primary-color);
}

.app-name {
  font-weight: 600;
  color: var(--primary-color);
  text-decoration: none;
}

.package-name {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.version-code {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
}

.action-buttons {
  display: flex;
  gap: 0.25rem;
}

.upload-area {
  text-align: center;
  padding: 2rem;
  border: 2px dashed var(--surface-border);
  border-radius: 8px;
}

.upload-hint {
  margin-top: 1rem;
  color: var(--text-color-secondary);
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
  background: var(--primary-color);
  background-opacity: 0.1;
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
</style>
