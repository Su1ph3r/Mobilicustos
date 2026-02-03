<template>
  <div class="scheduled-scans-view">
    <div class="header">
      <h1>Scheduled Scans</h1>
      <Button
        label="New Schedule"
        icon="pi pi-plus"
        @click="showCreateDialog = true"
      />
    </div>

    <div class="stats-cards">
      <Card class="stat-card">
        <template #content>
          <div class="stat-value">{{ stats.active }}</div>
          <div class="stat-label">Active Schedules</div>
        </template>
      </Card>
      <Card class="stat-card">
        <template #content>
          <div class="stat-value">{{ stats.paused }}</div>
          <div class="stat-label">Paused</div>
        </template>
      </Card>
      <Card class="stat-card">
        <template #content>
          <div class="stat-value">{{ stats.runsToday }}</div>
          <div class="stat-label">Runs Today</div>
        </template>
      </Card>
      <Card class="stat-card">
        <template #content>
          <div class="stat-value">{{ nextRunTime }}</div>
          <div class="stat-label">Next Run</div>
        </template>
      </Card>
    </div>

    <Card>
      <template #content>
        <DataTable
          :value="schedules"
          :loading="loading"
          :paginator="true"
          :rows="20"
          :totalRecords="totalRecords"
          :lazy="true"
          @page="onPage"
          responsiveLayout="scroll"
          stripedRows
        >
          <Column field="name" header="Schedule Name" sortable>
            <template #body="{ data }">
              <div class="schedule-name">
                <i
                  :class="data.is_active ? 'pi pi-clock text-green-500' : 'pi pi-pause text-gray-500'"
                />
                {{ data.name }}
              </div>
            </template>
          </Column>

          <Column field="app_name" header="App" sortable />

          <Column field="cron_description" header="Schedule">
            <template #body="{ data }">
              <Tag
                :value="data.cron_description || data.cron_expression"
                severity="info"
              />
            </template>
          </Column>

          <Column field="next_run_at" header="Next Run">
            <template #body="{ data }">
              <span v-if="data.next_run_at && data.is_active">
                {{ formatDate(data.next_run_at) }}
              </span>
              <span v-else class="text-gray-500">-</span>
            </template>
          </Column>

          <Column field="last_run_at" header="Last Run">
            <template #body="{ data }">
              <span v-if="data.last_run_at">
                {{ formatRelativeTime(data.last_run_at) }}
              </span>
              <span v-else class="text-gray-500">Never</span>
            </template>
          </Column>

          <Column field="run_count" header="Runs" style="width: 80px">
            <template #body="{ data }">
              {{ data.run_count || 0 }}
            </template>
          </Column>

          <Column field="is_active" header="Status" style="width: 100px">
            <template #body="{ data }">
              <Tag
                :value="data.is_active ? 'Active' : 'Paused'"
                :severity="data.is_active ? 'success' : 'warning'"
              />
            </template>
          </Column>

          <Column header="Actions" style="width: 180px">
            <template #body="{ data }">
              <div class="action-buttons">
                <Button
                  icon="pi pi-play"
                  class="p-button-sm p-button-success p-button-text"
                  v-tooltip.top="'Run Now'"
                  @click="runNow(data)"
                  :disabled="!data.is_active"
                />
                <Button
                  :icon="data.is_active ? 'pi pi-pause' : 'pi pi-play'"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="data.is_active ? 'Pause' : 'Resume'"
                  @click="toggleActive(data)"
                />
                <Button
                  icon="pi pi-pencil"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="'Edit'"
                  @click="editSchedule(data)"
                />
                <Button
                  icon="pi pi-trash"
                  class="p-button-sm p-button-danger p-button-text"
                  v-tooltip.top="'Delete'"
                  @click="confirmDelete(data)"
                />
              </div>
            </template>
          </Column>
        </DataTable>
      </template>
    </Card>

    <!-- Create/Edit Dialog -->
    <Dialog
      v-model:visible="showCreateDialog"
      :header="editingSchedule ? 'Edit Schedule' : 'Create Schedule'"
      :style="{ width: '600px' }"
      modal
    >
      <div class="form-grid">
        <div class="form-field">
          <label>Schedule Name</label>
          <InputText
            v-model="form.name"
            placeholder="e.g., Daily Security Scan"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Application</label>
          <Dropdown
            v-model="form.app_id"
            :options="apps"
            optionLabel="app_name"
            optionValue="app_id"
            placeholder="Select an app"
            class="w-full"
            :disabled="!!editingSchedule"
          />
        </div>

        <div class="form-field">
          <label>Schedule (Cron Expression)</label>
          <div class="cron-input">
            <Dropdown
              v-model="selectedPreset"
              :options="cronPresets"
              optionLabel="label"
              optionValue="value"
              placeholder="Select preset..."
              class="w-full"
              @change="onPresetChange"
            />
            <InputText
              v-model="form.cron_expression"
              placeholder="0 2 * * *"
              class="w-full mt-2"
            />
          </div>
          <small class="text-gray-500">
            {{ cronDescription }}
          </small>
        </div>

        <div class="form-field">
          <label>Analyzers (leave empty for all)</label>
          <MultiSelect
            v-model="form.analyzers"
            :options="analyzerOptions"
            optionLabel="label"
            optionValue="value"
            placeholder="All analyzers"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Webhook URL (optional)</label>
          <InputText
            v-model="form.webhook_url"
            placeholder="https://your-webhook.com/notify"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Notification Email (optional)</label>
          <InputText
            v-model="form.notify_email"
            placeholder="security@example.com"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Status</label>
          <div class="flex align-items-center gap-2">
            <InputSwitch v-model="form.is_active" />
            <span>{{ form.is_active ? 'Active' : 'Paused' }}</span>
          </div>
        </div>
      </div>

      <template #footer>
        <Button
          label="Cancel"
          class="p-button-text"
          @click="closeDialog"
        />
        <Button
          :label="editingSchedule ? 'Update' : 'Create'"
          :loading="saving"
          @click="saveSchedule"
        />
      </template>
    </Dialog>

    <!-- Delete Confirmation -->
    <Dialog
      v-model:visible="showDeleteDialog"
      header="Confirm Delete"
      :style="{ width: '400px' }"
      modal
    >
      <p>Are you sure you want to delete this schedule?</p>
      <p class="text-gray-500">
        <strong>{{ scheduleToDelete?.name }}</strong>
      </p>

      <template #footer>
        <Button
          label="Cancel"
          class="p-button-text"
          @click="showDeleteDialog = false"
        />
        <Button
          label="Delete"
          class="p-button-danger"
          :loading="deleting"
          @click="deleteSchedule"
        />
      </template>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { scheduledScansApi, appsApi } from '@/services/api'

const toast = useToast()

// State
const schedules = ref<any[]>([])
const apps = ref<any[]>([])
const loading = ref(false)
const saving = ref(false)
const deleting = ref(false)
const totalRecords = ref(0)
const page = ref(1)

const showCreateDialog = ref(false)
const showDeleteDialog = ref(false)
const editingSchedule = ref<any>(null)
const scheduleToDelete = ref<any>(null)
const selectedPreset = ref('')

const form = ref({
  name: '',
  app_id: '',
  cron_expression: '0 2 * * *',
  analyzers: [],
  webhook_url: '',
  notify_email: '',
  is_active: true,
})

// Stats
const stats = computed(() => {
  const active = schedules.value.filter(s => s.is_active).length
  const paused = schedules.value.filter(s => !s.is_active).length
  return {
    active,
    paused,
    runsToday: 0, // Would need separate query
  }
})

const nextRunTime = computed(() => {
  const activeSchedules = schedules.value
    .filter(s => s.is_active && s.next_run_at)
    .sort((a, b) => new Date(a.next_run_at).getTime() - new Date(b.next_run_at).getTime())

  if (activeSchedules.length === 0) return '-'

  const next = new Date(activeSchedules[0].next_run_at)
  const now = new Date()
  const diff = next.getTime() - now.getTime()

  if (diff < 3600000) {
    return `${Math.floor(diff / 60000)}m`
  } else if (diff < 86400000) {
    return `${Math.floor(diff / 3600000)}h`
  } else {
    return `${Math.floor(diff / 86400000)}d`
  }
})

// Cron presets
const cronPresets = [
  { label: 'Every hour', value: '0 * * * *' },
  { label: 'Every 6 hours', value: '0 */6 * * *' },
  { label: 'Daily at midnight', value: '0 0 * * *' },
  { label: 'Daily at 2 AM', value: '0 2 * * *' },
  { label: 'Weekly on Monday', value: '0 0 * * 1' },
  { label: 'Monthly on the 1st', value: '0 0 1 * *' },
  { label: 'Custom', value: '' },
]

const analyzerOptions = [
  { label: 'DEX Analyzer', value: 'dex_analyzer' },
  { label: 'Manifest Analyzer', value: 'manifest_analyzer' },
  { label: 'Plist Analyzer', value: 'plist_analyzer' },
  { label: 'Binary Analyzer', value: 'binary_analyzer' },
  { label: 'Secret Scanner', value: 'secret_scanner' },
  { label: 'Crypto Auditor', value: 'crypto_auditor' },
  { label: 'Privacy Analyzer', value: 'privacy_analyzer' },
  { label: 'Dependency Scanner', value: 'dependency_analyzer' },
  { label: 'IPC Scanner', value: 'ipc_scanner' },
  { label: 'WebView Auditor', value: 'webview_auditor' },
]

const cronDescription = computed(() => {
  const preset = cronPresets.find(p => p.value === form.value.cron_expression)
  return preset ? preset.label : 'Custom schedule'
})

// Methods
async function fetchSchedules() {
  loading.value = true
  try {
    const response = await scheduledScansApi.list({ page: page.value, page_size: 20 })
    schedules.value = response.items
    totalRecords.value = response.total
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to load schedules',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

async function fetchApps() {
  try {
    const response = await appsApi.list({ page: 1, page_size: 100 })
    apps.value = response.data?.apps || response.data?.items || []
  } catch (error) {
    console.error('Failed to load apps:', error)
  }
}

function onPage(event: any) {
  page.value = (event?.page ?? 0) + 1
  fetchSchedules()
}

function onPresetChange(event: any) {
  if (event.value) {
    form.value.cron_expression = event.value
  }
}

function editSchedule(schedule: any) {
  editingSchedule.value = schedule
  form.value = {
    name: schedule.name,
    app_id: schedule.app_id,
    cron_expression: schedule.cron_expression,
    analyzers: schedule.analyzers || [],
    webhook_url: schedule.webhook_url || '',
    notify_email: schedule.notify_email || '',
    is_active: schedule.is_active,
  }
  showCreateDialog.value = true
}

async function saveSchedule() {
  if (!form.value.name || !form.value.app_id || !form.value.cron_expression) {
    toast.add({
      severity: 'warn',
      summary: 'Validation',
      detail: 'Please fill in all required fields',
      life: 3000,
    })
    return
  }

  saving.value = true
  try {
    if (editingSchedule.value) {
      await scheduledScansApi.update(editingSchedule.value.schedule_id, form.value)
      toast.add({
        severity: 'success',
        summary: 'Success',
        detail: 'Schedule updated',
        life: 3000,
      })
    } else {
      await scheduledScansApi.create(form.value)
      toast.add({
        severity: 'success',
        summary: 'Success',
        detail: 'Schedule created',
        life: 3000,
      })
    }
    closeDialog()
    fetchSchedules()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: error.response?.data?.detail || 'Failed to save schedule',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function closeDialog() {
  showCreateDialog.value = false
  editingSchedule.value = null
  selectedPreset.value = ''
  form.value = {
    name: '',
    app_id: '',
    cron_expression: '0 2 * * *',
    analyzers: [],
    webhook_url: '',
    notify_email: '',
    is_active: true,
  }
}

async function toggleActive(schedule: any) {
  try {
    if (schedule.is_active) {
      await scheduledScansApi.pause(schedule.schedule_id)
    } else {
      await scheduledScansApi.resume(schedule.schedule_id)
    }
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: schedule.is_active ? 'Schedule paused' : 'Schedule resumed',
      life: 3000,
    })
    fetchSchedules()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to update schedule',
      life: 3000,
    })
  }
}

async function runNow(schedule: any) {
  try {
    const result = await scheduledScansApi.trigger(schedule.schedule_id)
    toast.add({
      severity: 'success',
      summary: 'Scan Started',
      detail: `Scan ${result.scan_id} triggered`,
      life: 3000,
    })
    fetchSchedules()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to trigger scan',
      life: 3000,
    })
  }
}

function confirmDelete(schedule: any) {
  scheduleToDelete.value = schedule
  showDeleteDialog.value = true
}

async function deleteSchedule() {
  if (!scheduleToDelete.value) return

  deleting.value = true
  try {
    await scheduledScansApi.delete(scheduleToDelete.value.schedule_id)
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: 'Schedule deleted',
      life: 3000,
    })
    showDeleteDialog.value = false
    scheduleToDelete.value = null
    fetchSchedules()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to delete schedule',
      life: 3000,
    })
  } finally {
    deleting.value = false
  }
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

function formatRelativeTime(dateStr: string) {
  const date = new Date(dateStr)
  const now = new Date()
  const diff = now.getTime() - date.getTime()

  if (diff < 60000) return 'Just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

onMounted(() => {
  fetchSchedules()
  fetchApps()
})
</script>

<style scoped>
.scheduled-scans-view {
  padding: 1.5rem;
}

.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1.5rem;
}

.header h1 {
  margin: 0;
  font-size: 1.5rem;
}

.stats-cards {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.stat-card {
  text-align: center;
}

.stat-value {
  font-size: 2rem;
  font-weight: 600;
  color: var(--primary-color);
}

.stat-label {
  font-size: 0.875rem;
  color: var(--text-color-secondary);
}

.schedule-name {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.action-buttons {
  display: flex;
  gap: 0.25rem;
}

.form-grid {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.form-field label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 500;
}

.cron-input {
  display: flex;
  flex-direction: column;
}

@media (max-width: 768px) {
  .stats-cards {
    grid-template-columns: repeat(2, 1fr);
  }
}
</style>
