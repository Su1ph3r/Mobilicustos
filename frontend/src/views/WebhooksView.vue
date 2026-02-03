<template>
  <div class="webhooks-view">
    <div class="header">
      <h1>Webhooks</h1>
      <Button
        label="New Webhook"
        icon="pi pi-plus"
        @click="showCreateDialog = true"
      />
    </div>

    <div class="info-banner">
      <i class="pi pi-info-circle"></i>
      <div>
        <strong>Webhooks</strong> allow you to receive real-time notifications when events occur in Mobilicustos.
        Configure URLs to receive POST requests with event data.
      </div>
    </div>

    <Card>
      <template #content>
        <DataTable
          :value="webhooks"
          :loading="loading"
          :paginator="true"
          :rows="20"
          responsiveLayout="scroll"
          stripedRows
        >
          <Column field="name" header="Name" sortable>
            <template #body="{ data }">
              <div class="webhook-name">
                <i
                  :class="data.is_active ? 'pi pi-link text-green-500' : 'pi pi-unlink text-gray-500'"
                />
                {{ data.name }}
              </div>
            </template>
          </Column>

          <Column field="url" header="URL">
            <template #body="{ data }">
              <code class="url-code">{{ truncateUrl(data.url) }}</code>
            </template>
          </Column>

          <Column field="events" header="Events">
            <template #body="{ data }">
              <div class="event-tags">
                <Tag
                  v-for="event in data.events?.slice(0, 3)"
                  :key="event"
                  :value="formatEventName(event)"
                  severity="info"
                  class="mr-1"
                />
                <Tag
                  v-if="data.events?.length > 3"
                  :value="`+${data.events.length - 3}`"
                  severity="secondary"
                />
              </div>
            </template>
          </Column>

          <Column header="Stats" style="width: 150px">
            <template #body="{ data }">
              <div class="stats-inline">
                <span class="text-green-500">
                  <i class="pi pi-check"></i> {{ data.success_count || 0 }}
                </span>
                <span class="text-red-500">
                  <i class="pi pi-times"></i> {{ data.failure_count || 0 }}
                </span>
              </div>
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

          <Column header="Actions" style="width: 200px">
            <template #body="{ data }">
              <div class="action-buttons">
                <Button
                  icon="pi pi-send"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="'Test'"
                  @click="testWebhook(data)"
                  :loading="testingId === data.webhook_id"
                />
                <Button
                  :icon="data.is_active ? 'pi pi-pause' : 'pi pi-play'"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="data.is_active ? 'Pause' : 'Resume'"
                  @click="toggleActive(data)"
                />
                <Button
                  icon="pi pi-key"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="'Regenerate Secret'"
                  @click="regenerateSecret(data)"
                />
                <Button
                  icon="pi pi-pencil"
                  class="p-button-sm p-button-text"
                  v-tooltip.top="'Edit'"
                  @click="editWebhook(data)"
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
      :header="editingWebhook ? 'Edit Webhook' : 'Create Webhook'"
      :style="{ width: '600px' }"
      modal
    >
      <div class="form-grid">
        <div class="form-field">
          <label>Webhook Name</label>
          <InputText
            v-model="form.name"
            placeholder="e.g., Slack Notifications"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Webhook URL</label>
          <InputText
            v-model="form.url"
            placeholder="https://your-server.com/webhook"
            class="w-full"
          />
        </div>

        <div class="form-field">
          <label>Events</label>
          <MultiSelect
            v-model="form.events"
            :options="eventOptions"
            optionLabel="label"
            optionValue="value"
            placeholder="Select events"
            class="w-full"
            display="chip"
          />
        </div>

        <div class="form-field">
          <label>Custom Headers (optional)</label>
          <div v-for="(header, index) in customHeaders" :key="index" class="header-row">
            <InputText
              v-model="header.key"
              placeholder="Header Name"
              class="w-5"
            />
            <InputText
              v-model="header.value"
              placeholder="Header Value"
              class="w-5"
            />
            <Button
              icon="pi pi-minus"
              class="p-button-sm p-button-danger p-button-text"
              @click="removeHeader(index)"
            />
          </div>
          <Button
            label="Add Header"
            icon="pi pi-plus"
            class="p-button-sm p-button-text"
            @click="addHeader"
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
          :label="editingWebhook ? 'Update' : 'Create'"
          :loading="saving"
          @click="saveWebhook"
        />
      </template>
    </Dialog>

    <!-- Secret Dialog -->
    <Dialog
      v-model:visible="showSecretDialog"
      header="Webhook Secret"
      :style="{ width: '500px' }"
      modal
    >
      <p class="mb-3">
        Use this secret to verify webhook signatures. The signature is included
        in the <code>X-Webhook-Signature</code> header.
      </p>
      <div class="secret-display">
        <code>{{ currentSecret }}</code>
        <Button
          icon="pi pi-copy"
          class="p-button-sm p-button-text"
          v-tooltip.top="'Copy'"
          @click="copySecret"
        />
      </div>
      <template #footer>
        <Button label="Close" @click="showSecretDialog = false" />
      </template>
    </Dialog>

    <!-- Delete Confirmation -->
    <Dialog
      v-model:visible="showDeleteDialog"
      header="Confirm Delete"
      :style="{ width: '400px' }"
      modal
    >
      <p>Are you sure you want to delete this webhook?</p>
      <p class="text-gray-500">
        <strong>{{ webhookToDelete?.name }}</strong>
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
          @click="deleteWebhook"
        />
      </template>
    </Dialog>

    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useToast } from 'primevue/usetoast'
import { webhooksApi } from '@/services/api'

const toast = useToast()

// State
const webhooks = ref<any[]>([])
const loading = ref(false)
const saving = ref(false)
const deleting = ref(false)
const testingId = ref<string | null>(null)

const showCreateDialog = ref(false)
const showDeleteDialog = ref(false)
const showSecretDialog = ref(false)
const editingWebhook = ref<any>(null)
const webhookToDelete = ref<any>(null)
const currentSecret = ref('')

const form = ref({
  name: '',
  url: '',
  events: [] as string[],
  is_active: true,
})

const customHeaders = ref<Array<{ key: string; value: string }>>([])

const eventOptions = [
  { label: 'Scan Started', value: 'scan.started' },
  { label: 'Scan Completed', value: 'scan.completed' },
  { label: 'Scan Failed', value: 'scan.failed' },
  { label: 'New Finding', value: 'finding.new' },
  { label: 'Finding Status Changed', value: 'finding.status_changed' },
  { label: 'App Uploaded', value: 'app.uploaded' },
  { label: 'Schedule Triggered', value: 'schedule.triggered' },
]

// Methods
async function fetchWebhooks() {
  loading.value = true
  try {
    const response = await webhooksApi.list({ page: 1, page_size: 100 })
    webhooks.value = response.items
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to load webhooks',
      life: 3000,
    })
  } finally {
    loading.value = false
  }
}

function editWebhook(webhook: any) {
  editingWebhook.value = webhook
  form.value = {
    name: webhook.name,
    url: webhook.url,
    events: webhook.events || [],
    is_active: webhook.is_active,
  }
  customHeaders.value = webhook.headers
    ? Object.entries(webhook.headers).map(([key, value]) => ({ key, value: value as string }))
    : []
  showCreateDialog.value = true
}

async function saveWebhook() {
  if (!form.value.name || !form.value.url || form.value.events.length === 0) {
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
    const headers = customHeaders.value.reduce((acc, h) => {
      if (h.key && h.value) acc[h.key] = h.value
      return acc
    }, {} as Record<string, string>)

    const payload = {
      ...form.value,
      headers: Object.keys(headers).length > 0 ? headers : undefined,
    }

    if (editingWebhook.value) {
      await webhooksApi.update(editingWebhook.value.webhook_id, payload)
      toast.add({
        severity: 'success',
        summary: 'Success',
        detail: 'Webhook updated',
        life: 3000,
      })
    } else {
      const result = await webhooksApi.create(payload)
      currentSecret.value = result.secret
      showSecretDialog.value = true
      toast.add({
        severity: 'success',
        summary: 'Success',
        detail: 'Webhook created',
        life: 3000,
      })
    }
    closeDialog()
    fetchWebhooks()
  } catch (error: any) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: error.response?.data?.detail || 'Failed to save webhook',
      life: 3000,
    })
  } finally {
    saving.value = false
  }
}

function closeDialog() {
  showCreateDialog.value = false
  editingWebhook.value = null
  form.value = {
    name: '',
    url: '',
    events: [],
    is_active: true,
  }
  customHeaders.value = []
}

async function toggleActive(webhook: any) {
  try {
    if (webhook.is_active) {
      await webhooksApi.pause(webhook.webhook_id)
    } else {
      await webhooksApi.resume(webhook.webhook_id)
    }
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: webhook.is_active ? 'Webhook paused' : 'Webhook resumed',
      life: 3000,
    })
    fetchWebhooks()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to update webhook',
      life: 3000,
    })
  }
}

async function testWebhook(webhook: any) {
  testingId.value = webhook.webhook_id
  try {
    const result = await webhooksApi.test(webhook.webhook_id)
    if (result.success) {
      toast.add({
        severity: 'success',
        summary: 'Test Successful',
        detail: `Delivered in ${result.duration_ms}ms`,
        life: 3000,
      })
    } else {
      toast.add({
        severity: 'error',
        summary: 'Test Failed',
        detail: `Status: ${result.status_code}`,
        life: 3000,
      })
    }
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to test webhook',
      life: 3000,
    })
  } finally {
    testingId.value = null
  }
}

async function regenerateSecret(webhook: any) {
  try {
    const result = await webhooksApi.regenerateSecret(webhook.webhook_id)
    currentSecret.value = result.secret
    showSecretDialog.value = true
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: 'Secret regenerated',
      life: 3000,
    })
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to regenerate secret',
      life: 3000,
    })
  }
}

function copySecret() {
  navigator.clipboard.writeText(currentSecret.value)
  toast.add({
    severity: 'success',
    summary: 'Copied',
    detail: 'Secret copied to clipboard',
    life: 2000,
  })
}

function confirmDelete(webhook: any) {
  webhookToDelete.value = webhook
  showDeleteDialog.value = true
}

async function deleteWebhook() {
  if (!webhookToDelete.value) return

  deleting.value = true
  try {
    await webhooksApi.delete(webhookToDelete.value.webhook_id)
    toast.add({
      severity: 'success',
      summary: 'Success',
      detail: 'Webhook deleted',
      life: 3000,
    })
    showDeleteDialog.value = false
    webhookToDelete.value = null
    fetchWebhooks()
  } catch (error) {
    toast.add({
      severity: 'error',
      summary: 'Error',
      detail: 'Failed to delete webhook',
      life: 3000,
    })
  } finally {
    deleting.value = false
  }
}

function addHeader() {
  customHeaders.value.push({ key: '', value: '' })
}

function removeHeader(index: number) {
  customHeaders.value.splice(index, 1)
}

function truncateUrl(url: string) {
  if (url.length > 50) {
    return url.substring(0, 47) + '...'
  }
  return url
}

function formatEventName(event: string) {
  return event.split('.').map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(' ')
}

onMounted(() => {
  fetchWebhooks()
})
</script>

<style scoped>
.webhooks-view {
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

.info-banner {
  display: flex;
  align-items: flex-start;
  gap: 1rem;
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
  margin-bottom: 1.5rem;
}

.info-banner i {
  font-size: 1.25rem;
  color: var(--primary-color);
}

.webhook-name {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.url-code {
  font-size: 0.75rem;
  background: var(--surface-ground);
  padding: 0.25rem 0.5rem;
  border-radius: 4px;
}

.event-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 0.25rem;
}

.stats-inline {
  display: flex;
  gap: 1rem;
  font-size: 0.875rem;
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

.header-row {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
  align-items: center;
}

.secret-display {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 8px;
  font-family: monospace;
}

.secret-display code {
  flex: 1;
  word-break: break-all;
}
</style>
