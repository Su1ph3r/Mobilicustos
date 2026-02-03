<template>
  <div class="devices-view">
    <div class="page-header">
      <div>
        <h1>Devices</h1>
        <p class="text-secondary">Connected devices for dynamic analysis</p>
      </div>
      <div class="header-actions">
        <Button
          label="Discover Devices"
          icon="pi pi-refresh"
          :loading="devicesStore.discovering"
          @click="discoverDevices"
        />
        <Button
          label="Register Device"
          icon="pi pi-plus"
          class="p-button-secondary"
          @click="showRegisterDialog = true"
        />
      </div>
    </div>

    <!-- Device Cards -->
    <div class="grid">
      <div v-for="device in devicesStore.devices" :key="device.device_id" class="col-12 md:col-6 lg:col-4">
        <div :class="['device-card', device.status]">
          <div class="device-header">
            <div class="device-icon">
              <i :class="getPlatformIcon(device.platform)"></i>
            </div>
            <div class="device-info">
              <h3>{{ device.device_name || device.device_id }}</h3>
              <p>{{ device.model || 'Unknown Model' }}</p>
            </div>
            <Tag :value="device.status" :severity="getStatusSeverity(device.status)" />
          </div>

          <div class="device-details">
            <div class="detail-row">
              <span class="detail-label">Platform</span>
              <span class="detail-value">{{ device.platform }} {{ device.os_version }}</span>
            </div>
            <div class="detail-row">
              <span class="detail-label">Type</span>
              <Tag :value="device.device_type" severity="secondary" />
            </div>
            <div class="detail-row">
              <span class="detail-label">Connection</span>
              <span class="detail-value">{{ device.connection_type || 'USB' }}</span>
            </div>
            <div v-if="device.platform === 'android'" class="detail-row">
              <span class="detail-label">Rooted</span>
              <Tag :value="device.is_rooted ? 'Yes' : 'No'" :severity="device.is_rooted ? 'success' : 'warning'" />
            </div>
            <div v-if="device.platform === 'ios'" class="detail-row">
              <span class="detail-label">Jailbroken</span>
              <Tag :value="device.is_jailbroken ? 'Yes' : 'No'" :severity="device.is_jailbroken ? 'success' : 'warning'" />
            </div>
          </div>

          <div class="frida-section">
            <div class="frida-header">
              <span class="frida-label">Frida Server</span>
              <Tag
                :value="device.frida_server_status || 'not installed'"
                :severity="getFridaStatusSeverity(device.frida_server_status)"
              />
            </div>
            <div v-if="device.frida_server_version" class="frida-version">
              Version: {{ device.frida_server_version }}
            </div>
          </div>

          <div class="device-actions">
            <Button
              v-if="device.status === 'disconnected'"
              label="Connect"
              icon="pi pi-link"
              class="p-button-sm"
              @click="connectDevice(device)"
            />
            <Button
              v-if="!device.frida_server_status || device.frida_server_status === 'not_installed'"
              label="Install Frida"
              icon="pi pi-download"
              class="p-button-sm p-button-secondary"
              @click="installFrida(device)"
            />
            <Button
              v-else-if="device.frida_server_status === 'installed'"
              label="Start Frida"
              icon="pi pi-play"
              class="p-button-sm p-button-success"
              @click="startFrida(device)"
            />
            <Button
              v-else-if="device.frida_server_status === 'running'"
              label="Running"
              icon="pi pi-check"
              class="p-button-sm p-button-success"
              disabled
            />
            <Button
              icon="pi pi-trash"
              class="p-button-sm p-button-danger p-button-text"
              v-tooltip="'Remove Device'"
              @click="confirmDelete(device)"
            />
          </div>
        </div>
      </div>

      <div v-if="devicesStore.devices.length === 0 && !devicesStore.loading" class="col-12">
        <div class="empty-state">
          <i class="pi pi-mobile"></i>
          <h3>No Devices Found</h3>
          <p>Connect a device via USB or register a remote device</p>
          <Button label="Discover Devices" icon="pi pi-refresh" @click="discoverDevices" />
        </div>
      </div>
    </div>

    <!-- Register Device Dialog -->
    <Dialog
      v-model:visible="showRegisterDialog"
      header="Register Device"
      :modal="true"
      :style="{ width: '500px' }"
    >
      <div class="register-form">
        <div class="field">
          <label>Device Type</label>
          <Dropdown
            v-model="newDevice.device_type"
            :options="deviceTypes"
            optionLabel="label"
            optionValue="value"
            placeholder="Select Type"
          />
        </div>
        <div class="field">
          <label>Platform</label>
          <Dropdown
            v-model="newDevice.platform"
            :options="platforms"
            optionLabel="label"
            optionValue="value"
            placeholder="Select Platform"
          />
        </div>
        <div class="field">
          <label>Device Name</label>
          <InputText v-model="newDevice.device_name" placeholder="My Device" />
        </div>
        <div v-if="newDevice.device_type === 'corellium'" class="field">
          <label>Corellium Instance ID</label>
          <InputText v-model="newDevice.corellium_instance_id" placeholder="Instance ID" />
        </div>
        <div v-if="newDevice.device_type === 'corellium'" class="field">
          <label>Corellium Project ID</label>
          <InputText v-model="newDevice.corellium_project_id" placeholder="Project ID" />
        </div>
        <div v-if="newDevice.device_type === 'genymotion'" class="field">
          <label>Genymotion IP Address</label>
          <InputText v-model="newDevice.connection_string" placeholder="192.168.X.X:5555" />
          <small class="hint-text">Found in Genymotion > Settings > Network</small>
        </div>
        <div v-else-if="newDevice.device_type !== 'corellium'" class="field">
          <label>Connection String</label>
          <InputText v-model="newDevice.connection_string" placeholder="e.g., 192.168.1.100:5555" />
        </div>
      </div>
      <template #footer>
        <Button label="Cancel" class="p-button-text" @click="showRegisterDialog = false" :disabled="registering" />
        <Button label="Register" icon="pi pi-plus" @click="registerDevice" :loading="registering" />
      </template>
    </Dialog>

    <ConfirmDialog />
    <Toast />
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useDevicesStore, type Device } from '@/stores/devices'
import { useConfirm } from 'primevue/useconfirm'
import { useToast } from 'primevue/usetoast'
import { devicesApi } from '@/services/api'
import Button from 'primevue/button'
import Tag from 'primevue/tag'
import Dialog from 'primevue/dialog'
import Dropdown from 'primevue/dropdown'
import InputText from 'primevue/inputtext'
import ConfirmDialog from 'primevue/confirmdialog'
import Toast from 'primevue/toast'

const devicesStore = useDevicesStore()
const confirm = useConfirm()
const toast = useToast()

const showRegisterDialog = ref(false)
const newDevice = ref({
  device_type: 'physical',
  platform: 'android',
  device_name: '',
  connection_string: '',
  corellium_instance_id: '',
  corellium_project_id: '',
})
const registering = ref(false)

const deviceTypes = [
  { label: 'Physical Device', value: 'physical' },
  { label: 'Emulator', value: 'emulator' },
  { label: 'Genymotion', value: 'genymotion' },
  { label: 'Corellium', value: 'corellium' },
]

const platforms = [
  { label: 'Android', value: 'android' },
  { label: 'iOS', value: 'ios' },
]

function getPlatformIcon(platform: string) {
  return platform === 'android' ? 'pi pi-android' : 'pi pi-apple'
}

function getStatusSeverity(status: string) {
  switch (status) {
    case 'connected': return 'success'
    case 'busy': return 'warning'
    case 'error': return 'danger'
    default: return 'secondary'
  }
}

function getFridaStatusSeverity(status: string | null) {
  switch (status) {
    case 'running': return 'success'
    case 'installed': return 'info'
    case 'error': return 'danger'
    default: return 'secondary'
  }
}

async function discoverDevices() {
  try {
    await devicesStore.discoverDevices()
    toast.add({ severity: 'success', summary: 'Discovery Complete', detail: 'Devices refreshed', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to discover devices', life: 3000 })
  }
}

async function connectDevice(device: Device) {
  try {
    await devicesStore.connectDevice(device.device_id)
    toast.add({ severity: 'success', summary: 'Connected', detail: `${device.device_name} connected`, life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to connect device', life: 3000 })
  }
}

async function installFrida(device: Device) {
  try {
    await devicesStore.installFrida(device.device_id)
    toast.add({ severity: 'success', summary: 'Installed', detail: 'Frida server installed', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to install Frida', life: 3000 })
  }
}

async function startFrida(device: Device) {
  try {
    await devicesStore.startFrida(device.device_id)
    toast.add({ severity: 'success', summary: 'Started', detail: 'Frida server running', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to start Frida', life: 3000 })
  }
}

async function registerDevice() {
  if (registering.value) return
  registering.value = true
  try {
    await devicesApi.register(newDevice.value)
    await devicesStore.fetchDevices()
    showRegisterDialog.value = false
    newDevice.value = {
      device_type: 'physical',
      platform: 'android',
      device_name: '',
      connection_string: '',
      corellium_instance_id: '',
      corellium_project_id: '',
    }
    toast.add({ severity: 'success', summary: 'Registered', detail: 'Device registered', life: 2000 })
  } catch (e) {
    toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to register device', life: 3000 })
  } finally {
    registering.value = false
  }
}

function confirmDelete(device: Device) {
  confirm.require({
    message: `Remove ${device.device_name || device.device_id}?`,
    header: 'Remove Device',
    icon: 'pi pi-exclamation-triangle',
    acceptClass: 'p-button-danger',
    accept: async () => {
      try {
        await devicesStore.deleteDevice(device.device_id)
        toast.add({ severity: 'success', summary: 'Removed', detail: 'Device removed', life: 2000 })
      } catch (e) {
        toast.add({ severity: 'error', summary: 'Error', detail: 'Failed to remove device', life: 3000 })
      }
    },
  })
}

onMounted(() => {
  devicesStore.fetchDevices()
})
</script>

<style scoped>
.devices-view {
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

.device-card {
  background: var(--surface-card);
  border-radius: 8px;
  padding: 1.25rem;
  box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
  border-left: 4px solid var(--surface-border);
}

.device-card.connected {
  border-left-color: var(--green-500);
}

.device-card.busy {
  border-left-color: var(--yellow-500);
}

.device-card.error {
  border-left-color: var(--red-500);
}

.device-header {
  display: flex;
  align-items: center;
  gap: 1rem;
  margin-bottom: 1rem;
}

.device-icon {
  width: 48px;
  height: 48px;
  border-radius: 50%;
  background: var(--primary-color);
  display: flex;
  align-items: center;
  justify-content: center;
  color: white;
  font-size: 1.5rem;
}

.device-info {
  flex: 1;
}

.device-info h3 {
  margin: 0;
  font-size: 1.1rem;
}

.device-info p {
  margin: 0;
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.device-details {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
  margin-bottom: 1rem;
  padding: 1rem;
  background: var(--surface-ground);
  border-radius: 4px;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.detail-label {
  font-size: 0.85rem;
  color: var(--text-color-secondary);
}

.detail-value {
  font-weight: 500;
}

.frida-section {
  padding: 0.75rem;
  background: var(--surface-ground);
  border-radius: 4px;
  margin-bottom: 1rem;
}

.frida-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.frida-label {
  font-weight: 600;
}

.frida-version {
  font-size: 0.8rem;
  color: var(--text-color-secondary);
  margin-top: 0.25rem;
}

.device-actions {
  display: flex;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.empty-state {
  text-align: center;
  padding: 3rem;
  background: var(--surface-card);
  border-radius: 8px;
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
  margin-bottom: 1rem;
}

.register-form .field {
  margin-bottom: 1rem;
}

.register-form label {
  display: block;
  margin-bottom: 0.5rem;
  font-weight: 600;
}

.register-form .p-inputtext,
.register-form .p-dropdown {
  width: 100%;
}

.hint-text {
  display: block;
  margin-top: 0.25rem;
  font-size: 0.75rem;
  color: var(--text-color-secondary);
}
</style>
