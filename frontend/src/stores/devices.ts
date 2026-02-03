import { defineStore } from 'pinia'
import { ref } from 'vue'
import { devicesApi } from '@/services/api'

export interface Device {
  device_id: string
  device_type: 'physical' | 'emulator' | 'corellium'
  platform: 'android' | 'ios'
  device_name: string | null
  model: string | null
  os_version: string | null
  connection_type: string | null
  connection_string: string | null
  corellium_instance_id: string | null
  corellium_project_id: string | null
  status: 'connected' | 'disconnected' | 'busy' | 'error'
  last_seen: string | null
  is_rooted: boolean
  is_jailbroken: boolean
  frida_server_version: string | null
  frida_server_status: string | null
  created_at: string
  updated_at: string
}

export const useDevicesStore = defineStore('devices', () => {
  const devices = ref<Device[]>([])
  const currentDevice = ref<Device | null>(null)
  const loading = ref(false)
  const discovering = ref(false)
  const error = ref<string | null>(null)
  const pagination = ref({
    page: 1,
    pageSize: 20,
    total: 0,
    pages: 0,
  })

  async function fetchDevices() {
    loading.value = true
    error.value = null
    try {
      const response = await devicesApi.list({
        page: pagination.value.page,
        page_size: pagination.value.pageSize,
      })
      devices.value = response.data.items
      pagination.value = {
        page: response.data.page,
        pageSize: response.data.page_size,
        total: response.data.total,
        pages: response.data.pages,
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch devices'
    } finally {
      loading.value = false
    }
  }

  async function fetchDevice(id: string) {
    loading.value = true
    error.value = null
    try {
      const response = await devicesApi.get(id)
      currentDevice.value = response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch device'
    } finally {
      loading.value = false
    }
  }

  async function discoverDevices() {
    discovering.value = true
    error.value = null
    try {
      const response = await devicesApi.discover()
      await fetchDevices()
      return response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to discover devices'
      throw e
    } finally {
      discovering.value = false
    }
  }

  async function connectDevice(id: string) {
    try {
      await devicesApi.connect(id)
      const device = devices.value.find((d) => d.device_id === id)
      if (device) {
        device.status = 'connected'
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to connect device'
      throw e
    }
  }

  async function installFrida(id: string) {
    try {
      const response = await devicesApi.installFrida(id)
      const device = devices.value.find((d) => d.device_id === id)
      if (device) {
        device.frida_server_status = 'installed'
      }
      return response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to install Frida'
      throw e
    }
  }

  async function startFrida(id: string) {
    try {
      await devicesApi.startFrida(id)
      const device = devices.value.find((d) => d.device_id === id)
      if (device) {
        device.frida_server_status = 'running'
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to start Frida'
      throw e
    }
  }

  async function deleteDevice(id: string) {
    try {
      await devicesApi.delete(id)
      devices.value = devices.value.filter((d) => d.device_id !== id)
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to delete device'
      throw e
    }
  }

  return {
    devices,
    currentDevice,
    loading,
    discovering,
    error,
    pagination,
    fetchDevices,
    fetchDevice,
    discoverDevices,
    connectDevice,
    installFrida,
    startFrida,
    deleteDevice,
  }
})
