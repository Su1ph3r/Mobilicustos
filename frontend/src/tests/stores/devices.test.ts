/**
 * Tests for the devices store
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useDevicesStore } from '@/stores/devices'
import * as api from '@/services/api'
import { mockAxiosResponse, mockPaginatedResponse, mockEmptyResponse } from '../helpers'

// Mock the API module
vi.mock('@/services/api', () => ({
  devicesApi: {
    list: vi.fn(),
    get: vi.fn(),
    discover: vi.fn(),
    connect: vi.fn(),
    installFrida: vi.fn(),
    startFrida: vi.fn(),
    delete: vi.fn(),
  },
}))

describe('Devices Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('should have empty devices array', () => {
      const store = useDevicesStore()
      expect(store.devices).toEqual([])
    })

    it('should not be discovering', () => {
      const store = useDevicesStore()
      expect(store.discovering).toBe(false)
    })
  })

  describe('fetchDevices', () => {
    it('should fetch devices', async () => {
      const mockDevices = [
        {
          device_id: 'd1',
          device_name: 'Pixel 6',
          platform: 'android',
          status: 'connected',
        },
      ]

      vi.mocked(api.devicesApi.list).mockResolvedValue(
        mockPaginatedResponse(mockDevices, 1, 20, 1)
      )

      const store = useDevicesStore()
      await store.fetchDevices()

      expect(store.devices).toEqual(mockDevices)
    })
  })

  describe('discoverDevices', () => {
    it('should discover devices and refresh list', async () => {
      const mockDiscovered = { discovered: 2 }

      vi.mocked(api.devicesApi.discover).mockResolvedValue(mockAxiosResponse(mockDiscovered))
      vi.mocked(api.devicesApi.list).mockResolvedValue(
        mockPaginatedResponse([], 1, 20, 0)
      )

      const store = useDevicesStore()
      const result = await store.discoverDevices()

      expect(result).toEqual(mockDiscovered)
      expect(store.discovering).toBe(false)
      expect(api.devicesApi.list).toHaveBeenCalled()
    })

    it('should set discovering state', async () => {
      let resolvePromise: (value: any) => void
      const promise = new Promise((resolve) => {
        resolvePromise = resolve
      })

      vi.mocked(api.devicesApi.discover).mockReturnValue(promise as any)

      const store = useDevicesStore()
      const discoverPromise = store.discoverDevices()

      expect(store.discovering).toBe(true)

      resolvePromise!(mockAxiosResponse({ discovered: 0 }))
      vi.mocked(api.devicesApi.list).mockResolvedValue(
        mockPaginatedResponse([], 1, 20, 0)
      )

      await discoverPromise
      expect(store.discovering).toBe(false)
    })
  })

  describe('connectDevice', () => {
    it('should connect device and update status', async () => {
      vi.mocked(api.devicesApi.connect).mockResolvedValue(mockEmptyResponse())

      const store = useDevicesStore()
      store.devices = [
        { device_id: 'd1', status: 'disconnected' } as any,
      ]

      await store.connectDevice('d1')

      expect(store.devices[0].status).toBe('connected')
    })
  })

  describe('installFrida', () => {
    it('should install Frida and update status', async () => {
      vi.mocked(api.devicesApi.installFrida).mockResolvedValue(
        mockAxiosResponse({ version: '16.0.0' })
      )

      const store = useDevicesStore()
      store.devices = [
        { device_id: 'd1', frida_server_status: null } as any,
      ]

      const result = await store.installFrida('d1')

      expect(store.devices[0].frida_server_status).toBe('installed')
      expect(result).toEqual({ version: '16.0.0' })
    })
  })

  describe('startFrida', () => {
    it('should start Frida and update status', async () => {
      vi.mocked(api.devicesApi.startFrida).mockResolvedValue(mockEmptyResponse())

      const store = useDevicesStore()
      store.devices = [
        { device_id: 'd1', frida_server_status: 'installed' } as any,
      ]

      await store.startFrida('d1')

      expect(store.devices[0].frida_server_status).toBe('running')
    })
  })

  describe('deleteDevice', () => {
    it('should delete device from list', async () => {
      vi.mocked(api.devicesApi.delete).mockResolvedValue(mockEmptyResponse())

      const store = useDevicesStore()
      store.devices = [
        { device_id: 'd1' } as any,
        { device_id: 'd2' } as any,
      ]

      await store.deleteDevice('d1')

      expect(store.devices).toHaveLength(1)
      expect(store.devices[0].device_id).toBe('d2')
    })
  })
})
