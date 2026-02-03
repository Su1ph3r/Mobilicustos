/**
 * Tests for the apps store
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useAppsStore } from '@/stores/apps'
import * as api from '@/services/api'
import { mockAxiosResponse, mockPaginatedResponse, mockEmptyResponse } from '../helpers'

// Mock the API module
vi.mock('@/services/api', () => ({
  appsApi: {
    list: vi.fn(),
    get: vi.fn(),
    upload: vi.fn(),
    delete: vi.fn(),
    getStats: vi.fn(),
  },
}))

describe('Apps Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('should have empty apps array', () => {
      const store = useAppsStore()
      expect(store.apps).toEqual([])
    })

    it('should have null currentApp', () => {
      const store = useAppsStore()
      expect(store.currentApp).toBeNull()
    })

    it('should not be loading', () => {
      const store = useAppsStore()
      expect(store.loading).toBe(false)
    })

    it('should have default pagination', () => {
      const store = useAppsStore()
      expect(store.pagination.page).toBe(1)
      expect(store.pagination.pageSize).toBe(20)
    })
  })

  describe('fetchApps', () => {
    it('should fetch apps and update state', async () => {
      const mockApps = [
        { app_id: '1', package_name: 'com.test.app1', platform: 'android' },
        { app_id: '2', package_name: 'com.test.app2', platform: 'ios' },
      ]

      vi.mocked(api.appsApi.list).mockResolvedValue(
        mockPaginatedResponse(mockApps, 1, 20, 2)
      )

      const store = useAppsStore()
      await store.fetchApps()

      expect(store.apps).toEqual(mockApps)
      expect(store.pagination.total).toBe(2)
      expect(store.loading).toBe(false)
    })

    it('should set error on failure', async () => {
      vi.mocked(api.appsApi.list).mockRejectedValue({
        response: { data: { detail: 'Failed to fetch' } },
      })

      const store = useAppsStore()
      await store.fetchApps()

      expect(store.error).toBe('Failed to fetch')
      expect(store.loading).toBe(false)
    })

    it('should set loading state during fetch', async () => {
      let resolvePromise: (value: any) => void
      const promise = new Promise((resolve) => {
        resolvePromise = resolve
      })

      vi.mocked(api.appsApi.list).mockReturnValue(promise as any)

      const store = useAppsStore()
      const fetchPromise = store.fetchApps()

      expect(store.loading).toBe(true)

      resolvePromise!(mockPaginatedResponse([], 1, 20, 0))

      await fetchPromise
      expect(store.loading).toBe(false)
    })
  })

  describe('fetchApp', () => {
    it('should fetch single app', async () => {
      const mockApp = {
        app_id: '1',
        package_name: 'com.test.app',
        platform: 'android',
      }

      vi.mocked(api.appsApi.get).mockResolvedValue(mockAxiosResponse(mockApp))

      const store = useAppsStore()
      await store.fetchApp('1')

      expect(store.currentApp).toEqual(mockApp)
      expect(api.appsApi.get).toHaveBeenCalledWith('1')
    })
  })

  describe('uploadApp', () => {
    it('should upload app and add to list', async () => {
      const mockFile = new File(['test'], 'test.apk', {
        type: 'application/vnd.android.package-archive',
      })
      const mockApp = {
        app_id: 'new-1',
        package_name: 'com.new.app',
        platform: 'android',
      }

      vi.mocked(api.appsApi.upload).mockResolvedValue(mockAxiosResponse(mockApp))

      const store = useAppsStore()
      const result = await store.uploadApp(mockFile)

      expect(result).toEqual(mockApp)
      expect(store.apps[0]).toEqual(mockApp)
    })

    it('should throw on upload failure', async () => {
      const mockFile = new File(['test'], 'test.apk')

      vi.mocked(api.appsApi.upload).mockRejectedValue({
        response: { data: { detail: 'Upload failed' } },
      })

      const store = useAppsStore()

      await expect(store.uploadApp(mockFile)).rejects.toThrow()
      expect(store.error).toBe('Upload failed')
    })
  })

  describe('deleteApp', () => {
    it('should delete app and remove from list', async () => {
      const store = useAppsStore()
      store.apps = [
        { app_id: '1', package_name: 'app1' } as any,
        { app_id: '2', package_name: 'app2' } as any,
      ]

      vi.mocked(api.appsApi.delete).mockResolvedValue(mockEmptyResponse())

      await store.deleteApp('1')

      expect(store.apps).toHaveLength(1)
      expect(store.apps[0].app_id).toBe('2')
    })
  })

  describe('filters', () => {
    it('should set filters and reset page', async () => {
      vi.mocked(api.appsApi.list).mockResolvedValue(
        mockPaginatedResponse([], 1, 20, 0)
      )

      const store = useAppsStore()
      store.pagination.page = 5

      store.setFilters({ platform: 'android' })

      expect(store.filters.platform).toBe('android')
      expect(store.pagination.page).toBe(1)
    })
  })
})
