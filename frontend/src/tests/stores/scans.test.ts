/**
 * Tests for the scans store
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useScansStore } from '@/stores/scans'
import * as api from '@/services/api'
import { mockAxiosResponse, mockPaginatedResponse, mockEmptyResponse } from '../helpers'

// Mock the API module
vi.mock('@/services/api', () => ({
  scansApi: {
    list: vi.fn(),
    get: vi.fn(),
    create: vi.fn(),
    cancel: vi.fn(),
    delete: vi.fn(),
    getProgress: vi.fn(),
  },
}))

describe('Scans Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('should have empty scans array', () => {
      const store = useScansStore()
      expect(store.scans).toEqual([])
    })

    it('should have null currentScan', () => {
      const store = useScansStore()
      expect(store.currentScan).toBeNull()
    })

    it('should have default filters', () => {
      const store = useScansStore()
      expect(store.filters.app_id).toBeNull()
      expect(store.filters.status).toBeNull()
      expect(store.filters.scan_type).toBeNull()
    })
  })

  describe('fetchScans', () => {
    it('should fetch scans', async () => {
      const mockScans = [
        {
          scan_id: 's1',
          app_id: 'a1',
          scan_type: 'static',
          status: 'completed',
          progress: 100,
        },
      ]

      vi.mocked(api.scansApi.list).mockResolvedValue(
        mockPaginatedResponse(mockScans, 1, 20, 1)
      )

      const store = useScansStore()
      await store.fetchScans()

      expect(store.scans).toEqual(mockScans)
    })
  })

  describe('createScan', () => {
    it('should create scan and add to list', async () => {
      const mockScan = {
        scan_id: 'new-scan',
        app_id: 'a1',
        scan_type: 'static',
        status: 'pending',
        progress: 0,
      }

      vi.mocked(api.scansApi.create).mockResolvedValue(mockAxiosResponse(mockScan))

      const store = useScansStore()
      const result = await store.createScan({
        app_id: 'a1',
        scan_type: 'static',
      })

      expect(result).toEqual(mockScan)
      expect(store.scans[0]).toEqual(mockScan)
    })

    it('should include analyzers if provided', async () => {
      vi.mocked(api.scansApi.create).mockResolvedValue(
        mockAxiosResponse({ scan_id: 's1', status: 'pending' })
      )

      const store = useScansStore()
      await store.createScan({
        app_id: 'a1',
        scan_type: 'static',
        analyzers_enabled: ['manifest_analyzer', 'secret_scanner'],
      })

      expect(api.scansApi.create).toHaveBeenCalledWith({
        app_id: 'a1',
        scan_type: 'static',
        analyzers_enabled: ['manifest_analyzer', 'secret_scanner'],
      })
    })
  })

  describe('cancelScan', () => {
    it('should cancel scan and update status', async () => {
      vi.mocked(api.scansApi.cancel).mockResolvedValue(mockEmptyResponse())

      const store = useScansStore()
      store.scans = [
        { scan_id: 's1', status: 'running' } as any,
      ]

      await store.cancelScan('s1')

      expect(store.scans[0].status).toBe('cancelled')
    })

    it('should update currentScan if matching', async () => {
      vi.mocked(api.scansApi.cancel).mockResolvedValue(mockEmptyResponse())

      const store = useScansStore()
      store.currentScan = { scan_id: 's1', status: 'running' } as any

      await store.cancelScan('s1')

      expect(store.currentScan!.status).toBe('cancelled')
    })
  })

  describe('refreshScanProgress', () => {
    it('should update scan progress', async () => {
      const progressData = {
        status: 'running',
        progress: 50,
        current_analyzer: 'secret_scanner',
        findings_count: { critical: 1, high: 2, medium: 3, low: 4, info: 5 },
      }

      vi.mocked(api.scansApi.getProgress).mockResolvedValue(mockAxiosResponse(progressData))

      const store = useScansStore()
      store.scans = [
        {
          scan_id: 's1',
          status: 'running',
          progress: 25,
          current_analyzer: 'manifest_analyzer',
          findings_count: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        } as any,
      ]

      const result = await store.refreshScanProgress('s1')

      expect(store.scans[0].progress).toBe(50)
      expect(store.scans[0].current_analyzer).toBe('secret_scanner')
      expect(result).toEqual(progressData)
    })
  })

  describe('deleteScan', () => {
    it('should delete scan from list', async () => {
      vi.mocked(api.scansApi.delete).mockResolvedValue(mockEmptyResponse())

      const store = useScansStore()
      store.scans = [
        { scan_id: 's1' } as any,
        { scan_id: 's2' } as any,
      ]

      await store.deleteScan('s1')

      expect(store.scans).toHaveLength(1)
      expect(store.scans[0].scan_id).toBe('s2')
    })
  })

  describe('setFilters', () => {
    it('should set filters and reset page', async () => {
      vi.mocked(api.scansApi.list).mockResolvedValue(
        mockPaginatedResponse([], 1, 20, 0)
      )

      const store = useScansStore()
      store.pagination.page = 3

      store.setFilters({ status: 'running' })

      expect(store.filters.status).toBe('running')
      expect(store.pagination.page).toBe(1)
    })
  })
})
