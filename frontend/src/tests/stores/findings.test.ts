/**
 * Tests for the findings store
 */

import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useFindingsStore } from '@/stores/findings'
import * as api from '@/services/api'
import { mockAxiosResponse, mockPaginatedResponse, mockEmptyResponse } from '../helpers'

// Mock the API module
vi.mock('@/services/api', () => ({
  findingsApi: {
    list: vi.fn(),
    get: vi.fn(),
    getSummary: vi.fn(),
    updateStatus: vi.fn(),
    bulkUpdateStatus: vi.fn(),
    getFilterOptions: vi.fn(),
  },
}))

describe('Findings Store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  describe('initial state', () => {
    it('should have empty findings array', () => {
      const store = useFindingsStore()
      expect(store.findings).toEqual([])
    })

    it('should have null summary', () => {
      const store = useFindingsStore()
      expect(store.summary).toBeNull()
    })

    it('should have default filters', () => {
      const store = useFindingsStore()
      expect(store.filters.severity).toBeNull()
      expect(store.filters.status).toBeNull()
    })

    it('should have hasFilters computed as false initially', () => {
      const store = useFindingsStore()
      expect(store.hasFilters).toBe(false)
    })
  })

  describe('hasFilters computed property', () => {
    it('should return false when no filters are set', () => {
      const store = useFindingsStore()
      expect(store.hasFilters).toBe(false)
    })

    it('should return true when severity filter is set', () => {
      const store = useFindingsStore()
      store.filters.severity = ['critical']
      expect(store.hasFilters).toBe(true)
    })

    it('should return true when status filter is set', () => {
      const store = useFindingsStore()
      store.filters.status = ['open', 'confirmed']
      expect(store.hasFilters).toBe(true)
    })

    it('should return true when tool filter is set', () => {
      const store = useFindingsStore()
      store.filters.tool = ['mobsf']
      expect(store.hasFilters).toBe(true)
    })

    it('should return true when search filter is set', () => {
      const store = useFindingsStore()
      store.filters.search = 'sql injection'
      expect(store.hasFilters).toBe(true)
    })

    it('should return true when category filter is set', () => {
      const store = useFindingsStore()
      store.filters.category = ['Insecure Data Storage']
      expect(store.hasFilters).toBe(true)
    })

    it('should return true when owasp_masvs_category filter is set', () => {
      const store = useFindingsStore()
      store.filters.owasp_masvs_category = ['MASVS-STORAGE']
      expect(store.hasFilters).toBe(true)
    })

    it('should return false when only app_id is set', () => {
      const store = useFindingsStore()
      store.filters.app_id = 'app-123'
      expect(store.hasFilters).toBe(false)
    })

    it('should return false when only scan_id is set', () => {
      const store = useFindingsStore()
      store.filters.scan_id = 'scan-123'
      expect(store.hasFilters).toBe(false)
    })

    it('should return false when filters are empty arrays', () => {
      const store = useFindingsStore()
      store.filters.severity = []
      store.filters.status = []
      expect(store.hasFilters).toBe(false)
    })

    it('should return false when search is empty string', () => {
      const store = useFindingsStore()
      store.filters.search = ''
      expect(store.hasFilters).toBe(false)
    })

    it('should return true with multiple filters set', () => {
      const store = useFindingsStore()
      store.filters.severity = ['high', 'critical']
      store.filters.status = ['open']
      store.filters.search = 'hardcoded'
      expect(store.hasFilters).toBe(true)
    })
  })

  describe('fetchFindings', () => {
    it('should fetch findings and update state', async () => {
      const mockFindings = [
        {
          finding_id: 'f1',
          severity: 'high',
          title: 'Test Finding 1',
        },
        {
          finding_id: 'f2',
          severity: 'medium',
          title: 'Test Finding 2',
        },
      ]

      vi.mocked(api.findingsApi.list).mockResolvedValue(
        mockPaginatedResponse(mockFindings, 1, 20, 2)
      )

      const store = useFindingsStore()
      await store.fetchFindings()

      expect(store.findings).toEqual(mockFindings)
      expect(store.pagination.total).toBe(2)
    })

    it('should include filters in request', async () => {
      vi.mocked(api.findingsApi.list).mockResolvedValue(
        mockPaginatedResponse([], 1, 20, 0)
      )

      const store = useFindingsStore()
      store.filters.severity = ['high', 'critical']
      store.filters.app_id = 'test-app'

      await store.fetchFindings()

      expect(api.findingsApi.list).toHaveBeenCalledWith(
        expect.objectContaining({
          severity: ['high', 'critical'],
          app_id: 'test-app',
        })
      )
    })
  })

  describe('fetchSummary', () => {
    it('should fetch summary', async () => {
      const mockSummary = {
        total: 100,
        by_severity: { critical: 5, high: 20, medium: 40, low: 30, info: 5 },
        by_status: { open: 80, confirmed: 10, mitigated: 10 },
        by_category: { 'Storage': 30, 'Network': 25 },
        by_masvs: { 'MASVS-STORAGE': 30, 'MASVS-NETWORK': 25 },
        by_tool: { manifest_analyzer: 50, secret_scanner: 50 },
      }

      vi.mocked(api.findingsApi.getSummary).mockResolvedValue(mockAxiosResponse(mockSummary))

      const store = useFindingsStore()
      await store.fetchSummary()

      expect(store.summary).toEqual(mockSummary)
    })

    it('should accept app_id filter', async () => {
      vi.mocked(api.findingsApi.getSummary).mockResolvedValue(
        mockAxiosResponse({ total: 10, by_severity: {}, by_status: {}, by_category: {}, by_masvs: {}, by_tool: {} })
      )

      const store = useFindingsStore()
      await store.fetchSummary({ app_id: 'test-app' })

      expect(api.findingsApi.getSummary).toHaveBeenCalledWith({ app_id: 'test-app' })
    })
  })

  describe('updateStatus', () => {
    it('should update finding status', async () => {
      vi.mocked(api.findingsApi.updateStatus).mockResolvedValue(mockEmptyResponse())

      const store = useFindingsStore()
      store.findings = [
        { finding_id: 'f1', status: 'open' } as any,
      ]

      await store.updateStatus('f1', 'confirmed')

      expect(store.findings[0].status).toBe('confirmed')
    })

    it('should update currentFinding if matching', async () => {
      vi.mocked(api.findingsApi.updateStatus).mockResolvedValue(mockEmptyResponse())

      const store = useFindingsStore()
      store.currentFinding = { finding_id: 'f1', status: 'open' } as any

      await store.updateStatus('f1', 'mitigated')

      expect(store.currentFinding!.status).toBe('mitigated')
    })
  })

  describe('bulkUpdateStatus', () => {
    it('should update multiple findings', async () => {
      vi.mocked(api.findingsApi.bulkUpdateStatus).mockResolvedValue(mockEmptyResponse())

      const store = useFindingsStore()
      store.findings = [
        { finding_id: 'f1', status: 'open' } as any,
        { finding_id: 'f2', status: 'open' } as any,
        { finding_id: 'f3', status: 'open' } as any,
      ]

      await store.bulkUpdateStatus(['f1', 'f2'], 'confirmed')

      expect(store.findings[0].status).toBe('confirmed')
      expect(store.findings[1].status).toBe('confirmed')
      expect(store.findings[2].status).toBe('open')
    })
  })

  describe('clearFilters', () => {
    it('should reset all filters', async () => {
      vi.mocked(api.findingsApi.list).mockResolvedValue(
        mockPaginatedResponse([], 1, 20, 0)
      )

      const store = useFindingsStore()
      store.filters.severity = ['high']
      store.filters.status = ['open']
      store.filters.app_id = 'test-app'
      store.pagination.page = 5

      store.clearFilters()

      expect(store.filters.severity).toBeNull()
      expect(store.filters.status).toBeNull()
      expect(store.filters.app_id).toBeNull()
      expect(store.pagination.page).toBe(1)
    })
  })
})
