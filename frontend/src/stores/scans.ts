import { defineStore } from 'pinia'
import { ref } from 'vue'
import { scansApi } from '@/services/api'

export interface Scan {
  scan_id: string
  app_id: string
  scan_type: 'static' | 'dynamic' | 'full'
  analyzers_enabled: string[]
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  current_analyzer: string | null
  findings_count: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  started_at: string | null
  completed_at: string | null
  created_at: string
  error_message: string | null
  analyzer_errors: Array<{ analyzer: string; error: string }>
}

export const useScansStore = defineStore('scans', () => {
  const scans = ref<Scan[]>([])
  const currentScan = ref<Scan | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const pagination = ref({
    page: 1,
    pageSize: 20,
    total: 0,
    pages: 0,
  })

  const filters = ref({
    app_id: null as string | null,
    status: null as string | null,
    scan_type: null as string | null,
  })

  async function fetchScans() {
    loading.value = true
    error.value = null
    try {
      const params = {
        page: pagination.value.page,
        page_size: pagination.value.pageSize,
        ...Object.fromEntries(
          Object.entries(filters.value).filter(([_, v]) => v !== null)
        ),
      }
      const response = await scansApi.list(params)
      scans.value = response.data.items
      pagination.value = {
        page: response.data.page,
        pageSize: response.data.page_size,
        total: response.data.total,
        pages: response.data.pages,
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch scans'
    } finally {
      loading.value = false
    }
  }

  async function fetchScan(id: string) {
    loading.value = true
    error.value = null
    try {
      const response = await scansApi.get(id)
      currentScan.value = response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch scan'
    } finally {
      loading.value = false
    }
  }

  async function createScan(data: {
    app_id: string
    scan_type: string
    analyzers_enabled?: string[]
  }) {
    loading.value = true
    error.value = null
    try {
      const response = await scansApi.create(data)
      scans.value.unshift(response.data)
      return response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to create scan'
      throw e
    } finally {
      loading.value = false
    }
  }

  async function cancelScan(id: string) {
    try {
      await scansApi.cancel(id)
      const scan = scans.value.find((s) => s.scan_id === id)
      if (scan) {
        scan.status = 'cancelled'
      }
      if (currentScan.value?.scan_id === id) {
        currentScan.value.status = 'cancelled'
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to cancel scan'
      throw e
    }
  }

  async function deleteScan(id: string) {
    try {
      await scansApi.delete(id)
      scans.value = scans.value.filter((s) => s.scan_id !== id)
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to delete scan'
      throw e
    }
  }

  async function refreshScanProgress(id: string) {
    try {
      const response = await scansApi.getProgress(id)
      const scan = scans.value.find((s) => s.scan_id === id)
      if (scan) {
        scan.status = response.data.status
        scan.progress = response.data.progress
        scan.current_analyzer = response.data.current_analyzer
        scan.findings_count = response.data.findings_count
      }
      if (currentScan.value?.scan_id === id) {
        currentScan.value.status = response.data.status
        currentScan.value.progress = response.data.progress
        currentScan.value.current_analyzer = response.data.current_analyzer
        currentScan.value.findings_count = response.data.findings_count
      }
      return response.data
    } catch (e: any) {
      console.error('Failed to refresh scan progress:', e)
    }
  }

  function setPage(page: number) {
    pagination.value.page = page
    fetchScans()
  }

  function setFilters(newFilters: Partial<typeof filters.value>) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchScans()
  }

  return {
    scans,
    currentScan,
    loading,
    error,
    pagination,
    filters,
    fetchScans,
    fetchScan,
    createScan,
    cancelScan,
    deleteScan,
    refreshScanProgress,
    setPage,
    setFilters,
  }
})
