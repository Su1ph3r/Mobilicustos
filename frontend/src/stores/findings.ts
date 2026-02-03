import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { findingsApi } from '@/services/api'

export interface Finding {
  finding_id: string
  scan_id: string | null
  app_id: string | null
  tool: string
  platform: string | null
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: string
  category: string | null
  title: string
  description: string
  impact: string
  remediation: string
  resource_type: string | null
  file_path: string | null
  line_number: number | null
  code_snippet: string | null
  poc_evidence: string | null
  poc_verification: string | null
  poc_commands: string[]
  poc_frida_script: string | null
  poc_screenshot_path: string | null
  remediation_commands: string[]
  remediation_code: Record<string, any>
  remediation_resources: string[]
  risk_score: number | null
  cvss_score: number | null
  cvss_vector: string | null
  cwe_id: string | null
  cwe_name: string | null
  owasp_masvs_category: string | null
  owasp_masvs_control: string | null
  owasp_mastg_test: string | null
  canonical_id: string | null
  tool_sources: string[]
  first_seen: string
  last_seen: string
  created_at: string
}

export interface FindingsSummary {
  total: number
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_category: Record<string, number>
  by_masvs: Record<string, number>
  by_tool: Record<string, number>
}

export interface FilterOptions {
  severities: string[]
  statuses: string[]
  platforms: string[]
  categories: string[]
  tools: string[]
  masvs_categories: string[]
  cwe_ids: string[]
}

export const useFindingsStore = defineStore('findings', () => {
  const findings = ref<Finding[]>([])
  const currentFinding = ref<Finding | null>(null)
  const summary = ref<FindingsSummary | null>(null)
  const filterOptions = ref<FilterOptions | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const pagination = ref({
    page: 1,
    pageSize: 20,
    total: 0,
    pages: 0,
  })

  const filters = ref({
    severity: null as string[] | null,
    status: null as string[] | null,
    platform: null as string[] | null,
    category: null as string[] | null,
    tool: null as string[] | null,
    owasp_masvs_category: null as string[] | null,
    cwe_id: null as string[] | null,
    app_id: null as string | null,
    scan_id: null as string | null,
    search: null as string | null,
  })

  const sorting = ref({
    sortBy: 'severity' as string,
    sortOrder: 'desc' as 'asc' | 'desc',
  })

  const hasFilters = computed(() => {
    return Object.entries(filters.value).some(([key, v]) => {
      // Ignore app_id and scan_id for hasFilters check
      if (key === 'app_id' || key === 'scan_id') return false
      if (v === null || v === undefined) return false
      if (Array.isArray(v)) return v.length > 0
      if (typeof v === 'string') return v.length > 0
      return true
    })
  })

  async function fetchFindings() {
    loading.value = true
    error.value = null
    try {
      const params = {
        page: pagination.value.page,
        page_size: pagination.value.pageSize,
        sort_by: sorting.value.sortBy,
        sort_order: sorting.value.sortOrder,
        ...Object.fromEntries(
          Object.entries(filters.value).filter(([_, v]) => {
            if (v === null || v === undefined) return false
            if (Array.isArray(v)) return v.length > 0
            if (typeof v === 'string') return v.length > 0
            return true
          })
        ),
      }
      const response = await findingsApi.list(params)
      findings.value = response.data.items
      pagination.value = {
        page: response.data.page,
        pageSize: response.data.page_size,
        total: response.data.total,
        pages: response.data.pages,
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch findings'
    } finally {
      loading.value = false
    }
  }

  async function fetchFinding(id: string) {
    loading.value = true
    error.value = null
    try {
      const response = await findingsApi.get(id)
      currentFinding.value = response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch finding'
    } finally {
      loading.value = false
    }
  }

  async function fetchSummary(params?: { app_id?: string; scan_id?: string }) {
    try {
      const response = await findingsApi.getSummary(params)
      summary.value = response.data
    } catch (e: any) {
      console.error('Failed to fetch summary:', e)
    }
  }

  async function fetchFilterOptions() {
    try {
      const response = await findingsApi.getFilterOptions()
      filterOptions.value = response.data
    } catch (e: any) {
      console.error('Failed to fetch filter options:', e)
    }
  }

  async function updateStatus(id: string, status: string) {
    try {
      await findingsApi.updateStatus(id, status)
      // Update local state
      const finding = findings.value.find((f) => f.finding_id === id)
      if (finding) {
        finding.status = status
      }
      if (currentFinding.value?.finding_id === id) {
        currentFinding.value.status = status
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to update status'
      throw e
    }
  }

  async function bulkUpdateStatus(ids: string[], status: string) {
    try {
      await findingsApi.bulkUpdateStatus(ids, status)
      // Update local state
      findings.value.forEach((f) => {
        if (ids.includes(f.finding_id)) {
          f.status = status
        }
      })
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to update status'
      throw e
    }
  }

  async function deleteFinding(id: string) {
    try {
      await findingsApi.delete(id)
      // Remove from local state
      findings.value = findings.value.filter((f) => f.finding_id !== id)
      pagination.value.total = Math.max(0, pagination.value.total - 1)
      // Refresh summary
      fetchSummary()
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to delete finding'
      throw e
    }
  }

  async function bulkDeleteFindings(ids: string[]) {
    try {
      await findingsApi.bulkDelete(ids)
      // Remove from local state
      findings.value = findings.value.filter((f) => !ids.includes(f.finding_id))
      pagination.value.total = Math.max(0, pagination.value.total - ids.length)
      // Refresh summary and findings
      fetchSummary()
      fetchFindings()
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to delete findings'
      throw e
    }
  }

  function setPage(page: number) {
    pagination.value.page = page
    fetchFindings()
  }

  function setPageSize(size: number) {
    pagination.value.pageSize = size
    pagination.value.page = 1  // Reset to first page when changing page size
    fetchFindings()
  }

  function setFilters(newFilters: Partial<typeof filters.value>) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchFindings()
  }

  function clearFilters() {
    filters.value = {
      severity: null,
      status: null,
      platform: null,
      category: null,
      tool: null,
      owasp_masvs_category: null,
      cwe_id: null,
      app_id: null,
      scan_id: null,
      search: null,
    }
    pagination.value.page = 1
    fetchFindings()
  }

  function setSort(sortBy: string, sortOrder: 'asc' | 'desc') {
    sorting.value.sortBy = sortBy
    sorting.value.sortOrder = sortOrder
    pagination.value.page = 1
    fetchFindings()
  }

  return {
    findings,
    currentFinding,
    summary,
    filterOptions,
    loading,
    error,
    pagination,
    filters,
    sorting,
    hasFilters,
    fetchFindings,
    fetchFinding,
    fetchSummary,
    fetchFilterOptions,
    updateStatus,
    bulkUpdateStatus,
    deleteFinding,
    bulkDeleteFindings,
    setPage,
    setPageSize,
    setFilters,
    clearFilters,
    setSort,
  }
})
