import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { appsApi } from '@/services/api'

/** Represents an uploaded mobile application with metadata, framework info, and signing details */
export interface MobileApp {
  app_id: string
  package_name: string
  app_name: string | null
  version_name: string | null
  version_code: number | null
  platform: 'android' | 'ios'
  file_path: string | null
  file_hash_sha256: string | null
  file_size_bytes: number | null
  framework: string | null
  framework_version: string | null
  framework_details: Record<string, any>
  signing_info: Record<string, any>
  min_sdk_version: number | null
  target_sdk_version: number | null
  min_ios_version: string | null
  status: string
  upload_date: string
  last_analyzed: string | null
  metadata: Record<string, any>
}

/** Aggregated statistics for a single application including scan count and findings breakdown */
export interface AppStats {
  app_id: string
  scan_count: number
  total_findings: number
  findings_by_severity: Record<string, number>
  findings_by_category: Record<string, number>
}

/**
 * Apps store managing the mobile application list, individual app details, and per-app statistics.
 * Provides paginated fetching, platform/framework/status filtering, upload, and deletion.
 */
export const useAppsStore = defineStore('apps', () => {
  const apps = ref<MobileApp[]>([])
  const currentApp = ref<MobileApp | null>(null)
  const currentAppStats = ref<AppStats | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const pagination = ref({
    page: 1,
    pageSize: 20,
    total: 0,
    pages: 0,
  })

  const filters = ref({
    platform: null as string | null,
    framework: null as string | null,
    status: null as string | null,
    search: null as string | null,
  })

  /** Fetch paginated app list applying current filters and pagination state */
  async function fetchApps() {
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
      const response = await appsApi.list(params)
      apps.value = response.data.items
      pagination.value = {
        page: response.data.page,
        pageSize: response.data.page_size,
        total: response.data.total,
        pages: response.data.pages,
      }
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch apps'
    } finally {
      loading.value = false
    }
  }

  /** Fetch a single app by ID and set it as the current app */
  async function fetchApp(id: string) {
    loading.value = true
    error.value = null
    try {
      const response = await appsApi.get(id)
      currentApp.value = response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to fetch app'
    } finally {
      loading.value = false
    }
  }

  /** Fetch scan and findings statistics for a specific app */
  async function fetchAppStats(id: string) {
    try {
      const response = await appsApi.getStats(id)
      currentAppStats.value = response.data
    } catch (e: any) {
      console.error('Failed to fetch app stats:', e)
    }
  }

  /** Upload an APK/IPA/AAB file and prepend the new app to the list */
  async function uploadApp(file: File) {
    loading.value = true
    error.value = null
    try {
      const response = await appsApi.upload(file)
      apps.value.unshift(response.data)
      return response.data
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to upload app'
      throw e
    } finally {
      loading.value = false
    }
  }

  /** Delete an app by ID and remove it from the local list */
  async function deleteApp(id: string) {
    loading.value = true
    error.value = null
    try {
      await appsApi.delete(id)
      apps.value = apps.value.filter((a) => a.app_id !== id)
    } catch (e: any) {
      error.value = e.response?.data?.detail || 'Failed to delete app'
      throw e
    } finally {
      loading.value = false
    }
  }

  /** Navigate to a specific page and re-fetch the app list */
  function setPage(page: number) {
    pagination.value.page = page
    fetchApps()
  }

  /** Merge new filter values, reset to page 1, and re-fetch the app list */
  function setFilters(newFilters: Partial<typeof filters.value>) {
    filters.value = { ...filters.value, ...newFilters }
    pagination.value.page = 1
    fetchApps()
  }

  return {
    apps,
    currentApp,
    currentAppStats,
    loading,
    error,
    pagination,
    filters,
    fetchApps,
    fetchApp,
    fetchAppStats,
    uploadApp,
    deleteApp,
    setPage,
    setFilters,
  }
})
