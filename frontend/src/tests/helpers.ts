/**
 * Test helper functions
 */

import type { AxiosResponse } from 'axios'

/**
 * Creates a mock AxiosResponse with all required properties
 */
export function mockAxiosResponse<T>(data: T, status = 200): AxiosResponse<T> {
  return {
    data,
    status,
    statusText: status === 200 ? 'OK' : 'Error',
    headers: {} as any,
    config: {
      headers: {} as any,
    } as any,
  }
}

/**
 * Creates a mock paginated response
 */
export function mockPaginatedResponse<T>(
  items: T[],
  page = 1,
  pageSize = 20,
  total?: number
): AxiosResponse<{
  items: T[]
  page: number
  page_size: number
  total: number
  pages: number
}> {
  const totalItems = total ?? items.length
  return mockAxiosResponse({
    items,
    page,
    page_size: pageSize,
    total: totalItems,
    pages: Math.ceil(totalItems / pageSize),
  })
}

/**
 * Creates a mock empty response (for delete/update operations)
 */
export function mockEmptyResponse(): AxiosResponse<Record<string, never>> {
  return mockAxiosResponse({})
}
