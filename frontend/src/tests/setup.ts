/**
 * Vitest setup file
 */

import { config } from '@vue/test-utils'
import { vi, beforeEach } from 'vitest'

// Mock PrimeVue components globally
config.global.stubs = {
  // Stub PrimeVue components to avoid rendering issues
  Button: true,
  DataTable: true,
  Column: true,
  Tag: true,
  Dropdown: true,
  InputText: true,
  Dialog: true,
  ProgressBar: true,
  ProgressSpinner: true,
  FileUpload: true,
  Textarea: true,
  MultiSelect: true,
  Checkbox: true,
  TabView: true,
  TabPanel: true,
  Toast: true,
  ConfirmDialog: true,
}

// Mock router-link
config.global.stubs['router-link'] = {
  template: '<a><slot /></a>',
}

// Mock router-view
config.global.stubs['router-view'] = {
  template: '<div><slot /></div>',
}

// Mock window.URL.createObjectURL
global.URL.createObjectURL = vi.fn(() => 'blob:mock-url')
global.URL.revokeObjectURL = vi.fn()

// Mock navigator.clipboard
Object.defineProperty(navigator, 'clipboard', {
  value: {
    writeText: vi.fn().mockResolvedValue(undefined),
    readText: vi.fn().mockResolvedValue(''),
  },
  writable: true,
})

// Mock localStorage
const localStorageMock = {
  getItem: vi.fn(),
  setItem: vi.fn(),
  removeItem: vi.fn(),
  clear: vi.fn(),
}
Object.defineProperty(window, 'localStorage', { value: localStorageMock })

// Reset mocks before each test
beforeEach(() => {
  vi.clearAllMocks()
})
