/**
 * Tests for the API service
 */

import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import axios from 'axios'
import {
  appsApi,
  scansApi,
  findingsApi,
  devicesApi,
  fridaApi,
  secretsApi,
} from '@/services/api'

// Mock axios
vi.mock('axios', () => {
  const mockAxios = {
    create: vi.fn(() => mockAxios),
    get: vi.fn(),
    post: vi.fn(),
    put: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  }
  return { default: mockAxios }
})

describe('API Service', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  describe('appsApi', () => {
    it('should have list method', () => {
      expect(appsApi.list).toBeDefined()
      expect(typeof appsApi.list).toBe('function')
    })

    it('should have get method', () => {
      expect(appsApi.get).toBeDefined()
      expect(typeof appsApi.get).toBe('function')
    })

    it('should have upload method', () => {
      expect(appsApi.upload).toBeDefined()
      expect(typeof appsApi.upload).toBe('function')
    })

    it('should have delete method', () => {
      expect(appsApi.delete).toBeDefined()
      expect(typeof appsApi.delete).toBe('function')
    })

    it('should have getStats method', () => {
      expect(appsApi.getStats).toBeDefined()
      expect(typeof appsApi.getStats).toBe('function')
    })
  })

  describe('scansApi', () => {
    it('should have list method', () => {
      expect(scansApi.list).toBeDefined()
    })

    it('should have get method', () => {
      expect(scansApi.get).toBeDefined()
    })

    it('should have create method', () => {
      expect(scansApi.create).toBeDefined()
    })

    it('should have cancel method', () => {
      expect(scansApi.cancel).toBeDefined()
    })

    it('should have delete method', () => {
      expect(scansApi.delete).toBeDefined()
    })

    it('should have getProgress method', () => {
      expect(scansApi.getProgress).toBeDefined()
    })
  })

  describe('findingsApi', () => {
    it('should have list method', () => {
      expect(findingsApi.list).toBeDefined()
    })

    it('should have get method', () => {
      expect(findingsApi.get).toBeDefined()
    })

    it('should have getSummary method', () => {
      expect(findingsApi.getSummary).toBeDefined()
    })

    it('should have updateStatus method', () => {
      expect(findingsApi.updateStatus).toBeDefined()
    })

    it('should have bulkUpdateStatus method', () => {
      expect(findingsApi.bulkUpdateStatus).toBeDefined()
    })

    it('should have getFilterOptions method', () => {
      expect(findingsApi.getFilterOptions).toBeDefined()
    })
  })

  describe('devicesApi', () => {
    it('should have list method', () => {
      expect(devicesApi.list).toBeDefined()
    })

    it('should have get method', () => {
      expect(devicesApi.get).toBeDefined()
    })

    it('should have discover method', () => {
      expect(devicesApi.discover).toBeDefined()
    })

    it('should have register method', () => {
      expect(devicesApi.register).toBeDefined()
    })

    it('should have connect method', () => {
      expect(devicesApi.connect).toBeDefined()
    })

    it('should have installFrida method', () => {
      expect(devicesApi.installFrida).toBeDefined()
    })

    it('should have startFrida method', () => {
      expect(devicesApi.startFrida).toBeDefined()
    })

    it('should have delete method', () => {
      expect(devicesApi.delete).toBeDefined()
    })
  })

  describe('fridaApi', () => {
    it('should have listScripts method', () => {
      expect(fridaApi.listScripts).toBeDefined()
    })

    it('should have getScript method', () => {
      expect(fridaApi.getScript).toBeDefined()
    })

    it('should have createScript method', () => {
      expect(fridaApi.createScript).toBeDefined()
    })

    it('should have updateScript method', () => {
      expect(fridaApi.updateScript).toBeDefined()
    })

    it('should have deleteScript method', () => {
      expect(fridaApi.deleteScript).toBeDefined()
    })

    it('should have inject method', () => {
      expect(fridaApi.inject).toBeDefined()
    })

    it('should have listSessions method', () => {
      expect(fridaApi.listSessions).toBeDefined()
    })

    it('should have detachSession method', () => {
      expect(fridaApi.detachSession).toBeDefined()
    })

    it('should have getCategories method', () => {
      expect(fridaApi.getCategories).toBeDefined()
    })
  })

  describe('secretsApi', () => {
    it('should have list method', () => {
      expect(secretsApi.list).toBeDefined()
    })

    it('should have get method', () => {
      expect(secretsApi.get).toBeDefined()
    })

    it('should have getSummary method', () => {
      expect(secretsApi.getSummary).toBeDefined()
    })

    it('should have validate method', () => {
      expect(secretsApi.validate).toBeDefined()
    })

    it('should have getTypes method', () => {
      expect(secretsApi.getTypes).toBeDefined()
    })

    it('should have getProviders method', () => {
      expect(secretsApi.getProviders).toBeDefined()
    })
  })
})
