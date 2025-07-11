import { apiRequest } from './api'
import type { ScanRequest, ScanResult, ScanProgress } from '../types/scan'
import type { ApiResponse } from '../types/api'

export const scanService = {
  // Start a new scan
  startScan: async (scanRequest: ScanRequest): Promise<ScanResult> => {
    return apiRequest('POST', '/v1/scan/start', {
      target_url: scanRequest.targetUrl,
      username: scanRequest.username,
      password: scanRequest.password,
      scan_type: scanRequest.scanType
    })
  },

  // Get scan status and progress
  getScanStatus: async (scanId: string): Promise<ScanResult> => {
    return apiRequest('GET', `/v1/scan/status/${scanId}`)
  },

  // Get detailed scan results
  getScanResults: async (scanId: string): Promise<ScanResult> => {
    return apiRequest('GET', `/v1/scan/status/${scanId}`)
  },

  // Get list of all scans
  getAllScans: async (): Promise<ScanResult[]> => {
    return apiRequest('GET', '/v1/scan/list')
  },

  // Cancel a running scan
  cancelScan: async (scanId: string): Promise<{ success: boolean }> => {
    return apiRequest('POST', `/v1/scan/${scanId}/cancel`)
  },

  // Export scan report
  exportReport: async (scanId: string, format: 'json' | 'pdf' = 'json'): Promise<Blob> => {
    const response = await fetch(`/api/v1/reports/${scanId}/export?format=${format}`)
    return response.blob()
  },
}

// Export individual functions for easier imports
export const {
  startScan,
  getScanStatus,
  getScanResults,
  getAllScans,
  cancelScan,
  exportReport,
} = scanService
