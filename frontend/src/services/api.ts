import axios from 'axios'
import type { ScanRequest, ScanResult } from '../types/scan'

const api = axios.create({
  baseURL: 'http://localhost:8000/api',
  headers: {
    'Content-Type': 'application/json',
  },
})

export const scanApi = {
  getPlugins: async () => {
    const response = await api.get('/plugins')
    return response.data
  },

  startScan: async (request: ScanRequest): Promise<ScanResult> => {
    const response = await api.post('/scan/start', request)
    return response.data
  },

  getScanStatus: async (scanId: string): Promise<{ status: string }> => {
    const response = await api.get(`/scan/${scanId}/status`)
    return response.data
  },

  getScanResults: async (scanId: string): Promise<ScanResult> => {
    const response = await api.get(`/scan/${scanId}/results`)
    return response.data
  },

  getAllScans: async (): Promise<ScanResult[]> => {
    const response = await api.get('/scan')
    return response.data
  },
}

export default api 