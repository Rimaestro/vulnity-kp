import axios from 'axios'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor untuk JWT token
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('access_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor untuk error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Handle token refresh atau redirect ke login
      localStorage.removeItem('access_token')
      localStorage.removeItem('refresh_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  }
)

// Auth API functions
export const authApi = {
  login: (credentials: { username: string; password: string }) =>
    apiClient.post('/api/v1/auth/login', credentials),
  
  register: (userData: { username: string; email: string; password: string; confirm_password: string; full_name?: string }) =>
    apiClient.post('/api/v1/auth/register', userData),
  
  logout: () =>
    apiClient.post('/api/v1/auth/logout'),
  
  getCurrentUser: () =>
    apiClient.get('/api/v1/auth/me'),
  
  refreshToken: () =>
    apiClient.post('/api/v1/auth/refresh'),
}

// Scan API functions
export const scanApi = {
  startScan: (scanData: any) =>
    apiClient.post('/api/v1/scan/start', scanData),

  getScans: (params?: { page?: number; size?: number; status_filter?: string }) => {
    // Transform frontend pagination params to backend format
    const backendParams: { skip?: number; limit?: number; status_filter?: string } = {}

    if (params?.page && params?.size) {
      backendParams.skip = (params.page - 1) * params.size
      backendParams.limit = params.size
    } else if (params?.size) {
      backendParams.skip = 0
      backendParams.limit = params.size
    }

    if (params?.status_filter) {
      backendParams.status_filter = params.status_filter
    }

    return apiClient.get('/api/v1/scan/', { params: backendParams })
  },

  getScan: (scanId: string | number) =>
    apiClient.get(`/api/v1/scan/${scanId}`),

  updateScan: (scanId: string | number, data: any) =>
    apiClient.patch(`/api/v1/scan/${scanId}`, data),

  updateScanStatus: (scanId: string | number, data: { status: string }) =>
    apiClient.patch(`/api/v1/scan/${scanId}/status`, data),

  deleteScan: (scanId: string | number) =>
    apiClient.delete(`/api/v1/scan/${scanId}`),

  cancelScan: (scanId: string | number) =>
    apiClient.post(`/api/v1/scan/${scanId}/cancel`),

  getScanStats: () =>
    apiClient.get('/api/v1/scan/stats/summary'),

  downloadScanReport: (scanId: string | number, format: 'pdf' | 'json' | 'csv' = 'pdf') =>
    apiClient.get(`/api/v1/scan/${scanId}/report`, {
      params: { format },
      responseType: 'blob'
    }),
}

// Vulnerability API functions
export const vulnerabilityApi = {
  getVulnerabilities: (params?: { page?: number; size?: number; scan_id?: string | number }) => {
    // Transform frontend pagination params to backend format
    const backendParams: { skip?: number; limit?: number; scan_id?: string | number } = {}

    if (params?.page && params?.size) {
      backendParams.skip = (params.page - 1) * params.size
      backendParams.limit = params.size
    } else if (params?.size) {
      backendParams.skip = 0
      backendParams.limit = params.size
    }

    if (params?.scan_id) {
      backendParams.scan_id = params.scan_id
    }

    return apiClient.get('/api/v1/vulnerability/', { params: backendParams })
  },

  getVulnerability: (vulnId: number) =>
    apiClient.get(`/api/v1/vulnerability/${vulnId}`),

  updateVulnerability: (vulnId: number, data: any) =>
    apiClient.patch(`/api/v1/vulnerability/${vulnId}`, data),

  getVulnerabilityStats: (scanId?: number) => {
    const params = scanId ? { scan_id: scanId } : {}
    return apiClient.get('/api/v1/vulnerability/stats/summary', { params })
  },

  getVulnerabilitiesByScan: (scanId: string | number) =>
    apiClient.get(`/api/v1/vulnerability/scan/${scanId}`),
}

// Analytics API functions
export const analyticsApi = {
  getVulnerabilityTrend: (months?: number) =>
    apiClient.get('/api/v1/vulnerability/stats/trend', { params: { months } }),

  getScanTrend: (weeks?: number) =>
    apiClient.get('/api/v1/scan/stats/trend', { params: { weeks } }),

  getFixrateTrend: (months?: number) =>
    apiClient.get('/api/v1/fixrate/stats/trend', { params: { months } }),
}
