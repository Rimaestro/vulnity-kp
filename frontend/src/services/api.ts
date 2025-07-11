import axios from 'axios'
import type { ApiResponse, ApiError } from '../types/api'

// Create axios instance with base configuration
export const api = axios.create({
  baseURL: '/api', // Proxied through Vite to backend
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // No authentication required for demo mode
    return config
  },
  (error) => {
    return Promise.reject(error)
  }
)

// Response interceptor
api.interceptors.response.use(
  (response) => {
    return response
  },
  (error) => {
    const apiError: ApiError = {
      message: error.response?.data?.detail || error.response?.data?.message || error.message || 'An error occurred',
      status: error.response?.status || 500,
      details: error.response?.data,
    }
    return Promise.reject(apiError)
  }
)

// Generic API wrapper
export const apiRequest = async <T>(
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  url: string,
  data?: any
): Promise<T> => {
  const response = await api.request({
    method,
    url,
    data,
  })
  return response.data
}
