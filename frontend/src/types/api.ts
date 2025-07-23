// User & Authentication
export interface User {
  id: number
  username: string
  email: string
  full_name?: string
  is_active: boolean
  created_at: string
  last_login_at?: string
}

export interface LoginRequest {
  username: string
  password: string
}

export interface RegisterRequest {
  username: string
  email: string
  password: string
  full_name?: string
}

export interface AuthResponse {
  user: User
  tokens: {
    access_token: string
    refresh_token: string
    expires_in: number
  }
  message: string
}

// Scan Management
export interface ScanRequest {
  target_url: string
  scan_name?: string
  description?: string
  scan_types: string[]
  max_depth?: number
  max_requests?: number
}

export interface Scan {
  id: string
  target_url: string
  scan_name?: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  progress: number
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  created_at: string
  started_at?: string
  completed_at?: string
}

// Vulnerability Management
export interface Vulnerability {
  id: number
  title: string
  description?: string
  vulnerability_type: string
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'open' | 'confirmed' | 'false_positive' | 'fixed'
  endpoint: string
  parameter?: string
  method: string
  payload?: string
  confidence: number
  cwe_id?: string
  cvss_score?: number
  created_at: string
  verified: boolean
  scan_id: string
}

// API Response Types
export interface ApiResponse<T> {
  data: T
  message?: string
  status: 'success' | 'error'
}

export interface PaginatedResponse<T> {
  items: T[]
  total: number
  page: number
  size: number
  pages: number
}

// Error Types
export interface ApiError {
  error: string
  message: string
  details?: string[]
  status_code: number
}
