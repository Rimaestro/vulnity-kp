/**
 * Data transformation utilities for converting backend responses to frontend types
 * Handles type conversions, field mapping, and data normalization
 */

import type { Scan, Vulnerability } from '@/types/api'

// Backend response types (matching backend schemas)
interface BackendScan {
  id: number
  target_url: string
  scan_name?: string
  status: string
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

interface BackendVulnerability {
  id: number
  title: string
  description?: string
  vulnerability_type: string
  risk: string
  status: string
  endpoint: string
  parameter?: string
  method: string
  payload?: string
  confidence: number
  cwe_id?: string
  cvss_score?: number
  created_at: string
  verified: boolean
  scan_id: number
}

interface BackendVulnerabilityStats {
  total_vulnerabilities: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  info_count: number
  sql_injection_count: number
  xss_count: number
  csrf_count: number
  open_count: number
  confirmed_count: number
  false_positive_count: number
  fixed_count: number
  verified_count: number
  unverified_count: number
}

// Frontend expected types
interface FrontendVulnerabilityStats {
  total_count: number
  critical_count: number
  high_count: number
  medium_count: number
  low_count: number
  fixed_count: number
}

/**
 * Transform backend scan data to frontend format
 */
export const transformScanData = (backendScan: BackendScan): Scan => ({
  id: backendScan.id.toString(), // Convert int to string
  target_url: backendScan.target_url,
  scan_name: backendScan.scan_name,
  status: backendScan.status as Scan['status'],
  progress: backendScan.progress,
  total_vulnerabilities: backendScan.total_vulnerabilities,
  critical_count: backendScan.critical_count,
  high_count: backendScan.high_count,
  medium_count: backendScan.medium_count || 0, // Provide default if missing
  low_count: backendScan.low_count,
  created_at: backendScan.created_at,
  started_at: backendScan.started_at,
  completed_at: backendScan.completed_at,
})

/**
 * Transform array of backend scans to frontend format
 */
export const transformScansData = (backendScans: BackendScan[]): Scan[] => {
  return backendScans.map(transformScanData)
}

/**
 * Transform backend vulnerability data to frontend format
 */
export const transformVulnerabilityData = (backendVuln: BackendVulnerability): Vulnerability => ({
  id: backendVuln.id,
  title: backendVuln.title,
  description: backendVuln.description,
  vulnerability_type: backendVuln.vulnerability_type,
  risk: backendVuln.risk as Vulnerability['risk'],
  status: backendVuln.status as Vulnerability['status'],
  endpoint: backendVuln.endpoint,
  parameter: backendVuln.parameter,
  method: backendVuln.method,
  payload: backendVuln.payload,
  confidence: backendVuln.confidence,
  cwe_id: backendVuln.cwe_id,
  cvss_score: backendVuln.cvss_score,
  created_at: backendVuln.created_at,
  verified: backendVuln.verified,
  scan_id: backendVuln.scan_id.toString(), // Convert int to string
})

/**
 * Transform array of backend vulnerabilities to frontend format
 */
export const transformVulnerabilitiesData = (backendVulns: BackendVulnerability[]): Vulnerability[] => {
  return backendVulns.map(transformVulnerabilityData)
}

/**
 * Transform backend vulnerability stats to frontend format
 */
export const transformVulnerabilityStats = (backendStats: BackendVulnerabilityStats): FrontendVulnerabilityStats => ({
  total_count: backendStats.total_vulnerabilities, // Map field name
  critical_count: backendStats.critical_count,
  high_count: backendStats.high_count,
  medium_count: backendStats.medium_count,
  low_count: backendStats.low_count,
  fixed_count: backendStats.fixed_count,
})

/**
 * Transform backend API response to frontend format
 * Handles both direct arrays and nested response objects
 */
export const transformApiResponse = <T, U>(
  response: any,
  transformer: (item: T) => U
): U[] => {
  // Handle direct array response
  if (Array.isArray(response)) {
    return response.map(transformer)
  }
  
  // Handle nested response with data property
  if (response.data && Array.isArray(response.data)) {
    return response.data.map(transformer)
  }
  
  // Handle nested response with items property
  if (response.items && Array.isArray(response.items)) {
    return response.items.map(transformer)
  }
  
  // Handle single item response
  if (response && typeof response === 'object') {
    return [transformer(response)]
  }
  
  // Fallback to empty array
  return []
}

/**
 * Create pagination parameters for backend API
 */
export const createPaginationParams = (page?: number, size?: number) => {
  const params: { skip?: number; limit?: number } = {}
  
  if (page && size) {
    params.skip = (page - 1) * size
    params.limit = size
  } else if (size) {
    params.skip = 0
    params.limit = size
  }
  
  return params
}

/**
 * Transform backend pagination response to frontend format
 */
export const transformPaginationResponse = <T>(
  response: any,
  totalCount?: number
): {
  items: T[]
  total: number
  page: number
  size: number
  pages: number
} => {
  const items = Array.isArray(response) ? response : (response.data || response.items || [])
  const total = totalCount || response.total || items.length
  const size = response.size || response.limit || 10
  const page = response.page || (response.skip ? Math.floor(response.skip / size) + 1 : 1)
  const pages = Math.ceil(total / size)
  
  return {
    items,
    total,
    page,
    size,
    pages
  }
}

/**
 * Safe data access with fallback values
 */
export const safeGet = <T>(obj: any, path: string, defaultValue: T): T => {
  try {
    const keys = path.split('.')
    let result = obj
    
    for (const key of keys) {
      if (result == null || typeof result !== 'object') {
        return defaultValue
      }
      result = result[key]
    }
    
    return result !== undefined ? result : defaultValue
  } catch {
    return defaultValue
  }
}

/**
 * Validate and normalize scan status
 */
export const normalizeScanStatus = (status: string): Scan['status'] => {
  const validStatuses: Scan['status'][] = ['pending', 'running', 'completed', 'failed', 'cancelled']
  const normalizedStatus = status.toLowerCase() as Scan['status']
  
  return validStatuses.includes(normalizedStatus) ? normalizedStatus : 'pending'
}

/**
 * Validate and normalize vulnerability risk level
 */
export const normalizeVulnerabilityRisk = (risk: string): Vulnerability['risk'] => {
  const validRisks: Vulnerability['risk'][] = ['critical', 'high', 'medium', 'low', 'info']
  const normalizedRisk = risk.toLowerCase() as Vulnerability['risk']
  
  return validRisks.includes(normalizedRisk) ? normalizedRisk : 'info'
}
