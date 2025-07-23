import type { Scan, Vulnerability } from './api'

// Extended scan types for scanner components
export interface ScanWithDetails extends Scan {
  vulnerabilities?: Vulnerability[]
  scan_metadata?: {
    start_time?: number
    end_time?: number
    duration?: number
    parameters_tested?: string[]
  }
  current_phase?: string
  estimated_completion?: string
  description?: string
  max_depth?: number
  max_requests?: number
  request_delay?: number
}

// Scan form data
export interface ScanFormData {
  target_url: string
  scan_name: string
  description: string
  scan_types: ScanType[]
  max_depth: number
  max_requests: number
  request_delay: number
}

// Available scan types
export interface ScanType {
  id: string
  name: string
  description: string
  enabled: boolean
  risk_level: 'low' | 'medium' | 'high'
}

// Scan statistics
export interface ScanStats {
  total_scans: number
  running_scans: number
  completed_scans: number
  failed_scans: number
  total_vulnerabilities: number
  critical_vulnerabilities: number
  high_vulnerabilities: number
  medium_vulnerabilities: number
  low_vulnerabilities: number
}

// Scan filter options
export interface ScanFilters {
  status?: string[]
  scan_types?: string[]
  date_range?: {
    start: string
    end: string
  }
  risk_level?: string[]
}

// Scan table column definitions
export interface ScanTableColumn {
  key: string
  label: string
  sortable: boolean
  width?: string
}

// Scan actions
export type ScanAction = 'view' | 'cancel' | 'delete' | 'download' | 'retry'

// Scan status with display properties
export interface ScanStatusInfo {
  status: string
  label: string
  color: 'default' | 'secondary' | 'destructive' | 'outline'
  icon?: string
}

// Real-time scan updates
export interface ScanUpdate {
  scan_id: string
  status: string
  progress: number
  current_phase?: string
  vulnerabilities_found?: number
  estimated_completion?: string
}

// Vulnerability summary for scan
export interface VulnerabilitySummary {
  total: number
  by_risk: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  by_type: Record<string, number>
  by_status: Record<string, number>
}

// Export types
export interface ScanExportOptions {
  format: 'pdf' | 'json' | 'csv' | 'xml'
  include_vulnerabilities: boolean
  include_evidence: boolean
  include_recommendations: boolean
}

// Scanner configuration
export interface ScannerConfig {
  max_concurrent_scans: number
  default_request_delay: number
  default_max_depth: number
  default_max_requests: number
  available_scan_types: ScanType[]
}
