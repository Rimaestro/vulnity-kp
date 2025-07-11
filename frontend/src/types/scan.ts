export interface ScanRequestOptions {
  max_depth: number
  threads: number
  timeout: number
  follow_redirects: boolean
}

export interface ScanRequest {
  url: string
  scan_types: string[]
  options: ScanRequestOptions
}

export interface ScanStatistics {
  urls_crawled: number
  forms_tested: number
  vulnerabilities_found: number
  elapsed_time: number
  requests_sent: number
  current_url?: string
}

export interface Vulnerability {
  type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  location: string
  evidence: string
  id?: string
  name?: string
  url?: string
  method?: string
  payload?: string
  cwe_id?: number
  remediation?: string
  discovered_at?: string
}

export interface ScanResult {
  id: string
  url: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  vulnerabilities: Vulnerability[]
  created_at: string
  completed_at?: string
  statistics?: ScanStatistics
  target_url?: string
  start_time?: string
  end_time?: string
}

const types = {
  ScanRequestOptions,
  ScanRequest,
  ScanStatistics,
  Vulnerability,
  ScanResult
}

export default types 