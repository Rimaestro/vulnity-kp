export interface ScanRequest {
  targetUrl: string;
  username?: string;
  password?: string;
  scanType: 'sql_injection';
}

export interface ScanResult {
  id: number;
  target_url: string;
  scan_type: 'sql_injection' | 'xss' | 'full_scan';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  created_at: string;
  started_at?: string;
  completed_at?: string;
  progress: number;
  current_step?: string;
  vulnerabilities: Vulnerability[];
  summary?: ScanSummary;
  error_message?: string;
  user_id: number;
}

export interface Vulnerability {
  type: 'boolean_based' | 'union_based' | 'time_based' | 'blind_boolean' | 'error_based';
  severity: 'low' | 'medium' | 'high' | 'critical';
  payload: string;
  confidence: number;
  extracted_data: string[];
  error_disclosure: string[];
  response_time?: number;
  details: Record<string, any>;
}

export interface ScanSummary {
  total_vulnerabilities: number;
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  injection_types_found: Record<string, number>;
  success_rate: number;
  total_payloads_tested: number;
  scan_duration: number;
}

export interface ScanProgress {
  scan_id: number;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  progress: number;
  current_step: string;
  message: string;
  vulnerabilities_found: number;
}
