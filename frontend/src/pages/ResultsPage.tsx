import React, { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { FileText, Loader, AlertTriangle, CheckCircle, Clock, XCircle } from 'lucide-react'
import { scanService } from '../services/scanService'
import { ScanResult, Vulnerability } from '../types/scan'

export const ResultsPage: React.FC = () => {
  const { scanId } = useParams<{ scanId: string }>()
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (scanId) {
      fetchScanResults()
      // Poll for updates if scan is running
      const interval = setInterval(() => {
        if (scanResult?.status === 'running' || scanResult?.status === 'pending') {
          fetchScanResults()
        }
      }, 3000) // Poll every 3 seconds

      return () => clearInterval(interval)
    }
  }, [scanId, scanResult?.status])

  const fetchScanResults = async () => {
    if (!scanId) return

    try {
      const result = await scanService.getScanResults(scanId)
      setScanResult(result)
      setError(null)
    } catch (err: any) {
      setError(err.message || 'Failed to fetch scan results')
    } finally {
      setIsLoading(false)
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-5 w-5 text-green-600" />
      case 'running':
        return <Loader className="h-5 w-5 text-blue-600 animate-spin" />
      case 'failed':
        return <XCircle className="h-5 w-5 text-red-600" />
      case 'pending':
        return <Clock className="h-5 w-5 text-yellow-600" />
      default:
        return <Clock className="h-5 w-5 text-gray-600" />
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200'
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low':
        return 'bg-blue-100 text-blue-800 border-blue-200'
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <Loader className="h-8 w-8 animate-spin text-blue-600 mx-auto mb-4" />
          <p className="text-gray-600">Loading scan results...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan Results</h1>
          <p className="text-gray-600">View vulnerability assessment results and reports</p>
        </div>
        <div className="card">
          <div className="flex items-center space-x-3 p-4 bg-red-50 border border-red-200 rounded-lg">
            <AlertTriangle className="h-5 w-5 text-red-600" />
            <div>
              <h3 className="font-medium text-red-900">Error Loading Results</h3>
              <p className="text-sm text-red-700">{error}</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (!scanResult) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Scan Results</h1>
          <p className="text-gray-600">View vulnerability assessment results and reports</p>
        </div>

        <div className="card">
          <div className="text-center py-12">
            <FileText className="h-16 w-16 text-gray-300 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">Scan Not Found</h3>
            <p className="text-gray-600">
              The requested scan could not be found.
            </p>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Scan Results</h1>
        <p className="text-gray-600">Scan ID: {scanResult.id} • Target: {scanResult.target_url}</p>
      </div>

      {/* Scan Status */}
      <div className="card">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-3">
            {getStatusIcon(scanResult.status)}
            <div>
              <h3 className="font-medium text-gray-900">
                Scan Status: {scanResult.status.charAt(0).toUpperCase() + scanResult.status.slice(1)}
              </h3>
              {scanResult.current_step && (
                <p className="text-sm text-gray-600">{scanResult.current_step}</p>
              )}
            </div>
          </div>

          <div className="text-right">
            <div className="text-sm text-gray-600">Progress</div>
            <div className="flex items-center space-x-2">
              <div className="w-32 bg-gray-200 rounded-full h-2">
                <div
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${scanResult.progress}%` }}
                ></div>
              </div>
              <span className="text-sm font-medium text-gray-900">{scanResult.progress}%</span>
            </div>
          </div>
        </div>
      </div>

      {/* Error Message */}
      {scanResult.error_message && (
        <div className="card">
          <div className="flex items-center space-x-3 p-4 bg-red-50 border border-red-200 rounded-lg">
            <XCircle className="h-5 w-5 text-red-600" />
            <div>
              <h3 className="font-medium text-red-900">Scan Error</h3>
              <p className="text-sm text-red-700">{scanResult.error_message}</p>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerabilities */}
      {scanResult.vulnerabilities && scanResult.vulnerabilities.length > 0 && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">
            Vulnerabilities Found ({scanResult.vulnerabilities.length})
          </h2>
          <div className="space-y-4">
            {scanResult.vulnerabilities.map((vuln, index) => (
              <div key={index} className="p-4 border border-gray-200 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-medium text-gray-900">
                    SQL Injection - {vuln.type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </h3>
                  <span className={`px-2 py-1 text-xs font-medium rounded-full border ${getSeverityColor(vuln.severity)}`}>
                    {vuln.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-sm text-gray-600 mb-2">
                  Payload: <code className="bg-gray-100 px-1 rounded text-xs">{vuln.payload}</code>
                </p>
                <div className="flex items-center justify-between text-sm text-gray-600">
                  <span>Confidence: {Math.round(vuln.confidence * 100)}%</span>
                  {vuln.response_time && (
                    <span>Response Time: {vuln.response_time.toFixed(2)}s</span>
                  )}
                </div>
                {vuln.extracted_data.length > 0 && (
                  <div className="mt-2">
                    <p className="text-sm font-medium text-gray-700">Extracted Data:</p>
                    <ul className="text-sm text-gray-600 list-disc list-inside">
                      {vuln.extracted_data.map((data, i) => (
                        <li key={i}>{data}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Summary */}
      {scanResult.summary && (
        <div className="card">
          <h2 className="text-lg font-semibold text-gray-900 mb-4">Scan Summary</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center p-4 bg-gray-50 rounded-lg">
              <div className="text-2xl font-bold text-gray-900">{scanResult.summary.total_vulnerabilities}</div>
              <div className="text-sm text-gray-600">Total Vulnerabilities</div>
            </div>
            <div className="text-center p-4 bg-red-50 rounded-lg">
              <div className="text-2xl font-bold text-red-600">
                {scanResult.summary.severity_breakdown.critical + scanResult.summary.severity_breakdown.high}
              </div>
              <div className="text-sm text-red-600">Critical + High</div>
            </div>
            <div className="text-center p-4 bg-blue-50 rounded-lg">
              <div className="text-2xl font-bold text-blue-600">
                {Math.round(scanResult.summary.success_rate * 100)}%
              </div>
              <div className="text-sm text-blue-600">Success Rate</div>
            </div>
            <div className="text-center p-4 bg-green-50 rounded-lg">
              <div className="text-2xl font-bold text-green-600">{scanResult.summary.total_payloads_tested}</div>
              <div className="text-sm text-green-600">Payloads Tested</div>
            </div>
          </div>
        </div>
      )}

      {/* No Vulnerabilities */}
      {scanResult.status === 'completed' && (!scanResult.vulnerabilities || scanResult.vulnerabilities.length === 0) && (
        <div className="card">
          <div className="text-center py-8">
            <CheckCircle className="h-16 w-16 text-green-500 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 mb-2">No Vulnerabilities Found</h3>
            <p className="text-gray-600">
              The scan completed successfully but no SQL injection vulnerabilities were detected.
            </p>
          </div>
        </div>
      )}
    </div>
  )
}
