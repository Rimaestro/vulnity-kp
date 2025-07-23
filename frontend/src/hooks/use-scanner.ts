import { useState, useEffect, useCallback, useRef } from 'react'
import { useToast } from '@/hooks/use-toast'
import { useWebSocket } from '@/hooks/use-websocket'
import { scanApi, vulnerabilityApi } from '@/lib/api'
import type { Scan, Vulnerability, ScanRequest } from '@/types/api'
import type { ScanWithDetails, ScanStats, ScanFilters, ScanUpdate } from '@/types/scanner'

// Utility functions for error handling and retry logic
const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

const isRetryableError = (error: any): boolean => {
  const status = error.response?.status
  // Retry on network errors, 5xx errors, and 422 (which might be temporary validation issues)
  return !status || status >= 500 || status === 422 || status === 429
}

const retryWithBackoff = async <T>(
  fn: () => Promise<T>,
  maxRetries: number = 3,
  baseDelay: number = 1000
): Promise<T> => {
  let lastError: any

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn()
    } catch (error) {
      lastError = error

      // Don't retry on last attempt or non-retryable errors
      if (attempt === maxRetries || !isRetryableError(error)) {
        throw error
      }

      // Exponential backoff with jitter
      const delay = baseDelay * Math.pow(2, attempt) + Math.random() * 1000
      await sleep(delay)
    }
  }

  throw lastError
}

// Debounced error notification to prevent spam
const createDebouncedErrorNotifier = (toast: any, delay: number = 5000) => {
  let timeoutId: NodeJS.Timeout | null = null
  const errorQueue = new Set<string>()

  return (title: string, description: string) => {
    errorQueue.add(description)

    if (timeoutId) {
      clearTimeout(timeoutId)
    }

    timeoutId = setTimeout(() => {
      if (errorQueue.size === 1) {
        toast({
          title,
          description: Array.from(errorQueue)[0],
          variant: "destructive",
        })
      } else {
        toast({
          title: "Multiple Errors",
          description: `${errorQueue.size} errors occurred. Check console for details.`,
          variant: "destructive",
        })
      }
      errorQueue.clear()
      timeoutId = null
    }, delay)
  }
}

export function useScanner() {
  const [scans, setScans] = useState<Scan[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()

  // Create debounced error notifier
  const debouncedErrorNotifier = useRef(createDebouncedErrorNotifier(toast))

  // Update the notifier when toast changes
  useEffect(() => {
    debouncedErrorNotifier.current = createDebouncedErrorNotifier(toast)
  }, [toast])

  // WebSocket for real-time updates (disabled to prevent excessive connections)
  // const token = localStorage.getItem('access_token')
  // const websocket = useWebSocket({
  //   url: 'ws://localhost:8000/ws/scans',
  //   token,
  //   autoConnect: false, // Connect only when needed
  // })

  // Handle real-time scan updates (disabled to prevent excessive refreshing)
  // useEffect(() => {
  //   if (websocket.isConnected) {
  //     const unsubscribe = websocket.subscribe('scan_update', (update: ScanUpdate) => {
  //       setScans(prevScans =>
  //         prevScans.map(scan =>
  //           scan.id === update.scan_id
  //             ? { ...scan, status: update.status as any, progress: update.progress }
  //             : scan
  //         )
  //       )
  //     })

  //     return unsubscribe
  //   }
  // }, [websocket.isConnected, websocket.subscribe])

  const fetchScans = useCallback(async (filters?: ScanFilters) => {
    try {
      setIsLoading(true)
      setError(null)

      const params = {
        page: 1,
        size: 50,
        status_filter: filters?.status?.join(',')
      }

      const response = await retryWithBackoff(() => scanApi.getScans(params))

      if (response.data) {
        setScans(Array.isArray(response.data) ? response.data : [])
      }
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to fetch scans'
      setError(errorMessage)

      // Only show error notification for non-retryable errors or after all retries failed
      if (!isRetryableError(err)) {
        debouncedErrorNotifier.current("Error", errorMessage)
      } else {
        // For retryable errors that failed after retries, show a more informative message
        debouncedErrorNotifier.current(
          "Connection Error",
          "Unable to fetch scans. Please check your connection and try again."
        )
      }

      console.error('Failed to fetch scans:', err)
    } finally {
      setIsLoading(false)
    }
  }, [])  // Remove toast dependency since we're using ref

  const startScan = useCallback(async (scanRequest: ScanRequest) => {
    try {
      setError(null)
      const response = await retryWithBackoff(() => scanApi.startScan(scanRequest), 2) // Fewer retries for user actions

      toast({
        title: "Scan Started",
        description: `Scan "${scanRequest.scan_name || 'Unnamed scan'}" has been started successfully.`,
      })

      // Refresh scans list
      await fetchScans()

      return response.data
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to start scan'
      setError(errorMessage)

      // Always show error for user-initiated actions, but use debounced notifier
      debouncedErrorNotifier.current("Scan Failed", errorMessage)

      console.error('Failed to start scan:', err)
      throw err
    }
  }, [fetchScans])  // Remove toast dependency

  const cancelScan = useCallback(async (scanId: string) => {
    try {
      setError(null)
      await scanApi.cancelScan(scanId)
      
      toast({
        title: "Scan Cancelled",
        description: "The scan has been cancelled successfully.",
      })
      
      // Refresh scans list
      await fetchScans()
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to cancel scan'
      setError(errorMessage)
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
    }
  }, [toast, fetchScans])

  const deleteScan = useCallback(async (scanId: string) => {
    try {
      setError(null)
      await scanApi.deleteScan(scanId)
      
      toast({
        title: "Scan Deleted",
        description: "The scan has been deleted successfully.",
      })
      
      // Refresh scans list
      await fetchScans()
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to delete scan'
      setError(errorMessage)
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
    }
  }, [toast, fetchScans])

  return {
    scans,
    isLoading,
    error,
    fetchScans,
    startScan,
    cancelScan,
    deleteScan,
  }
}

export function useScanDetail(scanId: string | null) {
  const [scan, setScan] = useState<ScanWithDetails | null>(null)
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()

  const fetchScanDetail = useCallback(async () => {
    if (!scanId) return

    try {
      setIsLoading(true)
      setError(null)
      
      // Fetch scan details
      const scanResponse = await scanApi.getScan(scanId)
      if (scanResponse.data) {
        setScan(scanResponse.data)
      }
      
      // Fetch vulnerabilities for this scan
      try {
        const vulnResponse = await vulnerabilityApi.getVulnerabilities({
          scan_id: scanId,
          page: 1,
          size: 100
        })
        if (vulnResponse.data) {
          setVulnerabilities(Array.isArray(vulnResponse.data) ? vulnResponse.data : [])
        }
      } catch (vulnErr) {
        // Vulnerabilities might not be available yet, that's okay
        setVulnerabilities([])
      }
      
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to fetch scan details'
      setError(errorMessage)
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
    } finally {
      setIsLoading(false)
    }
  }, [scanId, toast])

  useEffect(() => {
    fetchScanDetail()
  }, [scanId]) // Only depend on scanId, not fetchScanDetail to prevent infinite loop

  const downloadReport = useCallback(async (format: 'pdf' | 'json' | 'csv' = 'pdf') => {
    if (!scanId) return

    try {
      const response = await scanApi.downloadScanReport(scanId, format)
      
      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `scan-report-${scanId}.${format}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
      
      toast({
        title: "Report Downloaded",
        description: `Scan report has been downloaded as ${format.toUpperCase()}.`,
      })
    } catch (err: any) {
      const errorMessage = err.response?.data?.detail || 'Failed to download report'
      toast({
        title: "Error",
        description: errorMessage,
        variant: "destructive",
      })
    }
  }, [scanId, toast])

  return {
    scan,
    vulnerabilities,
    isLoading,
    error,
    fetchScanDetail,
    downloadReport,
  }
}

export function useScanStats() {
  const [stats, setStats] = useState<ScanStats | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const { toast } = useToast()

  // Create debounced error notifier for stats
  const debouncedErrorNotifier = useRef(createDebouncedErrorNotifier(toast, 10000)) // Longer delay for stats

  // Update the notifier when toast changes
  useEffect(() => {
    debouncedErrorNotifier.current = createDebouncedErrorNotifier(toast, 10000)
  }, [toast])

  const fetchStats = useCallback(async () => {
    try {
      setIsLoading(true)
      setError(null)

      // Try primary stats endpoint with retry
      const response = await retryWithBackoff(() => scanApi.getScanStats())
      if (response.data) {
        setStats(response.data)
        return
      }
    } catch (err: any) {
      console.warn('Primary stats endpoint failed, trying fallback calculation:', err)
    }

    // Fallback: calculate stats from scans list (use max allowed limit)
    try {
      const scansResponse = await retryWithBackoff(() => scanApi.getScans({ size: 100 }))
      if (scansResponse.data) {
        const scans = Array.isArray(scansResponse.data) ? scansResponse.data : []
        const calculatedStats: ScanStats = {
          total_scans: scans.length,
          running_scans: scans.filter(s => s.status === 'running').length,
          completed_scans: scans.filter(s => s.status === 'completed').length,
          failed_scans: scans.filter(s => s.status === 'failed').length,
          total_vulnerabilities: scans.reduce((sum, s) => sum + (s.total_vulnerabilities || 0), 0),
          critical_vulnerabilities: scans.reduce((sum, s) => sum + (s.critical_count || 0), 0),
          high_vulnerabilities: scans.reduce((sum, s) => sum + (s.high_count || 0), 0),
          medium_vulnerabilities: scans.reduce((sum, s) => sum + (s.medium_count || 0), 0),
          low_vulnerabilities: scans.reduce((sum, s) => sum + (s.low_count || 0), 0),
        }
        setStats(calculatedStats)
      }
    } catch (fallbackErr: any) {
      const errorMessage = 'Unable to load scan statistics. Please check your connection.'
      setError(errorMessage)

      // Only show error notification if both primary and fallback failed
      // Use debounced notifier to prevent spam
      debouncedErrorNotifier.current("Statistics Unavailable", errorMessage)

      console.error('Both primary and fallback stats failed:', fallbackErr)
    } finally {
      setIsLoading(false)
    }
  }, [])  // Remove toast dependency

  useEffect(() => {
    fetchStats()
  }, [fetchStats]) // Include fetchStats dependency for proper effect cleanup

  return {
    stats,
    isLoading,
    error,
    fetchStats,
  }
}
