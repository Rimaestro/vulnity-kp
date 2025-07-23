import { useState, useEffect } from 'react'
import { scanApi, vulnerabilityApi } from '@/lib/api'
import type { Scan, Vulnerability } from '@/types/api'
import {
  transformScansData,
  transformVulnerabilityStats,
  transformApiResponse,
  safeGet
} from '@/utils/data-transformers'

interface DashboardStats {
  totalScans: number
  activeScans: number
  totalVulnerabilities: number
  criticalVulnerabilities: number
  highVulnerabilities: number
  mediumVulnerabilities: number
  lowVulnerabilities: number
  fixedVulnerabilities: number
}

interface VulnerabilityBreakdown {
  critical: number
  high: number
  medium: number
  low: number
}

interface DashboardData {
  stats: DashboardStats
  recentScans: Scan[]
  vulnerabilityBreakdown: VulnerabilityBreakdown
  isLoading: boolean
  error: string | null
  refresh: () => Promise<void>
}

export function useDashboardData(): DashboardData {
  const [stats, setStats] = useState<DashboardStats>({
    totalScans: 0,
    activeScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    highVulnerabilities: 0,
    mediumVulnerabilities: 0,
    lowVulnerabilities: 0,
    fixedVulnerabilities: 0,
  })

  const [recentScans, setRecentScans] = useState<Scan[]>([])
  const [vulnerabilityBreakdown, setVulnerabilityBreakdown] = useState<VulnerabilityBreakdown>({
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
  })

  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchDashboardData = async () => {
    try {
      setIsLoading(true)
      setError(null)

      // Fetch scans data with proper parameter transformation
      const scansResponse = await scanApi.getScans({ page: 1, size: 10 })

      // Transform backend response to frontend format
      const rawScansData = scansResponse.data
      const scansData = Array.isArray(rawScansData)
        ? transformScansData(rawScansData)
        : transformApiResponse(rawScansData, (scan: any) => transformScansData([scan])[0])

      setRecentScans(scansData)

      // Calculate scan stats
      const totalScans = scansData.length
      const activeScans = scansData.filter(scan =>
        scan.status === 'running' || scan.status === 'pending'
      ).length

      // Fetch vulnerability stats with proper endpoint
      const vulnStatsResponse = await vulnerabilityApi.getVulnerabilityStats()

      // Transform vulnerability stats to frontend format
      const rawVulnStats = vulnStatsResponse.data
      const vulnStats = transformVulnerabilityStats(rawVulnStats)

      // Calculate vulnerability breakdown
      const breakdown = {
        critical: safeGet(vulnStats, 'critical_count', 0),
        high: safeGet(vulnStats, 'high_count', 0),
        medium: safeGet(vulnStats, 'medium_count', 0),
        low: safeGet(vulnStats, 'low_count', 0),
      }

      setVulnerabilityBreakdown(breakdown)

      // Update stats with transformed data
      setStats({
        totalScans,
        activeScans,
        totalVulnerabilities: safeGet(vulnStats, 'total_count', 0),
        criticalVulnerabilities: breakdown.critical,
        highVulnerabilities: breakdown.high,
        mediumVulnerabilities: breakdown.medium,
        lowVulnerabilities: breakdown.low,
        fixedVulnerabilities: safeGet(vulnStats, 'fixed_count', 0),
      })

      console.log('Dashboard data loaded successfully:', {
        scansCount: scansData.length,
        vulnStats: vulnStats,
        breakdown
      })

    } catch (err: any) {
      console.error('Error fetching dashboard data:', err)

      // Enhanced error logging
      if (err.response) {
        console.error('API Error Response:', {
          status: err.response.status,
          statusText: err.response.statusText,
          data: err.response.data
        })
      }

      setError(err.response?.data?.message || 'Failed to load dashboard data')

      // Set mock data for development
      if (process.env.NODE_ENV === 'development') {
        console.log('Falling back to mock data for development')
        setMockData()
      }
    } finally {
      setIsLoading(false)
    }
  }

  const setMockData = () => {
    // Mock data for development
    const mockScans: Scan[] = [
      {
        id: '1',
        target_url: 'https://example.com',
        scan_name: 'Example Website Scan',
        status: 'completed',
        progress: 100,
        total_vulnerabilities: 15,
        critical_count: 2,
        high_count: 5,
        medium_count: 6,
        low_count: 2,
        created_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
      },
      {
        id: '2',
        target_url: 'https://test.com',
        scan_name: 'Test Site Scan',
        status: 'running',
        progress: 65,
        total_vulnerabilities: 8,
        critical_count: 1,
        high_count: 2,
        medium_count: 3,
        low_count: 2,
        created_at: new Date(Date.now() - 3600000).toISOString(),
        started_at: new Date(Date.now() - 3600000).toISOString(),
      },
      {
        id: '3',
        target_url: 'https://demo.com',
        scan_name: 'Demo Application',
        status: 'pending',
        progress: 0,
        total_vulnerabilities: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        created_at: new Date(Date.now() - 7200000).toISOString(),
      }
    ]

    setRecentScans(mockScans)
    
    const mockBreakdown = {
      critical: 3,
      high: 7,
      medium: 9,
      low: 4,
    }
    
    setVulnerabilityBreakdown(mockBreakdown)
    
    setStats({
      totalScans: 12,
      activeScans: 2,
      totalVulnerabilities: 23,
      criticalVulnerabilities: 3,
      highVulnerabilities: 7,
      mediumVulnerabilities: 9,
      lowVulnerabilities: 4,
      fixedVulnerabilities: 8,
    })
  }

  useEffect(() => {
    fetchDashboardData()
  }, [])

  return {
    stats,
    recentScans,
    vulnerabilityBreakdown,
    isLoading,
    error,
    refresh: fetchDashboardData,
  }
}

// Hook for individual scan operations
export function useScanOperations() {
  const [isLoading, setIsLoading] = useState(false)

  const viewScan = async (scanId: string) => {
    // Navigate to scan detail page
    console.log('Viewing scan:', scanId)
  }

  const downloadReport = async (scanId: string) => {
    try {
      setIsLoading(true)
      // Implement report download
      console.log('Downloading report for scan:', scanId)
    } catch (error) {
      console.error('Error downloading report:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const deleteScan = async (scanId: string) => {
    try {
      setIsLoading(true)
      await scanApi.deleteScan(scanId)
      console.log('Scan deleted:', scanId)
    } catch (error) {
      console.error('Error deleting scan:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const pauseScan = async (scanId: string) => {
    try {
      setIsLoading(true)
      await scanApi.updateScanStatus(scanId, { status: 'cancelled' })
      console.log('Scan paused:', scanId)
    } catch (error) {
      console.error('Error pausing scan:', error)
    } finally {
      setIsLoading(false)
    }
  }

  const resumeScan = async (scanId: string) => {
    try {
      setIsLoading(true)
      await scanApi.updateScanStatus(scanId, { status: 'pending' })
      console.log('Scan resumed:', scanId)
    } catch (error) {
      console.error('Error resuming scan:', error)
    } finally {
      setIsLoading(false)
    }
  }

  return {
    viewScan,
    downloadReport,
    deleteScan,
    pauseScan,
    resumeScan,
    isLoading,
  }
}
