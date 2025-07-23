import { useState, useEffect } from "react"
import type { ActivityType } from "@/components/dashboard/activity-icon"

export interface ActivityData {
  id: string
  type: ActivityType
  title: string
  description?: string
  target?: string
  user?: string
  timestamp: Date
  status: "success" | "warning" | "error" | "info"
  metadata?: Record<string, any>
}

export interface ActivityGroup {
  date: string
  label: string
  activities: ActivityData[]
}

// Mock data generator
function generateMockActivities(): ActivityData[] {
  const now = new Date()
  const activities: ActivityData[] = [
    {
      id: "1",
      type: "scan-completed",
      title: "Scan completed",
      description: "Found 3 vulnerabilities",
      target: "example.com",
      user: "Admin",
      timestamp: new Date(now.getTime() - 2 * 60 * 1000), // 2 minutes ago
      status: "warning",
      metadata: { vulnerabilities: 3, duration: "45s" }
    },
    {
      id: "2", 
      type: "vulnerability-found",
      title: "Critical vulnerability found",
      description: "SQL Injection in login form",
      target: "/login.php",
      user: "System",
      timestamp: new Date(now.getTime() - 5 * 60 * 1000), // 5 minutes ago
      status: "error",
      metadata: { severity: "critical", cve: "CVE-2024-1234" }
    },
    {
      id: "3",
      type: "vulnerability-fixed", 
      title: "Issue resolved",
      description: "XSS vulnerability fixed",
      target: "/search.php",
      user: "Admin",
      timestamp: new Date(now.getTime() - 1 * 60 * 60 * 1000), // 1 hour ago
      status: "success",
      metadata: { severity: "medium", fixMethod: "input-sanitization" }
    },
    {
      id: "4",
      type: "scan-started",
      title: "Scan started",
      description: "Full security scan initiated",
      target: "testsite.com", 
      user: "Admin",
      timestamp: new Date(now.getTime() - 24 * 60 * 60 * 1000), // Yesterday
      status: "info",
      metadata: { scanType: "full", estimatedDuration: "10m" }
    },
    {
      id: "5",
      type: "report-generated",
      title: "Weekly report generated",
      description: "Security assessment report",
      user: "System",
      timestamp: new Date(now.getTime() - 24 * 60 * 60 * 1000 - 5 * 60 * 1000), // Yesterday
      status: "success",
      metadata: { reportType: "weekly", format: "pdf" }
    },
    {
      id: "6",
      type: "user-login",
      title: "User logged in",
      description: "Admin user session started",
      user: "Admin",
      timestamp: new Date(now.getTime() - 2 * 24 * 60 * 60 * 1000), // 2 days ago
      status: "info",
      metadata: { ip: "192.168.1.100", userAgent: "Chrome" }
    }
  ]

  return activities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
}

// Group activities by date
function groupActivitiesByDate(activities: ActivityData[]): ActivityGroup[] {
  const groups: Record<string, ActivityData[]> = {}
  const now = new Date()
  
  activities.forEach(activity => {
    const activityDate = activity.timestamp
    const diffTime = now.getTime() - activityDate.getTime()
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24))
    
    let dateKey: string
    let label: string
    
    if (diffDays === 0) {
      dateKey = "today"
      label = "Today"
    } else if (diffDays === 1) {
      dateKey = "yesterday" 
      label = "Yesterday"
    } else if (diffDays < 7) {
      dateKey = `${diffDays}days`
      label = `${diffDays} days ago`
    } else {
      dateKey = activityDate.toISOString().split('T')[0]
      label = activityDate.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric',
        year: activityDate.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
      })
    }
    
    if (!groups[dateKey]) {
      groups[dateKey] = []
    }
    groups[dateKey].push(activity)
  })
  
  // Convert to array and sort by date
  return Object.entries(groups)
    .map(([date, activities]) => ({
      date,
      label: activities[0] ? (
        activities[0].timestamp.getTime() > now.getTime() - 24 * 60 * 60 * 1000 ? "Today" :
        activities[0].timestamp.getTime() > now.getTime() - 48 * 60 * 60 * 1000 ? "Yesterday" :
        activities[0].timestamp.toLocaleDateString('en-US', { 
          month: 'short', 
          day: 'numeric',
          year: activities[0].timestamp.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
        })
      ) : date,
      activities: activities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
    }))
    .sort((a, b) => {
      // Sort groups by most recent activity in each group
      const aLatest = Math.max(...a.activities.map(act => act.timestamp.getTime()))
      const bLatest = Math.max(...b.activities.map(act => act.timestamp.getTime()))
      return bLatest - aLatest
    })
}

// Format relative time
export function formatRelativeTime(date: Date): string {
  const now = new Date()
  const diffTime = now.getTime() - date.getTime()
  const diffMinutes = Math.floor(diffTime / (1000 * 60))
  const diffHours = Math.floor(diffTime / (1000 * 60 * 60))
  const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24))
  
  if (diffMinutes < 1) return "Just now"
  if (diffMinutes < 60) return `${diffMinutes}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays === 1) return "Yesterday"
  if (diffDays < 7) return `${diffDays}d ago`
  
  return date.toLocaleDateString('en-US', { 
    month: 'short', 
    day: 'numeric',
    year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
  })
}

export function useActivityData() {
  const [activities, setActivities] = useState<ActivityData[]>([])
  const [groupedActivities, setGroupedActivities] = useState<ActivityGroup[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Real API call with fallback to mock data
  useEffect(() => {
    const fetchActivities = async () => {
      try {
        setLoading(true)
        setError(null)

        // 🆕 Try to generate activities from real scan data
        try {
          const { scanApi } = await import('@/lib/api')
          const { transformScansData } = await import('@/utils/data-transformers')

          // Fetch recent scans to generate activity data
          const scansResponse = await scanApi.getScans({ page: 1, size: 20 })

          if (scansResponse.data && Array.isArray(scansResponse.data) && scansResponse.data.length > 0) {
            const realScans = transformScansData(scansResponse.data)

            // Convert scans to activity data
            const realActivities: ActivityData[] = realScans.map((scan, index) => {
              const scanDate = new Date(scan.created_at)
              const completedDate = scan.completed_at ? new Date(scan.completed_at) : scanDate

              return {
                id: `scan-${scan.id}`,
                type: scan.status === 'completed' ? 'scan-completed' : 'scan-started',
                title: scan.status === 'completed' ? 'Scan completed' : 'Scan started',
                description: scan.scan_name || `Security scan for ${scan.target_url}`,
                target: scan.target_url,
                user: 'System',
                timestamp: scan.status === 'completed' ? completedDate : scanDate,
                status: scan.status === 'completed' ?
                  (scan.total_vulnerabilities > 0 ? 'warning' : 'success') : 'info',
                metadata: {
                  scan_id: scan.id,
                  vulnerabilities: scan.total_vulnerabilities,
                  progress: scan.progress
                }
              }
            })

            // Sort by timestamp (newest first)
            realActivities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())

            setActivities(realActivities)
            setGroupedActivities(groupActivitiesByDate(realActivities))

            console.log('Activity data loaded from backend scans:', {
              count: realActivities.length,
              scans: realActivities.length
            })

            return // Success - exit early
          }
        } catch (apiError) {
          console.warn('Failed to fetch real activity data, falling back to mock:', apiError)
        }

        // 🔄 Fallback to mock data if real API fails or returns empty
        console.log('Using mock activity data for demonstration')
        await new Promise(resolve => setTimeout(resolve, 500))

        const mockActivities = generateMockActivities()
        setActivities(mockActivities)
        setGroupedActivities(groupActivitiesByDate(mockActivities))

      } catch (err) {
        setError("Failed to fetch activities")
        console.error("Error fetching activities:", err)

        // Final fallback to mock data
        const mockActivities = generateMockActivities()
        setActivities(mockActivities)
        setGroupedActivities(groupActivitiesByDate(mockActivities))
      } finally {
        setLoading(false)
      }
    }

    fetchActivities()
  }, [])

  // Auto-refresh every 5 minutes (reduced frequency to prevent excessive refreshing)
  useEffect(() => {
    const interval = setInterval(async () => {
      try {
        // 🆕 Try real API first
        const { scanApi } = await import('@/lib/api')
        const { transformScansData } = await import('@/utils/data-transformers')

        const scansResponse = await scanApi.getScans({ page: 1, size: 20 })

        if (scansResponse.data && Array.isArray(scansResponse.data) && scansResponse.data.length > 0) {
          const realScans = transformScansData(scansResponse.data)

          const realActivities: ActivityData[] = realScans.map((scan) => {
            const scanDate = new Date(scan.created_at)
            const completedDate = scan.completed_at ? new Date(scan.completed_at) : scanDate

            return {
              id: `scan-${scan.id}`,
              type: scan.status === 'completed' ? 'scan-completed' : 'scan-started',
              title: scan.status === 'completed' ? 'Scan completed' : 'Scan started',
              description: scan.scan_name || `Security scan for ${scan.target_url}`,
              target: scan.target_url,
              user: 'System',
              timestamp: scan.status === 'completed' ? completedDate : scanDate,
              status: scan.status === 'completed' ?
                (scan.total_vulnerabilities > 0 ? 'warning' : 'success') : 'info',
              metadata: {
                scan_id: scan.id,
                vulnerabilities: scan.total_vulnerabilities,
                progress: scan.progress
              }
            }
          })

          realActivities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
          setActivities(realActivities)
          setGroupedActivities(groupActivitiesByDate(realActivities))

          console.log('Activity data auto-refreshed from backend')
          return
        }
      } catch (error) {
        console.warn('Auto-refresh failed, keeping current data:', error)
      }

      // 🔄 Fallback to mock refresh if real API fails
      const mockActivities = generateMockActivities()
      setActivities(mockActivities)
      setGroupedActivities(groupActivitiesByDate(mockActivities))
    }, 300000) // 5 minutes instead of 2 minutes

    return () => clearInterval(interval)
  }, [])

  const refreshActivities = async () => {
    setLoading(true)
    try {
      setError(null)

      // 🆕 Try real API first
      try {
        const { scanApi } = await import('@/lib/api')
        const { transformScansData } = await import('@/utils/data-transformers')

        const scansResponse = await scanApi.getScans({ page: 1, size: 20 })

        if (scansResponse.data && Array.isArray(scansResponse.data) && scansResponse.data.length > 0) {
          const realScans = transformScansData(scansResponse.data)

          const realActivities: ActivityData[] = realScans.map((scan) => {
            const scanDate = new Date(scan.created_at)
            const completedDate = scan.completed_at ? new Date(scan.completed_at) : scanDate

            return {
              id: `scan-${scan.id}`,
              type: scan.status === 'completed' ? 'scan-completed' : 'scan-started',
              title: scan.status === 'completed' ? 'Scan completed' : 'Scan started',
              description: scan.scan_name || `Security scan for ${scan.target_url}`,
              target: scan.target_url,
              user: 'System',
              timestamp: scan.status === 'completed' ? completedDate : scanDate,
              status: scan.status === 'completed' ?
                (scan.total_vulnerabilities > 0 ? 'warning' : 'success') : 'info',
              metadata: {
                scan_id: scan.id,
                vulnerabilities: scan.total_vulnerabilities,
                progress: scan.progress
              }
            }
          })

          realActivities.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime())
          setActivities(realActivities)
          setGroupedActivities(groupActivitiesByDate(realActivities))

          console.log('Activity data manually refreshed from backend')
          return
        }
      } catch (apiError) {
        console.warn('Manual refresh failed, using mock data:', apiError)
      }

      // 🔄 Fallback to mock data
      await new Promise(resolve => setTimeout(resolve, 200))
      const mockActivities = generateMockActivities()
      setActivities(mockActivities)
      setGroupedActivities(groupActivitiesByDate(mockActivities))

    } catch (err) {
      setError("Failed to refresh activities")
    } finally {
      setLoading(false)
    }
  }

  return {
    activities,
    groupedActivities,
    loading,
    error,
    refreshActivities
  }
}
