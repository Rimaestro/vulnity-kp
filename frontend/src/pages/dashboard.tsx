import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '@/contexts/auth-context'
import { DashboardLayout, DashboardHeader, DashboardContent } from '@/components/dashboard/dashboard-layout'
import { DashboardStats, VulnerabilityBreakdown } from '@/components/dashboard/dashboard-stats'
import { RecentScansTable } from '@/components/dashboard/recent-scans-table'
import { RecentActivity } from '@/components/dashboard/recent-activity'
import { VulnerabilityChart } from '@/components/dashboard'
import { useDashboardData, useScanOperations } from '@/hooks/use-dashboard-data'
import { useWebSocketDashboard } from '@/hooks/use-websocket'
import { SmartRefreshButton, useSmartRefresh } from '@/components/dashboard/smart-refresh-button'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { AnimatedButton } from '@/components/ui/button'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { AlertCircle, Plus, Download, Calendar, RefreshCw } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

export function DashboardPage() {
  const { user } = useAuth()
  const navigate = useNavigate()
  const [refreshKey, setRefreshKey] = useState(0)

  const {
    stats,
    recentScans,
    vulnerabilityBreakdown,
    isLoading,
    error,
    refresh
  } = useDashboardData()

  // WebSocket integration for real-time updates
  const websocket = useWebSocketDashboard()

  // Smart refresh integration
  const { isRefreshing, lastRefresh, handleRefresh } = useSmartRefresh(
    async () => {
      setRefreshKey(prev => prev + 1)
      await refresh()
    },
    websocket.connectionStatus
  )

  // Debug logging
  console.log('Dashboard render:', { isLoading, stats, error })

  // Fallback stats if data is not available
  const fallbackStats = {
    totalScans: 12,
    activeScans: 2,
    totalVulnerabilities: 23,
    criticalVulnerabilities: 3,
    highVulnerabilities: 7,
    mediumVulnerabilities: 9,
    lowVulnerabilities: 4,
    fixedVulnerabilities: 8,
  }

  const {
    viewScan,
    downloadReport,
    deleteScan,
    pauseScan,
    resumeScan,
    isLoading: isOperationLoading
  } = useScanOperations()

  // WebSocket event subscriptions (throttled to prevent excessive refreshing)
  React.useEffect(() => {
    if (!websocket.isConnected) return

    let refreshTimeout: NodeJS.Timeout | null = null

    // Throttled refresh function to prevent excessive API calls
    const throttledRefresh = () => {
      if (refreshTimeout) return // Already scheduled

      refreshTimeout = setTimeout(() => {
        refresh()
        refreshTimeout = null
      }, 2000) // Wait 2 seconds before refreshing
    }

    // Subscribe to dashboard updates
    const unsubscribeDashboard = websocket.subscribe('dashboard_update', (data) => {
      console.log('Received dashboard update via WebSocket:', data)
      throttledRefresh()
    })

    // Subscribe to scan updates
    const unsubscribeScan = websocket.subscribe('scan_update', (data) => {
      console.log('Received scan update via WebSocket:', data)
      throttledRefresh()
    })

    // Subscribe to notifications
    const unsubscribeNotification = websocket.subscribe('notification', (data) => {
      console.log('Received notification via WebSocket:', data)
      // You can show toast notifications here
    })

    return () => {
      unsubscribeDashboard()
      unsubscribeScan()
      unsubscribeNotification()
      // Clear any pending refresh timeout
      if (refreshTimeout) {
        clearTimeout(refreshTimeout)
      }
    }
  }, [websocket.isConnected, websocket.subscribe, refresh])

  const handleNewScan = () => {
    navigate('/dashboard/scans')
  }

  const handleViewScans = () => {
    navigate('/dashboard/scans')
  }

  const handleViewReports = () => {
    console.log('Viewing reports...')
    // TODO: Navigate to reports page when implemented
  }

  const handleSettings = () => {
    console.log('Opening settings...')
    // TODO: Navigate to settings page when implemented
  }

  return (
    <DashboardLayout>
      <DashboardHeader
        breadcrumbs={[
          { title: "Dashboard" }
        ]}
        actions={
          <>
            {/* Smart Refresh Button with WebSocket status */}
            <SmartRefreshButton
              onRefresh={handleRefresh}
              isLoading={isRefreshing || isLoading}
              connectionStatus={websocket.connectionStatus}
              lastUpdate={lastRefresh}
              lastPing={websocket.lastPing}
            />

            <AnimatedButton variant="outline" hoverScale={1.02}>
              <Download className="mr-2 h-4 w-4" />
              Export Report
            </AnimatedButton>
            <AnimatedButton variant="outline" hoverScale={1.02}>
              <Calendar className="mr-2 h-4 w-4" />
              Date Range
            </AnimatedButton>
            <AnimatedButton onClick={handleNewScan} hoverScale={1.05}>
              <Plus className="mr-2 h-4 w-4" />
              New Scan
            </AnimatedButton>
          </>
        }
      />

      <DashboardContent>
        {/* Welcome Section */}
        <div className="mb-6">
          <h1 className="text-3xl font-bold tracking-tight">
            Selamat datang, {user?.full_name || user?.username}! 👋
          </h1>
          <p className="text-muted-foreground">
            Dashboard Vulnity vulnerability scanner siap digunakan.
          </p>
        </div>

        {error && (
          <Alert className="mb-6">
            <AlertCircle className="h-4 w-4" />
            <AlertDescription>
              {error}. Menampilkan data contoh untuk demonstrasi.
            </AlertDescription>
          </Alert>
        )}

        {/* Tab Navigation */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
            <TabsTrigger value="reports">Reports</TabsTrigger>
            <TabsTrigger value="scans">Recent Scans</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="space-y-4">
              {/* Stats Overview */}
              <DashboardStats
                isLoading={isLoading}
                stats={stats || fallbackStats}
              />

              {/* Charts and Tables Grid */}
              <div className="grid gap-4 lg:grid-cols-6">
                {/* Enhanced Vulnerability Dashboard */}
                <VulnerabilityChart
                  className="lg:col-span-3"
                  onSeverityClick={(severity) => console.log('Filter by severity:', severity)}
                  showTrend={true}
                />

                <Card className="lg:col-span-3 hover-lift">
                  <CardHeader>
                    <CardTitle>Recent Activity</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <RecentActivity
                      maxItems={8}
                      showFilters={true}
                      autoRefresh={true}
                    />
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="scans" className="space-y-4">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Card className="hover-lift">
                <CardHeader>
                  <CardTitle>Recent Scans</CardTitle>
                </CardHeader>
                <CardContent>
                  <RecentScansTable
                    scans={recentScans}
                    isLoading={isLoading}
                    onViewScan={viewScan}
                    onDownloadReport={downloadReport}
                    onDeleteScan={deleteScan}
                    onPauseScan={pauseScan}
                    onResumeScan={resumeScan}
                  />
                </CardContent>
              </Card>
            </motion.div>
          </TabsContent>

          {/* Other tabs content */}
          <TabsContent value="analytics">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Card className="hover-lift">
                <CardHeader>
                  <CardTitle>Analytics Dashboard</CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Analytics content will be implemented here.</p>
                </CardContent>
              </Card>
            </motion.div>
          </TabsContent>

          <TabsContent value="reports">
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              <Card className="hover-lift">
                <CardHeader>
                  <CardTitle>Reports</CardTitle>
                </CardHeader>
                <CardContent>
                  <p>Reports content will be implemented here.</p>
                </CardContent>
              </Card>
            </motion.div>
          </TabsContent>
        </Tabs>
      </DashboardContent>
    </DashboardLayout>
  )
}
