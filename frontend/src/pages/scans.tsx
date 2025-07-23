import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Search, Filter, Download, RefreshCw } from 'lucide-react'
import { motion } from 'framer-motion'

import { DashboardLayout, DashboardHeader, DashboardContent } from '@/components/dashboard/dashboard-layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

import { Badge } from '@/components/ui/badge'
import { useToast } from '@/hooks/use-toast'

import type { ScanFilters } from '@/types/scanner'
import { ScanForm } from '@/components/scanner/scan-form'
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog'
import { useScanner, useScanStats } from '@/hooks/use-scanner'

export function ScansPage() {
  const navigate = useNavigate()
  const [searchQuery, setSearchQuery] = useState('')
  const [filters] = useState<ScanFilters>({}) // Removed setFilters as it's not used
  const [showNewScanModal, setShowNewScanModal] = useState(false)
  const { toast } = useToast()

  // Use custom hooks
  const { scans, isLoading, fetchScans, cancelScan } = useScanner()
  const { stats } = useScanStats()

  // Load scans on component mount and filter changes
  useEffect(() => {
    fetchScans(filters)
  }, [filters]) // Remove fetchScans dependency to prevent infinite loop

  const handleNewScan = () => {
    navigate('/dashboard/scans/new')
  }

  const handleScanSuccess = () => {
    setShowNewScanModal(false)
    fetchScans(filters) // Refresh the scans list
  }

  const handleRefresh = () => {
    fetchScans(filters)
  }

  const handleViewScan = (scanId: string) => {
    navigate(`/dashboard/scans/${scanId}`)
  }

  const handleCancelScan = async (scanId: string) => {
    await cancelScan(scanId)
  }



  const handleExport = () => {
    toast({
      title: "Export Started",
      description: "Your scan report is being generated...",
    })
  }

  const filteredScans = scans.filter(scan => 
    scan.target_url.toLowerCase().includes(searchQuery.toLowerCase()) ||
    scan.scan_name?.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <DashboardLayout>
      <DashboardHeader
        breadcrumbs={[
          { title: "Dashboard", href: "/dashboard" },
          { title: "Scans" }
        ]}
        actions={
          <>
            <Button variant="outline" onClick={handleRefresh} disabled={isLoading}>
              <RefreshCw className={`mr-2 h-4 w-4 ${isLoading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button variant="outline" onClick={handleExport}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
            <Button onClick={handleNewScan}>
              <Plus className="mr-2 h-4 w-4" />
              New Scan
            </Button>
          </>
        }
      />

      <DashboardContent>
        <div className="space-y-6">
          {/* Stats Overview */}
          {stats && (
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.total_scans}</div>
                  <p className="text-xs text-muted-foreground">
                    {stats.running_scans} running
                  </p>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Vulnerabilities</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.total_vulnerabilities}</div>
                  <p className="text-xs text-muted-foreground">
                    {stats.critical_vulnerabilities} critical
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Completed</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">{stats.completed_scans}</div>
                  <p className="text-xs text-muted-foreground">
                    {stats.failed_scans} failed
                  </p>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-2xl font-bold">
                    {stats.total_scans > 0 
                      ? Math.round((stats.completed_scans / stats.total_scans) * 100)
                      : 0}%
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Last 30 days
                  </p>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Search and Filters */}
          <div className="flex items-center space-x-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search scans..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
              />
            </div>
            <Button variant="outline">
              <Filter className="mr-2 h-4 w-4" />
              Filters
            </Button>
          </div>

          {/* Scans Table */}
          <Card>
            <CardHeader>
              <CardTitle>Recent Scans</CardTitle>
              <CardDescription>
                Manage and monitor your vulnerability scans
              </CardDescription>
            </CardHeader>
            <CardContent>
              {isLoading ? (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="h-8 w-8 animate-spin" />
                </div>
              ) : filteredScans.length === 0 ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">No scans found</p>
                  <Button onClick={handleNewScan} className="mt-4">
                    <Plus className="mr-2 h-4 w-4" />
                    Create your first scan
                  </Button>
                </div>
              ) : (
                <div className="space-y-4">
                  {filteredScans.map((scan) => (
                    <motion.div
                      key={scan.id}
                      initial={{ opacity: 0, y: 20 }}
                      animate={{ opacity: 1, y: 0 }}
                      className="flex items-center justify-between p-4 border rounded-lg hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex-1">
                        <div className="flex items-center space-x-2">
                          <h3 className="font-medium">{scan.scan_name || scan.target_url}</h3>
                          <Badge variant={
                            scan.status === 'completed' ? 'default' :
                            scan.status === 'running' ? 'secondary' :
                            scan.status === 'failed' ? 'destructive' : 'outline'
                          }>
                            {scan.status}
                          </Badge>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">
                          {scan.target_url}
                        </p>
                        <div className="flex items-center space-x-4 mt-2 text-xs text-muted-foreground">
                          <span>Created: {new Date(scan.created_at).toLocaleDateString()}</span>
                          <span>Vulnerabilities: {scan.total_vulnerabilities}</span>
                          {scan.status === 'running' && (
                            <span>Progress: {scan.progress}%</span>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center space-x-2">
                        <Button variant="outline" size="sm" onClick={() => handleViewScan(scan.id)}>
                          View Details
                        </Button>
                        {scan.status === 'running' && (
                          <Button variant="outline" size="sm" onClick={() => handleCancelScan(scan.id)}>
                            Cancel
                          </Button>
                        )}
                      </div>
                    </motion.div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </DashboardContent>

      {/* New Scan Modal */}
      <Dialog open={showNewScanModal} onOpenChange={setShowNewScanModal}>
        <DialogContent className="max-w-[95vw] max-h-[98vh] overflow-y-auto p-8">
          <DialogHeader>
            <DialogTitle>Create New Scan</DialogTitle>
          </DialogHeader>
          <ScanForm
            onSuccess={handleScanSuccess}
            onCancel={() => setShowNewScanModal(false)}
            isModal={true}
          />
        </DialogContent>
      </Dialog>


    </DashboardLayout>
  )
}
