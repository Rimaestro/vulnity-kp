import { useState, useEffect } from 'react'
import { RefreshCw, Download, Filter, Search, Shield, AlertTriangle } from 'lucide-react'
import { motion } from 'framer-motion'

import { DashboardLayout, DashboardHeader, DashboardContent } from '@/components/dashboard/dashboard-layout'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { useToast } from '@/hooks/use-toast'
import { useVulnerabilityData } from '@/hooks/use-vulnerability-data'

import { VulnerabilityStats } from '@/components/vulnerabilities/vulnerability-stats'
import { VulnerabilityFilters } from '@/components/vulnerabilities/vulnerability-filters'
import { VulnerabilityList } from '@/components/vulnerabilities/vulnerability-list'
import { VulnerabilityDetail } from '@/components/vulnerabilities/vulnerability-detail'

import type { VulnerabilityItem } from '@/hooks/use-vulnerability-data'

export function VulnerabilitiesPage() {
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedVulnerability, setSelectedVulnerability] = useState<VulnerabilityItem | null>(null)
  const [showFilters, setShowFilters] = useState(false)
  const [filters, setFilters] = useState({
    severity: [] as string[],
    type: [] as string[],
    status: [] as string[],
  })

  const { toast } = useToast()
  const {
    vulnerabilities,
    stats,
    riskMetrics,
    criticalActions,
    loading,
    error,
    refreshData,
    getVulnerabilitiesBySeverity,
    getVulnerabilitiesByType,
    getVulnerabilitiesByStatus
  } = useVulnerabilityData()

  // Filter vulnerabilities based on search and filters
  const filteredVulnerabilities = vulnerabilities.filter(vuln => {
    // Search filter
    const matchesSearch = !searchQuery || 
      vuln.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      vuln.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
      vuln.target.toLowerCase().includes(searchQuery.toLowerCase())

    // Severity filter
    const matchesSeverity = filters.severity.length === 0 || 
      filters.severity.includes(vuln.severity)

    // Type filter
    const matchesType = filters.type.length === 0 || 
      filters.type.includes(vuln.type)

    // Status filter
    const matchesStatus = filters.status.length === 0 || 
      filters.status.includes(vuln.status)

    return matchesSearch && matchesSeverity && matchesType && matchesStatus
  })

  const handleRefresh = async () => {
    try {
      await refreshData()
      toast({
        title: "Data Refreshed",
        description: "Vulnerability data has been updated successfully.",
      })
    } catch (err) {
      toast({
        title: "Refresh Failed",
        description: "Failed to refresh vulnerability data. Please try again.",
        variant: "destructive",
      })
    }
  }

  const handleExport = () => {
    // TODO: Implement export functionality
    toast({
      title: "Export Started",
      description: "Vulnerability report export will be available soon.",
    })
  }

  const handleVulnerabilityClick = (vulnerability: VulnerabilityItem) => {
    setSelectedVulnerability(vulnerability)
  }

  const handleCloseDetail = () => {
    setSelectedVulnerability(null)
  }

  const handleFilterChange = (newFilters: typeof filters) => {
    setFilters(newFilters)
  }

  return (
    <DashboardLayout>
      <DashboardHeader
        breadcrumbs={[
          { title: "Dashboard", href: "/dashboard" },
          { title: "Vulnerabilities" }
        ]}
        actions={
          <>
            <Button 
              variant="outline" 
              onClick={() => setShowFilters(!showFilters)}
              className={showFilters ? 'bg-muted' : ''}
            >
              <Filter className="mr-2 h-4 w-4" />
              Filters
            </Button>
            <Button variant="outline" onClick={handleRefresh} disabled={loading}>
              <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <Button variant="outline" onClick={handleExport}>
              <Download className="mr-2 h-4 w-4" />
              Export
            </Button>
          </>
        }
      />

      <DashboardContent>
        {/* Page Header */}
        <div className="mb-8">
          <div className="flex items-center space-x-3 mb-6">
            <div className="p-2 bg-destructive/10 rounded-lg">
              <Shield className="h-6 w-6 text-destructive" />
            </div>
            <div>
              <h1 className="text-3xl font-bold tracking-tight">Vulnerabilities</h1>
              <p className="text-muted-foreground">
                Monitor and manage security vulnerabilities across your applications
              </p>
            </div>
          </div>

          {/* Critical Actions Alert */}
          {criticalActions && criticalActions.length > 0 && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              className="mb-6"
            >
              <Card className="border-destructive/50 bg-destructive/5">
                <CardHeader className="pb-3">
                  <div className="flex items-center space-x-2">
                    <AlertTriangle className="h-5 w-5 text-destructive" />
                    <CardTitle className="text-destructive">Critical Actions Required</CardTitle>
                  </div>
                  <CardDescription>
                    {criticalActions.length} critical vulnerabilities need immediate attention
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2">
                    {criticalActions.slice(0, 3).map((vuln) => (
                      <div 
                        key={vuln.id}
                        className="flex items-center justify-between p-2 bg-background rounded border cursor-pointer hover:bg-muted/50"
                        onClick={() => handleVulnerabilityClick(vuln)}
                      >
                        <div>
                          <p className="font-medium text-sm">{vuln.title}</p>
                          <p className="text-xs text-muted-foreground">{vuln.target}</p>
                        </div>
                        <div className="text-right">
                          <span className="text-xs font-medium text-destructive">
                            {vuln.severity.toUpperCase()}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          )}
        </div>

        {/* Statistics */}
        <VulnerabilityStats 
          stats={stats}
          riskMetrics={riskMetrics}
          loading={loading}
        />

        {/* Filters */}
        {showFilters && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="mb-6"
          >
            <VulnerabilityFilters
              filters={filters}
              onFiltersChange={handleFilterChange}
              vulnerabilities={vulnerabilities}
            />
          </motion.div>
        )}

        {/* Search */}
        <div className="mb-6">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground h-4 w-4" />
            <Input
              placeholder="Search vulnerabilities by title, description, or target..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-10"
            />
          </div>
        </div>

        {/* Vulnerabilities List */}
        <VulnerabilityList
          vulnerabilities={filteredVulnerabilities}
          loading={loading}
          error={error}
          onVulnerabilityClick={handleVulnerabilityClick}
        />

        {/* Vulnerability Detail Modal */}
        <VulnerabilityDetail
          vulnerability={selectedVulnerability}
          open={!!selectedVulnerability}
          onClose={handleCloseDetail}
        />
      </DashboardContent>
    </DashboardLayout>
  )
}
