import { useState } from 'react'
import { format } from 'date-fns'
import { 
  Shield, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock, 
  Download,
  Eye,
  AlertCircle,
  Info
} from 'lucide-react'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { VulnerabilityDetail } from '@/components/vulnerabilities/vulnerability-detail'
import type { Vulnerability } from '@/types/api'
import type { ScanWithDetails, VulnerabilitySummary } from '@/types/scanner'
import type { VulnerabilityItem } from '@/hooks/use-vulnerability-data'

interface ScanDetailProps {
  scan: ScanWithDetails
  vulnerabilities?: Vulnerability[]
  onClose?: () => void
}

export function ScanDetail({ scan, vulnerabilities = [], onClose }: ScanDetailProps) {
  const [activeTab, setActiveTab] = useState('overview')
  const [selectedVulnerability, setSelectedVulnerability] = useState<VulnerabilityItem | null>(null)

  // Convert Vulnerability to VulnerabilityItem format for the detail modal
  const convertToVulnerabilityItem = (vuln: Vulnerability): VulnerabilityItem => {
    // Map vulnerability type to allowed types
    const mapVulnType = (type: string): VulnerabilityItem['type'] => {
      const typeMap: Record<string, VulnerabilityItem['type']> = {
        'sql_injection': 'sql-injection',
        'cross_site_scripting': 'xss',
        'cross_site_request_forgery': 'csrf',
        'file_upload': 'file-upload',
        'authentication_bypass': 'auth-bypass',
        'information_disclosure': 'info-disclosure',
        'denial_of_service': 'dos',
        'remote_code_execution': 'rce'
      }
      return typeMap[type] || 'info-disclosure'
    }

    // Map severity (exclude 'info' as it's not in VulnerabilityItem)
    const mapSeverity = (risk: string): VulnerabilityItem['severity'] => {
      if (risk === 'info') return 'low'
      return risk as VulnerabilityItem['severity']
    }

    return {
      id: vuln.id.toString(),
      title: vuln.title,
      description: vuln.description || '',
      severity: mapSeverity(vuln.risk),
      type: mapVulnType(vuln.vulnerability_type),
      status: vuln.status === 'confirmed' ? 'open' : 
              vuln.status === 'false_positive' ? 'dismissed' : 
              vuln.status as VulnerabilityItem['status'],
      target: vuln.endpoint || '',
      discoveredAt: new Date(vuln.created_at || Date.now()),
      lastUpdated: new Date(vuln.created_at || Date.now()),
      impact: mapSeverity(vuln.risk) as 'high' | 'medium' | 'low',
      exploitability: mapSeverity(vuln.risk) as 'high' | 'medium' | 'low',
      fixComplexity: 'medium' as 'low' | 'medium' | 'high',
      cve: vuln.cwe_id || undefined,
      tags: [],
      assignedTo: undefined,
      cvssScore: vuln.cvss_score || undefined,
      estimatedFixTime: 4 // Default 4 hours
    }
  }

  const handleVulnerabilityClick = (vulnerability: Vulnerability) => {
    const vulnerabilityItem = convertToVulnerabilityItem(vulnerability)
    setSelectedVulnerability(vulnerabilityItem)
  }

  const handleCloseVulnerabilityDetail = () => {
    setSelectedVulnerability(null)
  }

  // Calculate vulnerability summary
  const vulnerabilitySummary: VulnerabilitySummary = {
    total: vulnerabilities.length,
    by_risk: {
      critical: vulnerabilities.filter(v => v.risk === 'critical').length,
      high: vulnerabilities.filter(v => v.risk === 'high').length,
      medium: vulnerabilities.filter(v => v.risk === 'medium').length,
      low: vulnerabilities.filter(v => v.risk === 'low').length,
      info: vulnerabilities.filter(v => v.risk === 'info').length,
    },
    by_type: vulnerabilities.reduce((acc, v) => {
      acc[v.vulnerability_type] = (acc[v.vulnerability_type] || 0) + 1
      return acc
    }, {} as Record<string, number>),
    by_status: vulnerabilities.reduce((acc, v) => {
      acc[v.status] = (acc[v.status] || 0) + 1
      return acc
    }, {} as Record<string, number>)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'running':
        return <Clock className="h-4 w-4 text-blue-500" />
      case 'failed':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'cancelled':
        return <XCircle className="h-4 w-4 text-gray-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusColor = (status: string): "default" | "secondary" | "destructive" | "outline" => {
    switch (status) {
      case 'completed':
        return 'default'
      case 'running':
        return 'secondary'
      case 'failed':
        return 'destructive'
      case 'cancelled':
        return 'outline'
      default:
        return 'outline'
    }
  }

  const getRiskIcon = (risk: string) => {
    switch (risk) {
      case 'critical':
        return <AlertTriangle className="h-4 w-4 text-red-600" />
      case 'high':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />
      case 'medium':
        return <AlertCircle className="h-4 w-4 text-yellow-500" />
      case 'low':
        return <Info className="h-4 w-4 text-blue-500" />
      default:
        return <Info className="h-4 w-4 text-gray-500" />
    }
  }

  const getRiskColor = (risk: string): "default" | "secondary" | "destructive" | "outline" => {
    switch (risk) {
      case 'critical':
        return 'destructive'
      case 'high':
        return 'destructive'
      case 'medium':
        return 'default'
      case 'low':
        return 'secondary'
      default:
        return 'outline'
    }
  }
  
  const getRiskBadgeClass = (risk: string): string => {
    switch (risk) {
      case 'critical':
        return 'bg-red-600 hover:bg-red-700 text-white'
      case 'high':
        return 'bg-orange-600 hover:bg-orange-700 text-white'
      case 'medium':
        return 'border-yellow-500 text-yellow-600'
      case 'low':
        return 'text-blue-600'
      default:
        return ''
    }
  }

  return (
    <div className="space-y-6">

      {/* Status Overview */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center space-x-2">
            <Shield className="h-5 w-5" />
            <span>Scan Status</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                {getStatusIcon(scan.status)}
                <Badge variant={getStatusColor(scan.status)}>
                  {scan.status.toUpperCase()}
                </Badge>
              </div>
              <p className="text-sm text-muted-foreground">Current Status</p>
            </div>
            
            <div className="space-y-2">
              <div className="text-2xl font-bold">{scan.progress}%</div>
              <Progress value={scan.progress} className="w-full" />
              <p className="text-sm text-muted-foreground">Progress</p>
            </div>
            
            <div className="space-y-2">
              <div className="text-2xl font-bold">{vulnerabilitySummary.total}</div>
              <p className="text-sm text-muted-foreground">Vulnerabilities Found</p>
            </div>
            
            <div className="space-y-2">
              <div className="text-2xl font-bold">
                {scan.created_at ? format(new Date(scan.created_at), 'MMM dd, yyyy') : 'N/A'}
              </div>
              <p className="text-sm text-muted-foreground">Scan Date</p>
            </div>
          </div>

          {scan.current_phase && (
            <div className="mt-4">
              <Alert>
                <Clock className="h-4 w-4" />
                <AlertDescription>
                  Current Phase: {scan.current_phase}
                </AlertDescription>
              </Alert>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Vulnerability Summary */}
      {vulnerabilitySummary.total > 0 && (
        <Card>
          <CardHeader>
            <CardTitle>Vulnerability Summary</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-red-600">{vulnerabilitySummary.by_risk.critical}</div>
                <p className="text-sm text-muted-foreground">Critical</p>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-500">{vulnerabilitySummary.by_risk.high}</div>
                <p className="text-sm text-muted-foreground">High</p>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-yellow-500">{vulnerabilitySummary.by_risk.medium}</div>
                <p className="text-sm text-muted-foreground">Medium</p>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-blue-500">{vulnerabilitySummary.by_risk.low}</div>
                <p className="text-sm text-muted-foreground">Low</p>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-gray-500">{vulnerabilitySummary.by_risk.info}</div>
                <p className="text-sm text-muted-foreground">Info</p>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Detailed Information */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="vulnerabilities">
            Vulnerabilities ({vulnerabilitySummary.total})
          </TabsTrigger>
          <TabsTrigger value="details">Technical Details</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Scan Information</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium">Target URL</h4>
                  <p className="text-sm text-muted-foreground">{scan.target_url}</p>
                </div>
                <div>
                  <h4 className="font-medium">Scan ID</h4>
                  <p className="text-sm text-muted-foreground">{scan.id}</p>
                </div>
                <div>
                  <h4 className="font-medium">Started At</h4>
                  <p className="text-sm text-muted-foreground">
                    {scan.started_at ? format(new Date(scan.started_at), 'PPpp') : 'Not started'}
                  </p>
                </div>
                <div>
                  <h4 className="font-medium">Completed At</h4>
                  <p className="text-sm text-muted-foreground">
                    {scan.completed_at ? format(new Date(scan.completed_at), 'PPpp') : 'Not completed'}
                  </p>
                </div>
              </div>
              
              {scan.description && (
                <div>
                  <h4 className="font-medium">Description</h4>
                  <p className="text-sm text-muted-foreground">{scan.description}</p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="vulnerabilities" className="space-y-4">
          {vulnerabilities.length === 0 ? (
            <Card>
              <CardContent className="text-center py-8">
                <CheckCircle className="h-12 w-12 text-green-500 mx-auto mb-4" />
                <h3 className="text-lg font-medium">No Vulnerabilities Found</h3>
                <p className="text-muted-foreground">
                  Great! No security vulnerabilities were detected in this scan.
                </p>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardHeader>
                <CardTitle>Vulnerabilities</CardTitle>
                <CardDescription>
                  Detailed list of security vulnerabilities found during the scan
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Vulnerability</TableHead>
                      <TableHead>Risk</TableHead>
                      <TableHead>Type</TableHead>
                      <TableHead>Endpoint</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Actions</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {vulnerabilities.map((vulnerability) => (
                      <TableRow key={vulnerability.id}>
                        <TableCell>
                          <div>
                            <div className="font-medium">{vulnerability.title}</div>
                            {vulnerability.description && (
                              <div className="text-sm text-muted-foreground">
                                {vulnerability.description.substring(0, 100)}...
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center space-x-2">
                            {getRiskIcon(vulnerability.risk)}
                            <Badge variant={getRiskColor(vulnerability.risk)} className={getRiskBadgeClass(vulnerability.risk)}>
                              {vulnerability.risk.toUpperCase()}
                            </Badge>
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">
                            {vulnerability.vulnerability_type.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <div className="text-sm">
                            <div>{vulnerability.endpoint}</div>
                            {vulnerability.parameter && (
                              <div className="text-muted-foreground">
                                Parameter: {vulnerability.parameter}
                              </div>
                            )}
                          </div>
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline">
                            {vulnerability.status.replace('_', ' ').toUpperCase()}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <Button 
                            variant="outline" 
                            size="sm"
                            onClick={() => handleVulnerabilityClick(vulnerability)}
                          >
                            <Eye className="h-4 w-4 mr-2" />
                            View Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="details" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Technical Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="font-medium">Scan Configuration</h4>
                  <div className="text-sm text-muted-foreground space-y-1">
                    <div>Max Depth: {scan.max_depth || 'N/A'}</div>
                    <div>Max Requests: {scan.max_requests || 'N/A'}</div>
                    <div>Request Delay: {scan.request_delay || 'N/A'}s</div>
                  </div>
                </div>
                <div>
                  <h4 className="font-medium">Scan Metadata</h4>
                  <div className="text-sm text-muted-foreground space-y-1">
                    {scan.scan_metadata?.duration && (
                      <div>Duration: {Math.round(scan.scan_metadata.duration)}s</div>
                    )}
                    {scan.scan_metadata?.parameters_tested && (
                      <div>Parameters Tested: {scan.scan_metadata.parameters_tested.length}</div>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Vulnerability Detail Modal */}
      <VulnerabilityDetail
        vulnerability={selectedVulnerability}
        open={!!selectedVulnerability}
        onClose={handleCloseVulnerabilityDetail}
      />
    </div>
  )
}
