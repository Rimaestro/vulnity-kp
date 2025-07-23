import React, { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, RefreshCw, Trash2, Share2 } from 'lucide-react'
import { motion } from 'framer-motion'
import { DashboardLayout, DashboardHeader, DashboardContent } from '@/components/dashboard/dashboard-layout'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Separator } from '@/components/ui/separator'
import { useScanDetail } from '@/hooks/use-scanner'
import { ScanDetail } from '@/components/scanner/scan-detail'
import { Skeleton } from '@/components/ui/skeleton'
import { Alert, AlertDescription } from '@/components/ui/alert'

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const { scan, vulnerabilities, isLoading, error, fetchScanDetail, downloadReport } = useScanDetail(id || null)

  const handleBack = () => {
    navigate('/dashboard/scans')
  }

  const handleRefresh = () => {
    fetchScanDetail()
  }

  const handleDownloadReport = async (format: 'pdf' | 'json' | 'csv' = 'pdf') => {
    await downloadReport(format)
  }

  const handleShare = () => {
    if (navigator.share) {
      navigator.share({
        title: `Scan Report: ${scan?.scan_name || 'Unnamed Scan'}`,
        text: `Vulnerability scan results for ${scan?.target_url}`,
        url: window.location.href,
      })
    } else {
      // Fallback: copy to clipboard
      navigator.clipboard.writeText(window.location.href)
    }
  }

  if (isLoading) {
    return (
      <DashboardLayout>
        <DashboardHeader
          breadcrumbs={[
            { title: "Dashboard", href: "/dashboard" },
            { title: "Scans", href: "/dashboard/scans" },
            { title: "Loading..." }
          ]}
        />
        <DashboardContent>
          <div className="space-y-6">
            <Skeleton className="h-32 w-full" />
            <div className="space-y-4">
              <Skeleton className="h-8 w-1/3" />
              <Skeleton className="h-4 w-2/3" />
              <Skeleton className="h-4 w-1/2" />
            </div>
          </div>
        </DashboardContent>
      </DashboardLayout>
    )
  }

  if (error || !scan) {
    return (
      <DashboardLayout>
        <DashboardHeader
          breadcrumbs={[
            { title: "Dashboard", href: "/dashboard" },
            { title: "Scans", href: "/dashboard/scans" },
            { title: "Error" }
          ]}
        />
        <DashboardContent>
          <Alert variant="destructive">
            <AlertDescription>
              {error || 'Scan not found'}
            </AlertDescription>
          </Alert>
          <div className="mt-4">
            <Button onClick={handleBack} variant="outline">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Scans
            </Button>
          </div>
        </DashboardContent>
      </DashboardLayout>
    )
  }

  const getStatusBadgeVariant = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return 'default'
      case 'running':
        return 'secondary'
      case 'failed':
        return 'destructive'
      case 'cancelled':
        return 'outline'
      default:
        return 'secondary'
    }
  }

  return (
    <DashboardLayout>
      <DashboardHeader
        breadcrumbs={[
          { title: "Dashboard", href: "/dashboard" },
          { title: "Scans", href: "/dashboard/scans" },
          { title: scan.scan_name || 'Unnamed Scan' }
        ]}
        actions={
          <>
            <Button variant="outline" onClick={handleBack}>
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Scans
            </Button>
            <Button variant="outline" onClick={handleRefresh} disabled={isLoading}>
              <motion.div
                animate={isLoading ? { rotate: 360 } : { rotate: 0 }}
                transition={{
                  duration: 0.8,
                  ease: "easeInOut",
                  repeat: isLoading ? Infinity : 0
                }}
                className="mr-2"
              >
                <RefreshCw className="h-4 w-4" />
              </motion.div>
              Refresh
            </Button>
            <Button variant="outline" onClick={handleShare}>
              <Share2 className="mr-2 h-4 w-4" />
              Share
            </Button>
            <Button variant="outline" onClick={() => handleDownloadReport('pdf')}>
              <Download className="mr-2 h-4 w-4" />
              Export Report
            </Button>
          </>
        }
      />
      
      <DashboardContent>
        {/* Scan Detail Component */}
        <ScanDetail
          scan={scan}
          vulnerabilities={vulnerabilities}
        />
      </DashboardContent>
    </DashboardLayout>
  )
}
