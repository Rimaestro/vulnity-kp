import { useState } from 'react'
import { format } from 'date-fns'
import { motion } from 'framer-motion'
import {
  MoreHorizontal,
  Eye,
  Download,
  Trash2,
  Play,
  Pause,
  Clock,
  CheckCircle,
  XCircle,
  AlertCircle
} from 'lucide-react'

import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import type { Scan } from '@/types/api'

interface RecentScansTableProps {
  scans?: Scan[]
  isLoading?: boolean
  onViewScan?: (scanId: string) => void
  onDownloadReport?: (scanId: string) => void
  onDeleteScan?: (scanId: string) => void
  onPauseScan?: (scanId: string) => void
  onResumeScan?: (scanId: string) => void
}

function getStatusIcon(status: Scan['status']) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-green-500" />
    case 'running':
      return <Play className="h-4 w-4 text-blue-500" />
    case 'pending':
      return <Clock className="h-4 w-4 text-yellow-500" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-red-500" />
    case 'cancelled':
      return <AlertCircle className="h-4 w-4 text-gray-500" />
    default:
      return <Clock className="h-4 w-4 text-gray-500" />
  }
}

function getStatusBadge(status: Scan['status']) {
  const variants = {
    completed: 'default' as const,
    running: 'secondary' as const,
    pending: 'outline' as const,
    failed: 'destructive' as const,
    cancelled: 'secondary' as const,
  }

  const labels = {
    completed: 'Selesai',
    running: 'Berjalan',
    pending: 'Menunggu',
    failed: 'Gagal',
    cancelled: 'Dibatalkan',
  }

  return (
    <Badge variant={variants[status]} className="flex items-center gap-1">
      {getStatusIcon(status)}
      {labels[status]}
    </Badge>
  )
}

function getRiskBadge(count: number, type: 'critical' | 'high' | 'medium' | 'low') {
  if (count === 0) return null

  const variants = {
    critical: 'destructive' as const,
    high: 'destructive' as const,
    medium: 'outline' as const,
    low: 'secondary' as const,
  }

  const colors = {
    critical: 'text-red-600',
    high: 'text-orange-600',
    medium: 'text-yellow-600',
    low: 'text-blue-600',
  }

  return (
    <Badge variant={variants[type]} className={colors[type]}>
      {count}
    </Badge>
  )
}

export function RecentScansTable({
  scans = [],
  isLoading = false,
  onViewScan,
  onDownloadReport,
  onDeleteScan,
  onPauseScan,
  onResumeScan
}: RecentScansTableProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-6 w-32" />
          <Skeleton className="h-4 w-48" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-center space-x-4">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-16" />
                <Skeleton className="h-4 w-20" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (scans.length === 0) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Recent Scans</CardTitle>
          <CardDescription>
            Scan terbaru akan ditampilkan di sini
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8">
            <div className="mx-auto h-12 w-12 text-muted-foreground mb-4">
              <svg
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
                />
              </svg>
            </div>
            <h3 className="text-lg font-medium text-muted-foreground mb-2">
              Belum ada scan
            </h3>
            <p className="text-sm text-muted-foreground mb-4">
              Mulai scan pertama Anda untuk melihat hasilnya di sini
            </p>
            <Button>
              <Play className="h-4 w-4 mr-2" />
              Mulai Scan Baru
            </Button>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Scans</CardTitle>
        <CardDescription>
          {scans.length} scan terbaru dari aktivitas Anda
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Target URL</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Progress</TableHead>
              <TableHead>Vulnerabilities</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="w-[70px]"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scans.map((scan, index) => (
              <motion.div
                key={scan.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.1, duration: 0.3 }}
                style={{ display: 'contents' }}
              >
                <TableRow className="hover:bg-muted/50 transition-colors hover-lift">
                <TableCell>
                  <div>
                    <div className="font-medium">
                      {scan.scan_name || 'Unnamed Scan'}
                    </div>
                    <div className="text-sm text-muted-foreground truncate max-w-[200px]">
                      {scan.target_url}
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  {getStatusBadge(scan.status)}
                </TableCell>
                <TableCell>
                  <div className="space-y-1">
                    <Progress value={scan.progress} className="w-[60px]" />
                    <div className="text-xs text-muted-foreground">
                      {scan.progress}%
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  <div className="flex items-center space-x-1">
                    {getRiskBadge(scan.critical_count, 'critical')}
                    {getRiskBadge(scan.high_count, 'high')}
                    {getRiskBadge(scan.medium_count, 'medium')}
                    {getRiskBadge(scan.low_count, 'low')}
                    {scan.total_vulnerabilities === 0 && (
                      <span className="text-sm text-muted-foreground">-</span>
                    )}
                  </div>
                </TableCell>
                <TableCell>
                  <div className="text-sm">
                    {format(new Date(scan.created_at), 'dd/MM/yyyy')}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {format(new Date(scan.created_at), 'HH:mm')}
                  </div>
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" className="h-8 w-8 p-0">
                        <span className="sr-only">Open menu</span>
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuLabel>Actions</DropdownMenuLabel>
                      <DropdownMenuItem onClick={() => onViewScan?.(scan.id)}>
                        <Eye className="mr-2 h-4 w-4" />
                        View Details
                      </DropdownMenuItem>
                      {scan.status === 'completed' && (
                        <DropdownMenuItem onClick={() => onDownloadReport?.(scan.id)}>
                          <Download className="mr-2 h-4 w-4" />
                          Download Report
                        </DropdownMenuItem>
                      )}
                      {scan.status === 'running' && (
                        <DropdownMenuItem onClick={() => onPauseScan?.(scan.id)}>
                          <Pause className="mr-2 h-4 w-4" />
                          Pause Scan
                        </DropdownMenuItem>
                      )}
                      {scan.status === 'pending' && (
                        <DropdownMenuItem onClick={() => onResumeScan?.(scan.id)}>
                          <Play className="mr-2 h-4 w-4" />
                          Resume Scan
                        </DropdownMenuItem>
                      )}
                      <DropdownMenuSeparator />
                      <DropdownMenuItem 
                        onClick={() => onDeleteScan?.(scan.id)}
                        className="text-red-600"
                      >
                        <Trash2 className="mr-2 h-4 w-4" />
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
                </TableRow>
              </motion.div>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
