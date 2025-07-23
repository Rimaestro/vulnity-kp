import {
  Shield,
  Search,
  AlertTriangle,
  CheckCircle,
  TrendingUp,
  TrendingDown,
  Activity
} from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton, SkeletonStats } from '@/components/ui/skeleton'

interface StatsCardProps {
  title: string
  value: string | number
  description?: string
  icon: React.ComponentType<{ className?: string }>
  trend?: {
    value: number
    isPositive: boolean
  }
  badge?: {
    text: string
    variant?: 'default' | 'secondary' | 'destructive' | 'outline'
  }
  numberBadge?: {
    value: number
    isPositive: boolean
  }
}

function StatsCard({ title, value, description, icon: Icon, trend, badge, numberBadge }: StatsCardProps) {
  return (
    <Card className="hover-lift">
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <div className="flex items-center space-x-2">
          {badge && (
            <Badge variant={badge.variant || 'default'} className="text-xs">
              {badge.text}
            </Badge>
          )}
          {numberBadge && (
            <Badge
              variant={numberBadge.isPositive ? "default" : "destructive"}
              className={`text-xs flex items-center gap-1 ${
                numberBadge.isPositive
                  ? 'bg-green-100 text-green-700 hover:bg-green-100 dark:bg-green-900/20 dark:text-green-400'
                  : 'bg-red-100 text-red-700 hover:bg-red-100 dark:bg-red-900/20 dark:text-red-400'
              }`}
            >
              {numberBadge.isPositive ? (
                <TrendingUp className="h-3 w-3" />
              ) : (
                <TrendingDown className="h-3 w-3" />
              )}
              {numberBadge.isPositive ? '+' : ''}{numberBadge.value}%
            </Badge>
          )}
          <Icon className="h-4 w-4 text-muted-foreground" />
        </div>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-between">
          <div className="text-2xl font-bold">{value}</div>
          {trend && (
            <Badge
              variant={trend.isPositive ? "default" : "destructive"}
              className={`text-xs ${
                trend.isPositive
                  ? 'bg-green-100 text-green-700 hover:bg-green-100 dark:bg-green-900/20 dark:text-green-400'
                  : 'bg-red-100 text-red-700 hover:bg-red-100 dark:bg-red-900/20 dark:text-red-400'
              }`}
            >
              {trend.isPositive ? '+' : ''}{trend.value}%
            </Badge>
          )}
        </div>
        {description && (
          <p className="text-xs text-muted-foreground mt-1">
            {description}
          </p>
        )}
      </CardContent>
    </Card>
  )
}

interface DashboardStatsProps {
  isLoading?: boolean
  stats?: {
    totalScans: number
    activeScans: number
    totalVulnerabilities: number
    criticalVulnerabilities: number
    highVulnerabilities: number
    mediumVulnerabilities: number
    lowVulnerabilities: number
    fixedVulnerabilities: number
  }
}

export function DashboardStats({ isLoading = false, stats }: DashboardStatsProps) {
  // Debug logging
  console.log('DashboardStats render:', { isLoading, stats })

  if (isLoading) {
    return (
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <SkeletonStats />
      </div>
    )
  }

  const defaultStats = {
    totalScans: 0,
    activeScans: 0,
    totalVulnerabilities: 0,
    criticalVulnerabilities: 0,
    highVulnerabilities: 0,
    mediumVulnerabilities: 0,
    lowVulnerabilities: 0,
    fixedVulnerabilities: 0,
    ...stats
  }

  // Helper function to calculate trend percentage
  const calculateTrendPercentage = (current: number, previous: number): { value: number; isPositive: boolean } | undefined => {
    if (previous === 0 && current === 0) return undefined // No data to show trend
    if (previous === 0 && current > 0) return { value: 100, isPositive: true } // New data, show as 100% increase
    if (previous > 0 && current === 0) return { value: 100, isPositive: false } // All data gone, show as 100% decrease

    const percentage = Math.round(((current - previous) / previous) * 100)
    return {
      value: Math.abs(percentage),
      isPositive: percentage >= 0
    }
  }

  // Mock historical data for trend calculation (in real app, this would come from API)
  const historicalStats = {
    totalScans: 0, // Previous period scans
    fixedVulnerabilities: 0, // Previous period fixed vulnerabilities
  }

  const statsCards: StatsCardProps[] = [
    {
      title: 'Total Scans',
      value: defaultStats.totalScans,
      description: `${defaultStats.activeScans} scan aktif`,
      icon: Search,
      // Calculate trend based on historical data
      numberBadge: calculateTrendPercentage(defaultStats.totalScans, historicalStats.totalScans)
    },
    {
      title: 'Total Vulnerabilities',
      value: defaultStats.totalVulnerabilities,
      description: 'Semua kerentanan yang ditemukan',
      icon: Shield,
      // Hapus trend (badge angka), biarkan hanya badge "Active"
      badge: defaultStats.totalVulnerabilities > 0 ? {
        text: 'Active',
        variant: 'destructive' as const
      } : undefined
    },
    {
      title: 'Critical Issues',
      value: defaultStats.criticalVulnerabilities,
      description: 'Memerlukan perhatian segera',
      icon: AlertTriangle,
      // Hapus trend (badge angka), tapi tetap pertahankan badge "Urgent"
      badge: defaultStats.criticalVulnerabilities > 0 ? {
        text: 'Urgent',
        variant: 'destructive' as const
      } : undefined
    },
    {
      title: 'Fixed Issues',
      value: defaultStats.fixedVulnerabilities,
      description: 'Kerentanan yang sudah diperbaiki',
      icon: CheckCircle,
      // Calculate trend based on historical data
      numberBadge: calculateTrendPercentage(defaultStats.fixedVulnerabilities, historicalStats.fixedVulnerabilities)
    }
  ]

  return (
    <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
      {statsCards.map((card, index) => (
        <div key={index}>
          <StatsCard {...card} />
        </div>
      ))}
    </div>
  )
}

// Vulnerability Breakdown Component
interface VulnerabilityBreakdownProps {
  isLoading?: boolean
  vulnerabilities?: {
    critical: number
    high: number
    medium: number
    low: number
  }
}

export function VulnerabilityBreakdown({ isLoading = false, vulnerabilities }: VulnerabilityBreakdownProps) {
  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <Skeleton className="h-5 w-48" />
          <Skeleton className="h-4 w-64" />
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="flex items-center justify-between">
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-4 w-8" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  const defaultVulns = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    ...vulnerabilities
  }

  const total = defaultVulns.critical + defaultVulns.high + defaultVulns.medium + defaultVulns.low

  const severityLevels = [
    { 
      name: 'Critical', 
      count: defaultVulns.critical, 
      color: 'bg-red-500',
      textColor: 'text-red-500'
    },
    { 
      name: 'High', 
      count: defaultVulns.high, 
      color: 'bg-orange-500',
      textColor: 'text-orange-500'
    },
    { 
      name: 'Medium', 
      count: defaultVulns.medium, 
      color: 'bg-yellow-500',
      textColor: 'text-yellow-500'
    },
    { 
      name: 'Low', 
      count: defaultVulns.low, 
      color: 'bg-blue-500',
      textColor: 'text-blue-500'
    }
  ]

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center">
          <Activity className="h-5 w-5 mr-2" />
          Vulnerability Breakdown
        </CardTitle>
        <CardDescription>
          Distribusi kerentanan berdasarkan tingkat risiko
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {severityLevels.map((level) => (
            <div key={level.name} className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <div className={`w-3 h-3 rounded-full ${level.color}`} />
                <span className="text-sm font-medium">{level.name}</span>
              </div>
              <div className="flex items-center space-x-2">
                <span className={`text-sm font-bold ${level.textColor}`}>
                  {level.count}
                </span>
                {total > 0 && (
                  <span className="text-xs text-muted-foreground">
                    ({Math.round((level.count / total) * 100)}%)
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
        {total === 0 && (
          <div className="text-center py-4">
            <CheckCircle className="h-8 w-8 text-green-500 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">
              Tidak ada kerentanan yang ditemukan
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
