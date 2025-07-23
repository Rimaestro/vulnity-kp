import * as React from "react"
import { motion } from "framer-motion"
import { 
  Shield, 
  Clock, 
  TrendingUp, 
  TrendingDown, 
  AlertTriangle, 
  CheckCircle,
  Target,
  Timer,
  Zap
} from "lucide-react"

import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

import { useVulnerabilityData, type RiskMetrics as RiskMetricsType } from "@/hooks/use-vulnerability-data"

interface RiskMetricsProps {
  className?: string
  compact?: boolean
}

function RiskMetrics({ className, compact = false }: RiskMetricsProps) {
  const { riskMetrics, stats, loading, error } = useVulnerabilityData()

  if (loading) {
    return (
      <div className={cn("space-y-4", className)}>
        {compact ? (
          <div className="flex items-center space-x-4">
            {Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="flex items-center space-x-2">
                <Skeleton className="h-4 w-4 rounded-full" />
                <Skeleton className="h-4 w-16" />
              </div>
            ))}
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {Array.from({ length: 4 }).map((_, i) => (
              <div key={i} className="space-y-2">
                <Skeleton className="h-4 w-16" />
                <Skeleton className="h-6 w-12" />
                <Skeleton className="h-2 w-full" />
              </div>
            ))}
          </div>
        )}
      </div>
    )
  }

  if (error || !riskMetrics || !stats) {
    return (
      <div className={cn("text-center py-4", className)}>
        <p className="text-sm text-muted-foreground">Unable to load risk metrics</p>
      </div>
    )
  }

  const getRiskScoreColor = (score: number) => {
    if (score >= 8) return "text-red-600 dark:text-red-400"
    if (score >= 6) return "text-orange-600 dark:text-orange-400"
    if (score >= 4) return "text-yellow-600 dark:text-yellow-400"
    return "text-green-600 dark:text-green-400"
  }

  const getRiskScoreBadgeVariant = (score: number) => {
    if (score >= 8) return "destructive"
    if (score >= 6) return "secondary"
    if (score >= 4) return "outline"
    return "default"
  }

  const getSlaColor = (compliance: number) => {
    if (compliance >= 95) return "text-green-600 dark:text-green-400"
    if (compliance >= 85) return "text-yellow-600 dark:text-yellow-400"
    return "text-red-600 dark:text-red-400"
  }

  const getSlaProgressColor = (compliance: number) => {
    if (compliance >= 95) return "bg-green-500"
    if (compliance >= 85) return "bg-yellow-500"
    return "bg-red-500"
  }

  const getTrendIcon = (direction: string) => {
    switch (direction) {
      case "up":
        return <TrendingUp className="h-4 w-4 text-red-500" />
      case "down":
        return <TrendingDown className="h-4 w-4 text-green-500" />
      default:
        return <CheckCircle className="h-4 w-4 text-muted-foreground" />
    }
  }

  const formatDuration = (days: number) => {
    if (days < 1) return `${Math.round(days * 24)}h`
    if (days < 7) return `${Math.round(days)}d`
    return `${Math.round(days / 7)}w`
  }

  if (compact) {
    return (
      <div className={cn("flex items-center space-x-6", className)}>
        {/* Risk Score */}
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center space-x-2">
                <Target className="h-4 w-4 text-muted-foreground" />
                <Badge variant={getRiskScoreBadgeVariant(riskMetrics.riskScore)} className="text-xs">
                  Risk: {riskMetrics.riskScore.toFixed(1)}/10
                </Badge>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p>Overall security risk score</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        {/* SLA Compliance */}
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center space-x-2">
                <Shield className="h-4 w-4 text-muted-foreground" />
                <Badge variant="outline" className="text-xs">
                  SLA: {Math.round(riskMetrics.slaCompliance)}%
                </Badge>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p>SLA compliance rate</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        {/* Average Fix Time */}
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <div className="flex items-center space-x-2">
                <Timer className="h-4 w-4 text-muted-foreground" />
                <Badge variant="secondary" className="text-xs">
                  Avg Fix: {formatDuration(riskMetrics.averageFixTime)}
                </Badge>
              </div>
            </TooltipTrigger>
            <TooltipContent>
              <p>Average time to fix vulnerabilities</p>
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>

        {/* Trend */}
        {riskMetrics.trendDirection !== "stable" && (
          <TooltipProvider>
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center space-x-1">
                  {getTrendIcon(riskMetrics.trendDirection)}
                  <span className="text-xs text-muted-foreground">
                    {riskMetrics.trendPercentage.toFixed(1)}%
                  </span>
                </div>
              </TooltipTrigger>
              <TooltipContent>
                <p>Trend from last week</p>
              </TooltipContent>
            </Tooltip>
          </TooltipProvider>
        )}
      </div>
    )
  }

  return (
    <div className={cn("space-y-6", className)}>
      {/* Main Metrics Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {/* Risk Score */}
        <motion.div
          className="space-y-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <div className="flex items-center space-x-2">
            <Target className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">Risk Score</span>
          </div>
          <div className={cn("text-2xl font-bold", getRiskScoreColor(riskMetrics.riskScore))}>
            {riskMetrics.riskScore.toFixed(1)}
            <span className="text-sm text-muted-foreground">/10</span>
          </div>
          <Progress 
            value={(riskMetrics.riskScore / 10) * 100} 
            className="h-2"
          />
        </motion.div>

        {/* SLA Compliance */}
        <motion.div
          className="space-y-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.2 }}
        >
          <div className="flex items-center space-x-2">
            <Shield className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">SLA Compliance</span>
          </div>
          <div className={cn("text-2xl font-bold", getSlaColor(riskMetrics.slaCompliance))}>
            {Math.round(riskMetrics.slaCompliance)}
            <span className="text-sm text-muted-foreground">%</span>
          </div>
          <Progress 
            value={riskMetrics.slaCompliance} 
            className="h-2"
          />
        </motion.div>

        {/* Average Fix Time */}
        <motion.div
          className="space-y-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.3 }}
        >
          <div className="flex items-center space-x-2">
            <Clock className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">Avg Fix Time</span>
          </div>
          <div className="text-2xl font-bold">
            {formatDuration(riskMetrics.averageFixTime)}
          </div>
          <div className="text-xs text-muted-foreground">
            {riskMetrics.averageFixTime.toFixed(1)} days average
          </div>
        </motion.div>

        {/* Critical SLA Breaches */}
        <motion.div
          className="space-y-2"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.4 }}
        >
          <div className="flex items-center space-x-2">
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">SLA Breaches</span>
          </div>
          <div className={cn(
            "text-2xl font-bold",
            riskMetrics.criticalSlaBreaches > 0 ? "text-red-600 dark:text-red-400" : "text-green-600 dark:text-green-400"
          )}>
            {riskMetrics.criticalSlaBreaches}
          </div>
          <div className="text-xs text-muted-foreground">
            Critical issues overdue
          </div>
        </motion.div>
      </div>

      {/* Trend Analysis */}
      {riskMetrics.trendDirection !== "stable" && (
        <motion.div
          className="flex items-center justify-between p-4 bg-muted/50 rounded-lg"
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.3, delay: 0.5 }}
        >
          <div className="flex items-center space-x-3">
            {getTrendIcon(riskMetrics.trendDirection)}
            <div>
              <div className="text-sm font-medium">
                {riskMetrics.trendDirection === "up" ? "Increasing" : "Decreasing"} Vulnerabilities
              </div>
              <div className="text-xs text-muted-foreground">
                {riskMetrics.trendPercentage.toFixed(1)}% change from last week
              </div>
            </div>
          </div>
          <Badge 
            variant={riskMetrics.trendDirection === "up" ? "destructive" : "default"}
            className="text-xs"
          >
            {riskMetrics.trendDirection === "up" ? "Action Needed" : "Improving"}
          </Badge>
        </motion.div>
      )}

      {/* Quick Stats */}
      <div className="grid grid-cols-3 gap-4 text-center">
        <div className="space-y-1">
          <div className="text-lg font-bold text-red-600 dark:text-red-400">
            {stats.critical + stats.high}
          </div>
          <div className="text-xs text-muted-foreground">High Priority</div>
        </div>
        <div className="space-y-1">
          <div className="text-lg font-bold text-blue-600 dark:text-blue-400">
            {stats.inProgress}
          </div>
          <div className="text-xs text-muted-foreground">In Progress</div>
        </div>
        <div className="space-y-1">
          <div className="text-lg font-bold text-green-600 dark:text-green-400">
            {stats.fixed}
          </div>
          <div className="text-xs text-muted-foreground">Fixed</div>
        </div>
      </div>
    </div>
  )
}

export { RiskMetrics }
export type { RiskMetricsProps }
