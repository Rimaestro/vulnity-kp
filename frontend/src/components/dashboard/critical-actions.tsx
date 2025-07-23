import * as React from "react"
import { motion, AnimatePresence } from "framer-motion"
import { 
  AlertTriangle, 
  ExternalLink, 
  Eye, 
  Wrench, 
  Clock, 
  User, 
  Target,
  CheckCircle,
  X,
  MoreHorizontal,
  Zap
} from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

import { useVulnerabilityData, type VulnerabilityItem } from "@/hooks/use-vulnerability-data"

interface CriticalActionsProps {
  className?: string
  maxItems?: number
  onActionClick?: (action: string, vulnerability: VulnerabilityItem) => void
}

const severityConfig = {
  critical: {
    label: "Critical",
    bgColor: "bg-red-500",
    textColor: "text-red-500",
    lightBg: "bg-red-50 dark:bg-red-950",
    lightBorder: "border-red-200 dark:border-red-800",
    badgeVariant: "destructive" as const
  },
  high: {
    label: "High", 
    bgColor: "bg-orange-500",
    textColor: "text-orange-500",
    lightBg: "bg-orange-50 dark:bg-orange-950",
    lightBorder: "border-orange-200 dark:border-orange-800",
    badgeVariant: "secondary" as const
  },
  medium: {
    label: "Medium",
    bgColor: "bg-yellow-500",
    textColor: "text-yellow-500",
    lightBg: "bg-yellow-50 dark:bg-yellow-950",
    lightBorder: "border-yellow-200 dark:border-yellow-800",
    badgeVariant: "outline" as const
  },
  low: {
    label: "Low",
    bgColor: "bg-green-500",
    textColor: "text-green-500",
    lightBg: "bg-green-50 dark:bg-green-950",
    lightBorder: "border-green-200 dark:border-green-800",
    badgeVariant: "default" as const
  }
} as const

function CriticalActions({ 
  className, 
  maxItems = 3,
  onActionClick 
}: CriticalActionsProps) {
  const { criticalActions, loading, error } = useVulnerabilityData()
  const [expandedItem, setExpandedItem] = React.useState<string | null>(null)

  const handleActionClick = (action: string, vulnerability: VulnerabilityItem) => {
    if (onActionClick) {
      onActionClick(action, vulnerability)
    } else {
      // Default actions
      switch (action) {
        case "view":
          console.log("View vulnerability:", vulnerability.id)
          break
        case "fix":
          console.log("Fix vulnerability:", vulnerability.id)
          break
        case "guide":
          console.log("View fix guide for:", vulnerability.id)
          break
        case "dismiss":
          console.log("Dismiss vulnerability:", vulnerability.id)
          break
        default:
          console.log("Unknown action:", action)
      }
    }
  }

  const formatTimeAgo = (date: Date) => {
    const now = new Date()
    const diffTime = now.getTime() - date.getTime()
    const diffDays = Math.floor(diffTime / (1000 * 60 * 60 * 24))
    const diffHours = Math.floor(diffTime / (1000 * 60 * 60))
    
    if (diffDays > 0) return `${diffDays}d ago`
    if (diffHours > 0) return `${diffHours}h ago`
    return "Just now"
  }

  const getVulnerabilityIcon = (type: VulnerabilityItem["type"]) => {
    switch (type) {
      case "sql-injection":
        return <Target className="h-4 w-4" />
      case "xss":
        return <Zap className="h-4 w-4" />
      case "csrf":
        return <AlertTriangle className="h-4 w-4" />
      default:
        return <AlertTriangle className="h-4 w-4" />
    }
  }

  const getPriorityActions = (vulnerability: VulnerabilityItem) => {
    const actions = []
    
    // Primary action based on severity
    if (vulnerability.severity === "critical") {
      actions.push({
        key: "fix",
        label: "Fix Now",
        icon: <Wrench className="h-3 w-3" />,
        variant: "destructive" as const,
        primary: true
      })
    } else {
      actions.push({
        key: "view",
        label: "Review",
        icon: <Eye className="h-3 w-3" />,
        variant: "outline" as const,
        primary: true
      })
    }

    // Secondary actions
    actions.push({
      key: "guide",
      label: "Fix Guide",
      icon: <ExternalLink className="h-3 w-3" />,
      variant: "ghost" as const,
      primary: false
    })

    return actions
  }

  if (loading) {
    return (
      <Card className={cn("hover-lift", className)}>
        <CardHeader>
          <Skeleton className="h-5 w-32" />
          <Skeleton className="h-4 w-48" />
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            {Array.from({ length: maxItems }).map((_, i) => (
              <div key={i} className="flex items-start space-x-3 p-3 border rounded-lg">
                <Skeleton className="h-8 w-8 rounded-full" />
                <div className="flex-1 space-y-2">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
                <Skeleton className="h-6 w-16" />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error || !criticalActions) {
    return (
      <Card className={cn("hover-lift", className)}>
        <CardHeader>
          <CardTitle className="flex items-center text-destructive">
            <AlertTriangle className="h-5 w-5 mr-2" />
            Critical Actions
          </CardTitle>
          <CardDescription>Failed to load critical actions</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="text-center py-8 text-muted-foreground">
            <p className="text-sm">Unable to load critical actions</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  const displayItems = criticalActions.slice(0, maxItems)

  return (
    <Card className={cn("hover-lift", className)}>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <div className="flex items-center">
            <AlertTriangle className="h-5 w-5 mr-2" />
            Critical Actions
          </div>
          {criticalActions.length > 0 && (
            <Badge variant="destructive" className="text-xs">
              {criticalActions.length} urgent
            </Badge>
          )}
        </CardTitle>
        <CardDescription>
          High-priority vulnerabilities requiring immediate attention
        </CardDescription>
      </CardHeader>
      <CardContent>
        {displayItems.length === 0 ? (
          <div className="text-center py-8">
            <div className="w-16 h-16 bg-green-100 dark:bg-green-900/20 rounded-full flex items-center justify-center mx-auto mb-4">
              <CheckCircle className="h-8 w-8 text-green-600 dark:text-green-400" />
            </div>
            <p className="text-sm font-medium">No critical actions needed</p>
            <p className="text-xs text-muted-foreground mt-1">
              All high-priority vulnerabilities are being addressed
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            <AnimatePresence mode="popLayout">
              {displayItems.map((vulnerability, index) => {
                const config = severityConfig[vulnerability.severity]
                const isExpanded = expandedItem === vulnerability.id
                const priorityActions = getPriorityActions(vulnerability)
                
                return (
                  <motion.div
                    key={vulnerability.id}
                    layout
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -20 }}
                    transition={{ duration: 0.2, delay: index * 0.05 }}
                    className={cn(
                      "group border rounded-lg p-4 transition-all duration-200",
                      "hover:shadow-md hover:border-border",
                      config.lightBg,
                      config.lightBorder
                    )}
                  >
                    <div className="flex items-start space-x-3">
                      {/* Icon */}
                      <div className={cn(
                        "flex h-8 w-8 items-center justify-center rounded-full",
                        config.bgColor,
                        "text-white"
                      )}>
                        {getVulnerabilityIcon(vulnerability.type)}
                      </div>

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-start justify-between">
                          <div className="flex-1">
                            <h4 className="text-sm font-medium leading-tight">
                              {vulnerability.title}
                            </h4>
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">
                              {vulnerability.description}
                            </p>
                          </div>
                          
                          <Badge 
                            variant={config.badgeVariant}
                            className="text-xs ml-2 shrink-0"
                          >
                            {config.label}
                          </Badge>
                        </div>

                        {/* Metadata */}
                        <div className="flex items-center space-x-4 mt-3 text-xs text-muted-foreground">
                          <div className="flex items-center space-x-1">
                            <Target className="h-3 w-3" />
                            <span className="font-mono">{vulnerability.target}</span>
                          </div>
                          <div className="flex items-center space-x-1">
                            <Clock className="h-3 w-3" />
                            <span>{formatTimeAgo(vulnerability.discoveredAt)}</span>
                          </div>
                          {vulnerability.assignedTo && (
                            <div className="flex items-center space-x-1">
                              <User className="h-3 w-3" />
                              <span>{vulnerability.assignedTo}</span>
                            </div>
                          )}
                        </div>

                        {/* Actions */}
                        <div className="flex items-center justify-between mt-4">
                          <div className="flex items-center space-x-2">
                            {priorityActions.map((action) => (
                              <TooltipProvider key={action.key}>
                                <Tooltip>
                                  <TooltipTrigger asChild>
                                    <Button
                                      variant={action.variant}
                                      size="sm"
                                      className="h-7 text-xs"
                                      onClick={() => handleActionClick(action.key, vulnerability)}
                                    >
                                      {action.icon}
                                      <span className="ml-1">{action.label}</span>
                                    </Button>
                                  </TooltipTrigger>
                                  <TooltipContent>
                                    <p>{action.label} vulnerability</p>
                                  </TooltipContent>
                                </Tooltip>
                              </TooltipProvider>
                            ))}
                          </div>

                          {/* More actions dropdown */}
                          <DropdownMenu>
                            <DropdownMenuTrigger asChild>
                              <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                                <MoreHorizontal className="h-3 w-3" />
                              </Button>
                            </DropdownMenuTrigger>
                            <DropdownMenuContent align="end">
                              <DropdownMenuItem 
                                onClick={() => handleActionClick("view", vulnerability)}
                              >
                                <Eye className="h-3 w-3 mr-2" />
                                View Details
                              </DropdownMenuItem>
                              <DropdownMenuItem 
                                onClick={() => handleActionClick("guide", vulnerability)}
                              >
                                <ExternalLink className="h-3 w-3 mr-2" />
                                Fix Guide
                              </DropdownMenuItem>
                              <DropdownMenuItem 
                                onClick={() => handleActionClick("dismiss", vulnerability)}
                                className="text-destructive"
                              >
                                <X className="h-3 w-3 mr-2" />
                                Dismiss
                              </DropdownMenuItem>
                            </DropdownMenuContent>
                          </DropdownMenu>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )
              })}
            </AnimatePresence>

            {/* Show more button */}
            {criticalActions.length > maxItems && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.3 }}
                className="text-center pt-2"
              >
                <Button variant="ghost" size="sm">
                  Show {criticalActions.length - maxItems} more critical issues
                </Button>
              </motion.div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

export { CriticalActions }
export type { CriticalActionsProps }
