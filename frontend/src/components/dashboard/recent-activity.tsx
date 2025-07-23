import * as React from "react"
import { motion, AnimatePresence } from "framer-motion"
import { RefreshCw, Filter, MoreHorizontal, Eye, ExternalLink } from "lucide-react"

import { cn } from "@/lib/utils"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Skeleton } from "@/components/ui/skeleton"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu"

import { ActivityTimeline } from "./activity-timeline"
import { 
  ActivityItem, 
  ActivityContent, 
  ActivityTitle, 
  ActivityDescription, 
  ActivityTime, 
  ActivityActions 
} from "./activity-item"
import { ActivityIcon } from "./activity-icon"
import { useActivityData, formatRelativeTime, type ActivityData } from "@/hooks/use-activity-data"

interface RecentActivityProps {
  className?: string
  maxItems?: number
  showFilters?: boolean
  autoRefresh?: boolean
}

function RecentActivity({ 
  className, 
  maxItems = 10,
  showFilters = true,
  autoRefresh = true
}: RecentActivityProps) {
  const { groupedActivities, loading, error, refreshActivities } = useActivityData()
  const [filter, setFilter] = React.useState<"all" | "scans" | "critical">("all")
  const [isRefreshing, setIsRefreshing] = React.useState(false)

  const handleRefresh = async () => {
    setIsRefreshing(true)
    await refreshActivities()
    setTimeout(() => setIsRefreshing(false), 500)
  }

  const getStatusVariant = (status: ActivityData["status"]) => {
    switch (status) {
      case "success": return "success"
      case "warning": return "warning" 
      case "error": return "error"
      case "info": return "info"
      default: return "default"
    }
  }

  const getActivityActions = (activity: ActivityData) => {
    const actions = []
    
    if (activity.target) {
      actions.push(
        <TooltipProvider key="view">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                <Eye className="h-3 w-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>View details</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )
    }

    if (activity.type.includes("report")) {
      actions.push(
        <TooltipProvider key="external">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0">
                <ExternalLink className="h-3 w-3" />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Open report</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      )
    }

    return actions
  }

  const filteredGroups = React.useMemo(() => {
    if (filter === "all") return groupedActivities
    
    return groupedActivities.map(group => ({
      ...group,
      activities: group.activities.filter(activity => {
        if (filter === "scans") return activity.type.includes("scan")
        if (filter === "critical") return activity.status === "error"
        return true
      })
    })).filter(group => group.activities.length > 0)
  }, [groupedActivities, filter])

  const totalActivities = React.useMemo(() => {
    return filteredGroups.reduce((total, group) => total + group.activities.length, 0)
  }, [filteredGroups])

  if (error) {
    return (
      <div className="flex items-center justify-center h-32 text-muted-foreground">
        <div className="text-center">
          <p className="text-sm">Failed to load activities</p>
          <Button variant="ghost" size="sm" onClick={handleRefresh} className="mt-2">
            <RefreshCw className="h-4 w-4 mr-2" />
            Retry
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className={cn("space-y-4", className)}>
      {/* Header with filters and refresh */}
      {showFilters && (
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Button
              variant={filter === "all" ? "default" : "ghost"}
              size="sm"
              onClick={() => setFilter("all")}
            >
              All
            </Button>
            <Button
              variant={filter === "scans" ? "default" : "ghost"}
              size="sm"
              onClick={() => setFilter("scans")}
            >
              Scans
            </Button>
            <Button
              variant={filter === "critical" ? "default" : "ghost"}
              size="sm"
              onClick={() => setFilter("critical")}
            >
              Critical
            </Button>
          </div>
          
          <div className="flex items-center space-x-2">
            <span className="text-xs text-muted-foreground">
              {totalActivities} activities
            </span>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              disabled={isRefreshing}
              className="h-6 w-6 p-0"
            >
              <RefreshCw className={cn("h-3 w-3", isRefreshing && "animate-spin")} />
            </Button>
          </div>
        </div>
      )}

      {/* Activity Timeline */}
      <ScrollArea className="h-[400px] pr-4">
        {loading ? (
          <div className="space-y-4">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="flex items-start space-x-3">
                <Skeleton className="h-8 w-8 rounded-full" />
                <div className="space-y-2 flex-1">
                  <Skeleton className="h-4 w-3/4" />
                  <Skeleton className="h-3 w-1/2" />
                </div>
              </div>
            ))}
          </div>
        ) : (
          <ActivityTimeline variant="default" size="md">
            <AnimatePresence mode="popLayout">
              {filteredGroups.slice(0, Math.ceil(maxItems / 3)).map((group) => (
                <motion.div
                  key={group.date}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -20 }}
                  transition={{ duration: 0.2 }}
                  className="space-y-4"
                >
                  {/* Date Header */}
                  <div className="flex items-center space-x-2 -ml-6">
                    <div className="h-px bg-border flex-1" />
                    <Badge variant="secondary" className="text-xs">
                      {group.label}
                    </Badge>
                    <div className="h-px bg-border flex-1" />
                  </div>

                  {/* Activities for this date */}
                  {group.activities.slice(0, maxItems).map((activity, index) => (
                    <motion.div
                      key={activity.id}
                      initial={{ opacity: 0, x: -20 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ duration: 0.2, delay: index * 0.05 }}
                    >
                      <ActivityItem
                        variant="interactive"
                        status={getStatusVariant(activity.status)}
                      >
                        <ActivityIcon
                          activityType={activity.type}
                          variant="default"
                        />
                        
                        <ActivityContent>
                          <ActivityTitle>{activity.title}</ActivityTitle>
                          {activity.description && (
                            <ActivityDescription>
                              {activity.description}
                              {activity.target && (
                                <span className="ml-1 font-mono text-xs">
                                  {activity.target}
                                </span>
                              )}
                            </ActivityDescription>
                          )}
                          <ActivityTime>
                            {formatRelativeTime(activity.timestamp)}
                            {activity.user && (
                              <span className="ml-2">by {activity.user}</span>
                            )}
                          </ActivityTime>
                        </ActivityContent>

                        <ActivityActions>
                          {getActivityActions(activity)}
                        </ActivityActions>
                      </ActivityItem>
                    </motion.div>
                  ))}
                </motion.div>
              ))}
            </AnimatePresence>
          </ActivityTimeline>
        )}
      </ScrollArea>

      {/* Show more button */}
      {!loading && totalActivities > maxItems && (
        <div className="flex justify-center pt-2">
          <Button variant="ghost" size="sm">
            Show {Math.min(15, totalActivities - maxItems)} more activities
          </Button>
        </div>
      )}
    </div>
  )
}

export { RecentActivity }
export type { RecentActivityProps }
