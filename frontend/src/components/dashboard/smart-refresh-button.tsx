/**
 * Smart Refresh Button with WebSocket awareness
 * Shows different states based on WebSocket connection and provides manual refresh capability
 */

import React from 'react'
import { RefreshCw, Wifi, WifiOff, AlertCircle } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { Badge } from '@/components/ui/badge'
import { ConnectionStatus } from '@/hooks/use-websocket'
import { formatRelativeTime } from '@/hooks/use-activity-data'

interface SmartRefreshButtonProps {
  onRefresh: () => void
  isLoading?: boolean
  connectionStatus: ConnectionStatus
  lastUpdate?: Date | null
  lastPing?: Date | null
  className?: string
  showLabel?: boolean
  size?: 'sm' | 'default' | 'lg'
}

export function SmartRefreshButton({
  onRefresh,
  isLoading = false,
  connectionStatus,
  lastUpdate,
  lastPing,
  className = '',
  showLabel = true,
  size = 'default'
}: SmartRefreshButtonProps) {
  
  // Determine button state based on connection status
  const getButtonState = () => {
    switch (connectionStatus) {
      case ConnectionStatus.CONNECTED:
        return {
          variant: 'outline' as const,
          icon: Wifi,
          label: 'Live',
          tooltip: 'Real-time updates active. Click to force refresh.',
          className: 'border-green-200 text-green-700 hover:bg-green-50',
          iconClassName: 'text-green-600 animate-pulse'
        }
      
      case ConnectionStatus.CONNECTING:
      case ConnectionStatus.RECONNECTING:
        return {
          variant: 'outline' as const,
          icon: RefreshCw,
          label: 'Connecting',
          tooltip: 'Connecting to real-time updates...',
          className: 'border-yellow-200 text-yellow-700 hover:bg-yellow-50',
          iconClassName: 'text-yellow-600 animate-spin'
        }
      
      case ConnectionStatus.ERROR:
        return {
          variant: 'outline' as const,
          icon: AlertCircle,
          label: 'Error',
          tooltip: 'Connection error. Click to refresh manually.',
          className: 'border-red-200 text-red-700 hover:bg-red-50',
          iconClassName: 'text-red-600'
        }
      
      case ConnectionStatus.DISCONNECTED:
      default:
        return {
          variant: 'default' as const,
          icon: RefreshCw,
          label: 'Refresh',
          tooltip: 'Manual refresh mode. Click to update data.',
          className: '',
          iconClassName: isLoading ? 'animate-spin' : ''
        }
    }
  }
  
  const buttonState = getButtonState()
  const IconComponent = buttonState.icon
  
  // Format last update time
  const getLastUpdateText = () => {
    if (!lastUpdate) return null
    
    const timeAgo = formatRelativeTime(lastUpdate)
    return `Updated ${timeAgo}`
  }
  
  // Format connection info
  const getConnectionInfo = () => {
    const parts = []
    
    if (connectionStatus === ConnectionStatus.CONNECTED && lastPing) {
      const pingAgo = formatRelativeTime(lastPing)
      parts.push(`Last ping: ${pingAgo}`)
    }
    
    if (lastUpdate) {
      parts.push(getLastUpdateText())
    }
    
    return parts.join(' • ')
  }
  
  return (
    <TooltipProvider>
      <div className="flex items-center gap-2">
        {/* Main Refresh Button */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              onClick={onRefresh}
              disabled={isLoading}
              variant={buttonState.variant}
              size={size}
              className={`${buttonState.className} ${className}`}
            >
              <IconComponent 
                className={`w-4 h-4 ${buttonState.iconClassName} ${showLabel ? 'mr-2' : ''}`} 
              />
              {showLabel && buttonState.label}
            </Button>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-center">
              <div className="font-medium">{buttonState.tooltip}</div>
              {getConnectionInfo() && (
                <div className="text-xs text-muted-foreground mt-1">
                  {getConnectionInfo()}
                </div>
              )}
            </div>
          </TooltipContent>
        </Tooltip>
      </div>
    </TooltipProvider>
  )
}

// Connection Status Badge Component
interface ConnectionStatusBadgeProps {
  status: ConnectionStatus
  lastPing?: Date | null
}

function ConnectionStatusBadge({ status, lastPing }: ConnectionStatusBadgeProps) {
  const getBadgeProps = () => {
    switch (status) {
      case ConnectionStatus.CONNECTED:
        return {
          variant: 'default' as const,
          className: 'bg-green-100 text-green-800 border-green-200',
          text: 'Live',
          icon: <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
        }
      
      case ConnectionStatus.CONNECTING:
        return {
          variant: 'secondary' as const,
          className: 'bg-yellow-100 text-yellow-800 border-yellow-200',
          text: 'Connecting',
          icon: <div className="w-2 h-2 bg-yellow-500 rounded-full animate-pulse" />
        }
      
      case ConnectionStatus.RECONNECTING:
        return {
          variant: 'secondary' as const,
          className: 'bg-orange-100 text-orange-800 border-orange-200',
          text: 'Reconnecting',
          icon: <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse" />
        }
      
      case ConnectionStatus.ERROR:
        return {
          variant: 'destructive' as const,
          className: 'bg-red-100 text-red-800 border-red-200',
          text: 'Error',
          icon: <div className="w-2 h-2 bg-red-500 rounded-full" />
        }
      
      default:
        return null
    }
  }
  
  const badgeProps = getBadgeProps()
  if (!badgeProps) return null
  
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge 
            variant={badgeProps.variant}
            className={`${badgeProps.className} text-xs px-2 py-1 flex items-center gap-1.5`}
          >
            {badgeProps.icon}
            {badgeProps.text}
          </Badge>
        </TooltipTrigger>
        <TooltipContent>
          <div className="text-center">
            <div className="font-medium">Connection Status: {status}</div>
            {lastPing && status === ConnectionStatus.CONNECTED && (
              <div className="text-xs text-muted-foreground mt-1">
                Last ping: {formatRelativeTime(lastPing)}
              </div>
            )}
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

// Compact version for smaller spaces
export function CompactSmartRefreshButton({
  onRefresh,
  isLoading = false,
  connectionStatus,
  lastPing,
  className = ''
}: Omit<SmartRefreshButtonProps, 'showLabel' | 'size' | 'lastUpdate'>) {
  return (
    <SmartRefreshButton
      onRefresh={onRefresh}
      isLoading={isLoading}
      connectionStatus={connectionStatus}
      lastPing={lastPing}
      className={className}
      showLabel={false}
      size="sm"
    />
  )
}

// Hook for managing refresh state with WebSocket
export function useSmartRefresh(
  refreshFunction: () => Promise<void> | void,
  connectionStatus: ConnectionStatus
) {
  const [isRefreshing, setIsRefreshing] = React.useState(false)
  const [lastRefresh, setLastRefresh] = React.useState<Date | null>(null)
  
  const handleRefresh = React.useCallback(async () => {
    if (isRefreshing) return
    
    try {
      setIsRefreshing(true)
      await refreshFunction()
      setLastRefresh(new Date())
    } catch (error) {
      console.error('Refresh failed:', error)
    } finally {
      setIsRefreshing(false)
    }
  }, [refreshFunction, isRefreshing])
  
  // Auto-refresh when connection is restored
  React.useEffect(() => {
    if (connectionStatus === ConnectionStatus.CONNECTED && lastRefresh) {
      // Optional: Auto-refresh when connection is restored
      // handleRefresh()
    }
  }, [connectionStatus])
  
  return {
    isRefreshing,
    lastRefresh,
    handleRefresh
  }
}
