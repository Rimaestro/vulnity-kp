/**
 * Connection Status Indicator Component
 * Shows real-time WebSocket connection status with detailed information
 */

import React from 'react'
import { Wifi, WifiOff, AlertCircle, RefreshCw, Activity, Clock } from 'lucide-react'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { ConnectionStatus } from '@/hooks/use-websocket'
import { formatRelativeTime } from '@/hooks/use-activity-data'

interface ConnectionStatusProps {
  status: ConnectionStatus
  lastPing?: Date | null
  connectionCount?: number
  error?: string | null
  onReconnect?: () => void
  onDisconnect?: () => void
  className?: string
  variant?: 'full' | 'compact' | 'minimal'
}

export function ConnectionStatusIndicator({
  status,
  lastPing,
  connectionCount = 0,
  error,
  onReconnect,
  onDisconnect,
  className = '',
  variant = 'full'
}: ConnectionStatusProps) {
  
  // Get status configuration
  const getStatusConfig = () => {
    switch (status) {
      case ConnectionStatus.CONNECTED:
        return {
          icon: Wifi,
          label: 'Connected',
          description: 'Real-time updates active',
          color: 'green',
          bgColor: 'bg-green-50',
          borderColor: 'border-green-200',
          textColor: 'text-green-800',
          iconColor: 'text-green-600',
          badgeVariant: 'default' as const,
          badgeClassName: 'bg-green-100 text-green-800',
          pulse: true
        }
      
      case ConnectionStatus.CONNECTING:
        return {
          icon: RefreshCw,
          label: 'Connecting',
          description: 'Establishing connection...',
          color: 'yellow',
          bgColor: 'bg-yellow-50',
          borderColor: 'border-yellow-200',
          textColor: 'text-yellow-800',
          iconColor: 'text-yellow-600',
          badgeVariant: 'secondary' as const,
          badgeClassName: 'bg-yellow-100 text-yellow-800',
          pulse: false,
          spin: true
        }
      
      case ConnectionStatus.RECONNECTING:
        return {
          icon: RefreshCw,
          label: 'Reconnecting',
          description: 'Attempting to reconnect...',
          color: 'orange',
          bgColor: 'bg-orange-50',
          borderColor: 'border-orange-200',
          textColor: 'text-orange-800',
          iconColor: 'text-orange-600',
          badgeVariant: 'secondary' as const,
          badgeClassName: 'bg-orange-100 text-orange-800',
          pulse: true,
          spin: true
        }
      
      case ConnectionStatus.ERROR:
        return {
          icon: AlertCircle,
          label: 'Error',
          description: error || 'Connection failed',
          color: 'red',
          bgColor: 'bg-red-50',
          borderColor: 'border-red-200',
          textColor: 'text-red-800',
          iconColor: 'text-red-600',
          badgeVariant: 'destructive' as const,
          badgeClassName: 'bg-red-100 text-red-800',
          pulse: false
        }
      
      case ConnectionStatus.DISCONNECTED:
      default:
        return {
          icon: WifiOff,
          label: 'Disconnected',
          description: 'Manual refresh mode',
          color: 'gray',
          bgColor: 'bg-gray-50',
          borderColor: 'border-gray-200',
          textColor: 'text-gray-800',
          iconColor: 'text-gray-600',
          badgeVariant: 'outline' as const,
          badgeClassName: 'bg-gray-100 text-gray-800',
          pulse: false
        }
    }
  }
  
  const config = getStatusConfig()
  const IconComponent = config.icon
  
  // Render minimal variant
  if (variant === 'minimal') {
    return (
      <TooltipProvider>
        <Tooltip>
          <TooltipTrigger asChild>
            <div className={`flex items-center gap-2 ${className}`}>
              <div className={`w-2 h-2 rounded-full bg-${config.color}-500 ${config.pulse ? 'animate-pulse' : ''}`} />
              <span className={`text-xs ${config.textColor}`}>
                {config.label}
              </span>
            </div>
          </TooltipTrigger>
          <TooltipContent>
            <div className="text-center">
              <div className="font-medium">{config.description}</div>
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
  
  // Render compact variant
  if (variant === 'compact') {
    return (
      <Badge 
        variant={config.badgeVariant}
        className={`${config.badgeClassName} flex items-center gap-1.5 ${className}`}
      >
        <IconComponent 
          className={`w-3 h-3 ${config.iconColor} ${config.spin ? 'animate-spin' : ''} ${config.pulse ? 'animate-pulse' : ''}`} 
        />
        {config.label}
      </Badge>
    )
  }
  
  // Render full variant
  return (
    <Card className={`${config.bgColor} ${config.borderColor} ${className}`}>
      <CardContent className="p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-full ${config.bgColor}`}>
              <IconComponent 
                className={`w-4 h-4 ${config.iconColor} ${config.spin ? 'animate-spin' : ''} ${config.pulse ? 'animate-pulse' : ''}`} 
              />
            </div>
            
            <div>
              <div className={`font-medium ${config.textColor}`}>
                {config.label}
              </div>
              <div className={`text-sm ${config.textColor} opacity-75`}>
                {config.description}
              </div>
            </div>
          </div>
          
          <div className="flex items-center gap-2">
            {/* Connection Info */}
            {status === ConnectionStatus.CONNECTED && (
              <div className="text-right">
                {lastPing && (
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Activity className="w-3 h-3" />
                    {formatRelativeTime(lastPing)}
                  </div>
                )}
                {connectionCount > 0 && (
                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                    <Clock className="w-3 h-3" />
                    Session #{connectionCount}
                  </div>
                )}
              </div>
            )}
            
            {/* Action Buttons */}
            <div className="flex gap-1">
              {status === ConnectionStatus.DISCONNECTED && onReconnect && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={onReconnect}
                  className="h-8 px-2"
                >
                  <Wifi className="w-3 h-3 mr-1" />
                  Connect
                </Button>
              )}
              
              {status === ConnectionStatus.ERROR && onReconnect && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={onReconnect}
                  className="h-8 px-2"
                >
                  <RefreshCw className="w-3 h-3 mr-1" />
                  Retry
                </Button>
              )}
              
              {status === ConnectionStatus.CONNECTED && onDisconnect && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={onDisconnect}
                  className="h-8 px-2"
                >
                  <WifiOff className="w-3 h-3 mr-1" />
                  Disconnect
                </Button>
              )}
            </div>
          </div>
        </div>
        
        {/* Error Details */}
        {status === ConnectionStatus.ERROR && error && (
          <div className="mt-3 p-2 bg-red-100 border border-red-200 rounded text-sm text-red-700">
            <strong>Error:</strong> {error}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// Header Connection Status - for use in dashboard header
export function HeaderConnectionStatus({
  status,
  lastPing,
  onReconnect,
  className = ''
}: Pick<ConnectionStatusProps, 'status' | 'lastPing' | 'onReconnect' | 'className'>) {
  return (
    <ConnectionStatusIndicator
      status={status}
      lastPing={lastPing}
      onReconnect={onReconnect}
      className={className}
      variant="compact"
    />
  )
}

// Sidebar Connection Status - for use in sidebar
export function SidebarConnectionStatus({
  status,
  lastPing,
  connectionCount,
  error,
  onReconnect,
  onDisconnect,
  className = ''
}: ConnectionStatusProps) {
  return (
    <ConnectionStatusIndicator
      status={status}
      lastPing={lastPing}
      connectionCount={connectionCount}
      error={error}
      onReconnect={onReconnect}
      onDisconnect={onDisconnect}
      className={className}
      variant="full"
    />
  )
}

// Status Dot - minimal indicator for tight spaces
export function ConnectionStatusDot({
  status,
  className = ''
}: Pick<ConnectionStatusProps, 'status' | 'className'>) {
  const getColor = () => {
    switch (status) {
      case ConnectionStatus.CONNECTED:
        return 'bg-green-500'
      case ConnectionStatus.CONNECTING:
      case ConnectionStatus.RECONNECTING:
        return 'bg-yellow-500'
      case ConnectionStatus.ERROR:
        return 'bg-red-500'
      case ConnectionStatus.DISCONNECTED:
      default:
        return 'bg-gray-400'
    }
  }
  
  const shouldPulse = status === ConnectionStatus.CONNECTED || 
                     status === ConnectionStatus.CONNECTING || 
                     status === ConnectionStatus.RECONNECTING
  
  return (
    <div 
      className={`w-2 h-2 rounded-full ${getColor()} ${shouldPulse ? 'animate-pulse' : ''} ${className}`}
      title={status}
    />
  )
}
