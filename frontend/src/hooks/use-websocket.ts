/**
 * WebSocket hook for real-time dashboard updates
 * Provides connection management, message handling, and auto-reconnection
 */

import { useState, useEffect, useRef, useCallback } from 'react'

// WebSocket message types
export interface WebSocketMessage {
  type: string
  data?: any
  message?: string
  timestamp: string
}

// Connection status enum
export enum ConnectionStatus {
  DISCONNECTED = 'disconnected',
  CONNECTING = 'connecting',
  CONNECTED = 'connected',
  RECONNECTING = 'reconnecting',
  ERROR = 'error'
}

// WebSocket hook configuration
interface UseWebSocketConfig {
  url: string
  token: string | null
  autoConnect?: boolean
  reconnectInterval?: number
  maxReconnectAttempts?: number
  pingInterval?: number
}

// WebSocket hook return type
interface UseWebSocketReturn {
  connectionStatus: ConnectionStatus
  lastMessage: WebSocketMessage | null
  lastPing: Date | null
  isConnected: boolean
  connect: () => void
  disconnect: () => void
  sendMessage: (message: any) => void
  subscribe: (eventType: string, callback: (data: any) => void) => () => void
  connectionCount: number
  error: string | null
}

export function useWebSocket({
  url,
  token,
  autoConnect = true,
  reconnectInterval = 5000,
  maxReconnectAttempts = 5,
  pingInterval = 30000
}: UseWebSocketConfig): UseWebSocketReturn {
  
  // State management
  const [connectionStatus, setConnectionStatus] = useState<ConnectionStatus>(ConnectionStatus.DISCONNECTED)
  const [lastMessage, setLastMessage] = useState<WebSocketMessage | null>(null)
  const [lastPing, setLastPing] = useState<Date | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [connectionCount, setConnectionCount] = useState(0)
  
  // Refs for WebSocket and intervals
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const eventListenersRef = useRef<Map<string, Set<(data: any) => void>>>(new Map())
  
  // Computed values
  const isConnected = connectionStatus === ConnectionStatus.CONNECTED
  
  // Clear timeouts helper
  const clearTimeouts = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current)
      pingIntervalRef.current = null
    }
  }, [])
  
  // Setup ping interval
  const setupPingInterval = useCallback(() => {
    clearTimeouts()
    
    pingIntervalRef.current = setInterval(() => {
      if (wsRef.current?.readyState === WebSocket.OPEN) {
        wsRef.current.send(JSON.stringify({
          type: 'ping',
          timestamp: new Date().toISOString()
        }))
      }
    }, pingInterval)
  }, [pingInterval, clearTimeouts])
  
  // Handle incoming messages
  const handleMessage = useCallback((event: MessageEvent) => {
    try {
      const message: WebSocketMessage = JSON.parse(event.data)
      setLastMessage(message)
      setError(null)
      
      // Handle special message types
      switch (message.type) {
        case 'pong':
          setLastPing(new Date())
          break
          
        case 'connection_established':
          console.log('WebSocket connection established:', message)
          setConnectionStatus(ConnectionStatus.CONNECTED)
          reconnectAttemptsRef.current = 0
          setupPingInterval()
          break
          
        case 'error':
          console.error('WebSocket error message:', message.message)
          setError(message.message || 'Unknown WebSocket error')
          break
          
        default:
          // Trigger event listeners for this message type
          const listeners = eventListenersRef.current.get(message.type)
          if (listeners) {
            listeners.forEach(callback => {
              try {
                callback(message.data || message)
              } catch (err) {
                console.error('Error in WebSocket event listener:', err)
              }
            })
          }
          break
      }
      
    } catch (err) {
      console.error('Failed to parse WebSocket message:', err)
      setError('Failed to parse message from server')
    }
  }, [setupPingInterval])
  
  // Connect to WebSocket
  const connect = useCallback(() => {
    if (!token) {
      setError('Authentication token required for WebSocket connection')
      return
    }
    
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected')
      return
    }
    
    try {
      setConnectionStatus(ConnectionStatus.CONNECTING)
      setError(null)
      
      // Construct WebSocket URL with token
      const wsUrl = `${url}?token=${encodeURIComponent(token)}`
      
      console.log('Connecting to WebSocket:', wsUrl.replace(token, '[TOKEN]'))
      
      const ws = new WebSocket(wsUrl)
      wsRef.current = ws
      
      ws.onopen = () => {
        console.log('WebSocket connection opened')
        setConnectionCount(prev => prev + 1)
        // Connection status will be set when we receive connection_established message
      }
      
      ws.onmessage = handleMessage
      
      ws.onclose = (event) => {
        console.log('WebSocket connection closed:', event.code, event.reason)
        setConnectionStatus(ConnectionStatus.DISCONNECTED)
        clearTimeouts()
        
        // Auto-reconnect if not manually closed
        if (event.code !== 1000 && reconnectAttemptsRef.current < maxReconnectAttempts) {
          setConnectionStatus(ConnectionStatus.RECONNECTING)
          reconnectAttemptsRef.current++
          
          console.log(`Attempting to reconnect (${reconnectAttemptsRef.current}/${maxReconnectAttempts})...`)
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect()
          }, reconnectInterval)
        } else if (reconnectAttemptsRef.current >= maxReconnectAttempts) {
          setError('Maximum reconnection attempts reached')
          setConnectionStatus(ConnectionStatus.ERROR)
        }
      }
      
      ws.onerror = (event) => {
        console.error('WebSocket error:', event)
        setError('WebSocket connection error')
        setConnectionStatus(ConnectionStatus.ERROR)
      }
      
    } catch (err) {
      console.error('Failed to create WebSocket connection:', err)
      setError('Failed to create WebSocket connection')
      setConnectionStatus(ConnectionStatus.ERROR)
    }
  }, [url, token, handleMessage, reconnectInterval, maxReconnectAttempts, clearTimeouts])
  
  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    clearTimeouts()
    reconnectAttemptsRef.current = maxReconnectAttempts // Prevent auto-reconnect
    
    if (wsRef.current) {
      wsRef.current.close(1000, 'Manual disconnect')
      wsRef.current = null
    }
    
    setConnectionStatus(ConnectionStatus.DISCONNECTED)
    setLastMessage(null)
    setLastPing(null)
    setError(null)
  }, [clearTimeouts, maxReconnectAttempts])
  
  // Send message to WebSocket
  const sendMessage = useCallback((message: any) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      try {
        const messageStr = JSON.stringify({
          ...message,
          timestamp: new Date().toISOString()
        })
        wsRef.current.send(messageStr)
      } catch (err) {
        console.error('Failed to send WebSocket message:', err)
        setError('Failed to send message')
      }
    } else {
      console.warn('WebSocket not connected, cannot send message:', message)
      setError('WebSocket not connected')
    }
  }, [])
  
  // Subscribe to specific event types
  const subscribe = useCallback((eventType: string, callback: (data: any) => void) => {
    if (!eventListenersRef.current.has(eventType)) {
      eventListenersRef.current.set(eventType, new Set())
    }
    
    eventListenersRef.current.get(eventType)!.add(callback)
    
    // Return unsubscribe function
    return () => {
      const listeners = eventListenersRef.current.get(eventType)
      if (listeners) {
        listeners.delete(callback)
        if (listeners.size === 0) {
          eventListenersRef.current.delete(eventType)
        }
      }
    }
  }, [])
  
  // Auto-connect on mount if enabled
  useEffect(() => {
    if (autoConnect && token) {
      connect()
    }
    
    // Cleanup on unmount
    return () => {
      disconnect()
    }
  }, [autoConnect, token, connect, disconnect])
  
  // Reconnect when token changes
  useEffect(() => {
    if (token && isConnected) {
      // Disconnect and reconnect with new token
      disconnect()
      setTimeout(() => connect(), 100)
    }
  }, [token])
  
  return {
    connectionStatus,
    lastMessage,
    lastPing,
    isConnected,
    connect,
    disconnect,
    sendMessage,
    subscribe,
    connectionCount,
    error
  }
}

// Helper hook for dashboard-specific WebSocket functionality
export function useWebSocketDashboard() {
  const token = localStorage.getItem('access_token')
  
  const websocket = useWebSocket({
    url: 'ws://localhost:8000/ws/dashboard',
    token,
    autoConnect: false, // Disable auto-connect to reduce connection attempts
    reconnectInterval: 10000, // Increase reconnect interval to 10 seconds
    maxReconnectAttempts: 3, // Reduce max attempts
    pingInterval: 60000 // Increase ping interval to 1 minute
  })
  
  // Dashboard-specific methods
  const requestDashboardUpdate = useCallback(() => {
    websocket.sendMessage({
      type: 'request_dashboard_update'
    })
  }, [websocket])
  
  const subscribeToScan = useCallback((scanId: number) => {
    websocket.sendMessage({
      type: 'subscribe_to_scan',
      scan_id: scanId
    })
  }, [websocket])
  
  return {
    ...websocket,
    requestDashboardUpdate,
    subscribeToScan
  }
}
