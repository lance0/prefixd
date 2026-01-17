"use client"

import { useState, useEffect, useRef, useCallback, useMemo } from "react"
import { useSWRConfig } from "swr"

const WS_BASE = process.env.NEXT_PUBLIC_PREFIXD_WS || "ws://localhost:8080"

export type WsMessageType =
  | "MitigationCreated"
  | "MitigationUpdated"
  | "MitigationExpired"
  | "MitigationWithdrawn"
  | "EventIngested"
  | "ResyncRequired"

export interface WsMessage {
  type: WsMessageType
  // MitigationCreated/Updated
  mitigation?: {
    mitigation_id: string
    status: string
    customer_id: string | null
    victim_ip: string
    vector: string
    action_type: string
    rate_bps: number | null
    created_at: string
    expires_at: string
    scope_hash: string
  }
  // MitigationExpired/Withdrawn
  mitigation_id?: string
  // EventIngested
  event?: {
    event_id: string
    external_event_id: string | null
    victim_ip: string
    vector: string
    confidence: number | null
    source: string
    ingested_at: string
  }
  // ResyncRequired
  reason?: string
}

export type ConnectionState = "connecting" | "connected" | "disconnected" | "error"

interface UseWebSocketOptions {
  onMessage?: (message: WsMessage) => void
  reconnectInterval?: number
  maxReconnectAttempts?: number
}

export function useWebSocket(options: UseWebSocketOptions = {}) {
  const { 
    onMessage, 
    reconnectInterval = 3000, 
    maxReconnectAttempts = 10 
  } = options

  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected")
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const { mutate } = useSWRConfig()
  
  // Store callback in ref to avoid recreating WebSocket on callback change (advanced-event-handler-refs)
  const onMessageRef = useRef(onMessage)
  useEffect(() => {
    onMessageRef.current = onMessage
  }, [onMessage])

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    setConnectionState("connecting")

    try {
      const ws = new WebSocket(`${WS_BASE}/v1/ws/feed`)
      wsRef.current = ws

      ws.onopen = () => {
        setConnectionState("connected")
        reconnectAttemptsRef.current = 0
      }

      ws.onmessage = (event) => {
        try {
          const message: WsMessage = JSON.parse(event.data)
          setLastMessage(message)
          onMessageRef.current?.(message)

          // Handle ResyncRequired by invalidating SWR caches
          if (message.type === "ResyncRequired") {
            mutate(() => true) // Revalidate all keys
          }

          // Invalidate relevant caches based on message type
          if (message.type === "MitigationCreated" || 
              message.type === "MitigationUpdated" ||
              message.type === "MitigationExpired" ||
              message.type === "MitigationWithdrawn") {
            mutate("/v1/mitigations")
            mutate("/v1/stats")
          }

          if (message.type === "EventIngested") {
            mutate("/v1/events")
            mutate("/v1/stats")
          }
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e)
        }
      }

      ws.onclose = () => {
        setConnectionState("disconnected")
        wsRef.current = null

        // Attempt reconnection
        if (reconnectAttemptsRef.current < maxReconnectAttempts) {
          reconnectAttemptsRef.current++
          const delay = reconnectInterval * Math.min(reconnectAttemptsRef.current, 5)
          reconnectTimeoutRef.current = setTimeout(connect, delay)
        }
      }

      ws.onerror = () => {
        setConnectionState("error")
      }
    } catch (e) {
      console.error("Failed to create WebSocket:", e)
      setConnectionState("error")
    }
  }, [reconnectInterval, maxReconnectAttempts, mutate])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }
    reconnectAttemptsRef.current = maxReconnectAttempts // Prevent auto-reconnect
    wsRef.current?.close()
    wsRef.current = null
    setConnectionState("disconnected")
  }, [maxReconnectAttempts])

  // Auto-connect on mount
  useEffect(() => {
    connect()
    return () => {
      disconnect()
    }
  }, [connect, disconnect])

  // Memoize return value (rerender-derived-state)
  return useMemo(
    () => ({
      connectionState,
      lastMessage,
      connect,
      disconnect,
      isConnected: connectionState === "connected",
    }),
    [connectionState, lastMessage, connect, disconnect]
  )
}
