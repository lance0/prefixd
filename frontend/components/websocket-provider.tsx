"use client"

import React, { createContext, useContext, useState, useEffect, useRef, useCallback, useMemo } from "react"
import { useSWRConfig } from "swr"
import { toast } from "sonner"
import { WsMessage, WsMessageType, ConnectionState } from "@/hooks/use-websocket-types"

function getWsBase(): string {
  if (typeof window === "undefined") return "ws://127.0.0.1"
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:"
  return `${proto}//${window.location.host}`
}

interface WebSocketContextValue {
  connectionState: ConnectionState
  lastMessage: WsMessage | null
  connect: () => void
  disconnect: () => void
  isConnected: boolean
}

const WebSocketContext = createContext<WebSocketContextValue | null>(null)

export function WebSocketProvider({ children }: { children: React.ReactNode }) {
  const reconnectInterval = 3000
  const maxReconnectAttempts = 10

  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected")
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const { mutate } = useSWRConfig()

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      return
    }

    setConnectionState("connecting")

    try {
      const ws = new WebSocket(`${getWsBase()}/v1/ws/feed`)
      wsRef.current = ws

      ws.onopen = () => {
        setConnectionState("connected")
        reconnectAttemptsRef.current = 0
      }

      ws.onmessage = (event) => {
        try {
          const message: WsMessage = JSON.parse(event.data)
          setLastMessage(message)

          // Handle ResyncRequired by invalidating SWR caches
          if (message.type === "ResyncRequired") {
            mutate(() => true) // Revalidate all keys
            toast.info("Configuration reloaded from disk")
          }

          // Invalidate relevant caches based on message type
          // SWR keys match hook keys: "mitigations", "stats", "events"
          if (
            message.type === "MitigationCreated" ||
            message.type === "MitigationUpdated" ||
            message.type === "MitigationExpired" ||
            message.type === "MitigationWithdrawn"
          ) {
            // Toast notifications
            if (message.type === "MitigationCreated" && message.mitigation) {
              toast.error(`Mitigation Created: ${message.mitigation.victim_ip}`, {
                description: `${message.mitigation.vector} • Action: ${message.mitigation.action_type}`
              })
            } else if (message.type === "MitigationUpdated" && message.mitigation) {
              toast.warning(`Mitigation Escalated: ${message.mitigation.victim_ip}`, {
                description: `${message.mitigation.vector} • New Action: ${message.mitigation.action_type}`
              })
            } else if (message.type === "MitigationWithdrawn" && message.mitigation_id) {
              toast.success(`Mitigation Withdrawn`, {
                description: `ID: ${message.mitigation_id.split("-")[0]}...`
              })
            } else if (message.type === "MitigationExpired" && message.mitigation_id) {
              toast.info(`Mitigation Expired`, {
                description: `ID: ${message.mitigation_id.split("-")[0]}...`
              })
            }

            // Invalidate all mitigation-related keys (including those with params)
            mutate((key) => typeof key === "string" && key.startsWith("mitigations") || Array.isArray(key) && key[0] === "mitigations")
            mutate("stats")
          }

          if (message.type === "EventIngested") {
            mutate((key) => typeof key === "string" && key.startsWith("events") || Array.isArray(key) && key[0] === "events")
            mutate("stats")
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
  }, [maxReconnectAttempts, mutate])

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

  const value = useMemo(
    () => ({
      connectionState,
      lastMessage,
      connect,
      disconnect,
      isConnected: connectionState === "connected",
    }),
    [connectionState, lastMessage, connect, disconnect]
  )

  return <WebSocketContext.Provider value={value}>{children}</WebSocketContext.Provider>
}

export function useWebSocketContext() {
  const context = useContext(WebSocketContext)
  if (!context) {
    throw new Error("useWebSocketContext must be used within a WebSocketProvider")
  }
  return context
}
