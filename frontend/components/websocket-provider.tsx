"use client"

import React, { createContext, useContext, useState, useEffect, useRef, useCallback, useMemo } from "react"
import useSWR, { useSWRConfig } from "swr"
import { toast } from "sonner"
import { WsMessage, WsMessageType, ConnectionState } from "@/hooks/use-websocket-types"
import { getNotificationPreferences, type NotificationPreferences } from "@/lib/api"

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

const CRITICAL_EVENTS = new Set(["mitigation.created", "mitigation.escalated"])

const WS_TO_ALERT_EVENT: Record<string, string> = {
  MitigationCreated: "mitigation.created",
  MitigationUpdated: "mitigation.escalated",
  MitigationWithdrawn: "mitigation.withdrawn",
  MitigationExpired: "mitigation.expired",
  ResyncRequired: "config.reloaded",
  EventIngested: "mitigation.created",
}

export function shouldShowToast(wsType: string, prefs: NotificationPreferences | undefined): boolean {
  if (!prefs) return true
  const alertEvent = WS_TO_ALERT_EVENT[wsType]
  if (!alertEvent) return true
  if (prefs.muted_events.includes(alertEvent)) return false
  if (prefs.quiet_hours_start !== null && prefs.quiet_hours_end !== null) {
    const now = new Date().getUTCHours()
    const start = prefs.quiet_hours_start
    const end = prefs.quiet_hours_end
    const inQuiet = start <= end ? (now >= start && now < end) : (now >= start || now < end)
    if (inQuiet && !CRITICAL_EVENTS.has(alertEvent)) return false
  }
  return true
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
  const { data: notifPrefs } = useSWR<NotificationPreferences>(
    "notification-preferences",
    getNotificationPreferences,
    { refreshInterval: 0, revalidateOnFocus: false }
  )
  const notifPrefsRef = useRef(notifPrefs)
  useEffect(() => { notifPrefsRef.current = notifPrefs }, [notifPrefs])

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

          const prefs = notifPrefsRef.current
          const showToast = shouldShowToast(message.type, prefs)

          // Handle ResyncRequired by invalidating SWR caches
          if (message.type === "ResyncRequired") {
            mutate((key) => {
              const k = typeof key === "string"
                ? key
                : Array.isArray(key) && typeof key[0] === "string"
                  ? key[0] as string
                  : null
              return k !== null && (
                k.startsWith("mitigations") ||
                k.startsWith("events") ||
                k === "stats" ||
                k === "dashboard" ||
                k.startsWith("signal-groups")
              )
            })
            if (showToast) toast.info("Configuration reloaded from disk")
          }

          // Invalidate relevant caches based on message type
          // SWR keys match hook keys: "mitigations", "stats", "events"
          if (
            message.type === "MitigationCreated" ||
            message.type === "MitigationUpdated" ||
            message.type === "MitigationExpired" ||
            message.type === "MitigationWithdrawn"
          ) {
            // Toast notifications (filtered by preferences)
            if (showToast) {
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

  useEffect(() => {
    const handleVisibility = () => {
      if (!document.hidden && wsRef.current?.readyState !== WebSocket.OPEN) {
        reconnectAttemptsRef.current = 0
        connect()
      }
    }
    document.addEventListener("visibilitychange", handleVisibility)
    return () => document.removeEventListener("visibilitychange", handleVisibility)
  }, [connect])

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
