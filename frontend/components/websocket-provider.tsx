"use client"

import React, { createContext, useContext, useState, useEffect, useRef, useCallback, useMemo } from "react"
import useSWR, { useSWRConfig, type Arguments } from "swr"
import { toast } from "sonner"
import type { WsMessage, ConnectionState } from "@/hooks/use-websocket-types"
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

const CRITICAL_EVENTS = new Set(["mitigation.created"])

const WS_TO_ALERT_EVENT = new Map([
  ["mitigation_created", "mitigation.created"],
  // A TTL extension from a repeat detector event; no code path escalates.
  ["mitigation_updated", "mitigation.created"],
  ["mitigation_withdrawn", "mitigation.withdrawn"],
  ["mitigation_expired", "mitigation.expired"],
  ["resync_required", "config.reloaded"],
  ["event_ingested", "mitigation.created"],
])

/** The resource an SWR key names: a string key itself, or the first element of a tuple key. */
function swrResource(key: Arguments): string | null {
  const first: Arguments = Array.isArray(key) ? key[0] : key

  return first && !(first instanceof Object) ? String(first) : null
}

export function shouldShowToast(wsType: string, prefs: NotificationPreferences | undefined): boolean {
  if (!prefs) return true
  const alertEvent = WS_TO_ALERT_EVENT.get(wsType)

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
  const connectionTimeout = 10000

  const [connectionState, setConnectionState] = useState<ConnectionState>("disconnected")
  const [lastMessage, setLastMessage] = useState<WsMessage | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectAttemptsRef = useRef(0)
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const connectionTimeoutRef = useRef<NodeJS.Timeout | null>(null)
  const { mutate } = useSWRConfig()

  const { data: notifPrefs } = useSWR<NotificationPreferences>(
    "notification-preferences",
    getNotificationPreferences,
    { refreshInterval: 0, revalidateOnFocus: false }
  )

  const notifPrefsRef = useRef(notifPrefs)
  useEffect(() => { notifPrefsRef.current = notifPrefs }, [notifPrefs])

  const connect = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState <= WebSocket.OPEN) {
      return
    }

    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    setConnectionState(reconnectAttemptsRef.current === 0 ? "connecting" : "polling")

    const scheduleReconnect = () => {
      if (reconnectAttemptsRef.current < maxReconnectAttempts) {
        reconnectAttemptsRef.current++
        const delay = reconnectInterval * Math.min(reconnectAttemptsRef.current, 5)
        const jitter = Math.random() * reconnectInterval
        reconnectTimeoutRef.current = setTimeout(connect, delay + jitter)
      }
    }

    try {
      const ws = new WebSocket(`${getWsBase()}/v1/ws/feed`)
      wsRef.current = ws

      const usePolling = () => {
        if (wsRef.current !== ws) return
        wsRef.current = null

        if (connectionTimeoutRef.current) {
          clearTimeout(connectionTimeoutRef.current)
          connectionTimeoutRef.current = null
        }

        // Retire this attempt before closing: late events must not replace a newer socket.
        ws.onopen = null
        ws.onmessage = null
        ws.onclose = null
        ws.onerror = null
        ws.close()
        setConnectionState("polling")
        scheduleReconnect()
      }

      // An origin without an upgrade route can also leave the handshake pending.
      connectionTimeoutRef.current = setTimeout(usePolling, connectionTimeout)

      ws.onopen = () => {
        if (wsRef.current !== ws) return

        if (connectionTimeoutRef.current) {
          clearTimeout(connectionTimeoutRef.current)
          connectionTimeoutRef.current = null
        }

        setConnectionState("connected")
        reconnectAttemptsRef.current = 0
      }

      ws.onmessage = (event) => {
        if (wsRef.current !== ws) return

        try {
          const message: WsMessage = JSON.parse(event.data)
          setLastMessage(message)

          const prefs = notifPrefsRef.current
          const showToast = shouldShowToast(message.type, prefs)

          // Handle resync_required by invalidating SWR caches
          if (message.type === "resync_required") {
            mutate((key) => {
              const k = swrResource(key)

              return k !== null && (
                k.startsWith("mitigations") ||
                k.startsWith("events") ||
                k === "stats" ||
                k === "dashboard" ||
                k.startsWith("signal-groups")
              )
            })

            if (showToast) toast.info("Refreshing live data after missed updates")
          }

          // Invalidate relevant caches based on message type
          // SWR keys match hook keys: "mitigations", "stats", "events"
          if (
            message.type === "mitigation_created" ||
            message.type === "mitigation_updated" ||
            message.type === "mitigation_expired" ||
            message.type === "mitigation_withdrawn"
          ) {
            // Toast notifications (filtered by preferences)
            if (showToast) {
              if (message.type === "mitigation_created" && message.mitigation) {
                toast.error(`Mitigation Created: ${message.mitigation.victim_ip}`, {
                  description: `${message.mitigation.vector} • Action: ${message.mitigation.action_type}`
                })
              } else if (message.type === "mitigation_updated" && message.mitigation) {
                toast.warning(`Mitigation Updated: ${message.mitigation.victim_ip}`, {
                  description: `${message.mitigation.vector} • Action: ${message.mitigation.action_type}`
                })
              } else if (message.type === "mitigation_withdrawn" && message.mitigation_id) {
                toast.success(`Mitigation Withdrawn`, {
                  description: `ID: ${message.mitigation_id.split("-")[0]}...`
                })
              } else if (message.type === "mitigation_expired" && message.mitigation_id) {
                toast.info(`Mitigation Expired`, {
                  description: `ID: ${message.mitigation_id.split("-")[0]}...`
                })
              }
            }

            // Invalidate all mitigation-related keys (including those with params)
            mutate((key) => swrResource(key)?.startsWith("mitigations") ?? false)
            mutate("stats")
          }

          if (message.type === "event_ingested") {
            mutate((key) => swrResource(key)?.startsWith("events") ?? false)
            mutate("stats")
          }
        } catch (e) {
          console.error("Failed to parse WebSocket message:", e)
        }
      }

      ws.onclose = usePolling
      ws.onerror = usePolling
    } catch (e) {
      console.error("Failed to create WebSocket:", e)
      setConnectionState("polling")
      scheduleReconnect()
    }
  }, [maxReconnectAttempts, mutate])

  const disconnect = useCallback(() => {
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current)
      reconnectTimeoutRef.current = null
    }

    if (connectionTimeoutRef.current) {
      clearTimeout(connectionTimeoutRef.current)
      connectionTimeoutRef.current = null
    }

    reconnectAttemptsRef.current = maxReconnectAttempts // Prevent auto-reconnect
    const ws = wsRef.current
    wsRef.current = null
    ws?.close()
    setConnectionState("polling")
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
