"use client"

import { Wifi, WifiOff, RefreshCw, Clock3, AlertTriangle } from "lucide-react"
import { cn } from "@/lib/utils"
import { formatRelative } from "@/lib/format"
import { useWebSocket, type ConnectionState } from "@/hooks/use-websocket"
import { useDataFreshness } from "@/hooks/use-data-freshness"
import type { DataFreshness, FreshnessState } from "@/lib/freshness"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

interface ConnectionStatusProps {
  state: ConnectionState
  className?: string
}

const DISPLAY: Record<FreshnessState, { icon: typeof Wifi; label: string; tone: string; chip?: string }> = {
  connecting: { icon: Clock3, label: "Connecting", tone: "text-muted-foreground" },
  live: { icon: Wifi, label: "Live", tone: "text-success" },
  polling: { icon: RefreshCw, label: "Polling", tone: "text-warning" },
  stale: { icon: AlertTriangle, label: "Stale", tone: "text-warning", chip: "border-warning/60 bg-warning/10 text-foreground" },
  offline: { icon: WifiOff, label: "Offline", tone: "text-destructive", chip: "border-destructive/60 bg-destructive/10 text-foreground" },
}

function feedDescription(state: ConnectionState): string {
  switch (state) {
    case "connected":
      return "Realtime feed connected. HTTP polling also remains active."
    case "connecting":
      return "Connecting to the realtime feed; using HTTP polling every 5 seconds while this tab is visible and the API is reachable."
    case "polling":
    case "disconnected":
    case "error":
      return "Realtime feed unavailable; live event toasts are paused. Operational data polls every 5 seconds while this tab is visible and the API is reachable. Next.js alone needs a WebSocket upgrade proxy for /v1/ws/feed, such as nginx. Network or authentication failures can also interrupt realtime."
  }
}

/** "12s ago", measured from browser receipt of the last successful API response. */
function ago(ageMs: number): string {
  return formatRelative(0, ageMs)
}

function dataDescription({ state, ageMs }: DataFreshness): string {
  const last = ageMs === null ? "no successful API response yet" : `last successful API response ${ago(ageMs)}`

  switch (state) {
    case "connecting":
      return "Waiting for the first API response."
    case "live":
    case "polling":
      return `Data is current; ${last}.`
    case "stale":
      return `Data on screen may be out of date: ${last}.`
    case "offline":
      return `API requests are failing; data on screen is out of date: ${last}.`
  }
}

export function ConnectionStatus({ state, className }: ConnectionStatusProps) {
  const freshness = useDataFreshness(state)
  const display = DISPLAY[freshness.state]
  const Icon = display.icon
  const description = `${dataDescription(freshness)} ${feedDescription(state)}`
  const age = freshness.state === "live" || freshness.ageMs === null ? null : ago(freshness.ageMs)

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            role="status"
            tabIndex={0}
            aria-label={`${display.label}. ${description}`}
            className={cn(
              "flex items-center gap-1.5 rounded-sm text-xs text-muted-foreground focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2",
              display.chip && cn("rounded-md border px-2 py-0.5 font-medium", display.chip),
              className,
            )}
          >
            <Icon className={cn("size-4", display.tone)} aria-hidden="true" />
            <span>{display.label}</span>
            {/* The ticking age stays out of the live region; the accessible name carries it. */}
            {age ? <span aria-hidden="true" className="tabular-nums">({age})</span> : null}
          </div>
        </TooltipTrigger>
        <TooltipContent className="max-w-sm">
          <p>{description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}

/** Page-level notice shown only while data is stale, so lists never look current when they are not. */
export function StaleDataNotice() {
  const { connectionState } = useWebSocket()
  const { state, ageMs } = useDataFreshness(connectionState)
  const stale = state === "stale" || state === "offline"

  return (
    <div role="status" className={cn(stale && "mb-4 flex flex-wrap items-baseline gap-x-2 rounded-md border px-3 py-2 text-sm", state === "stale" && "border-warning/60 bg-warning/10", state === "offline" && "border-destructive/60 bg-destructive/10")}>
      {stale ? (
        <>
          <p className="font-medium">
            {state === "offline" ? "The controller API is not responding." : "Data may be out of date."}
            {" "}This page has not refreshed; mitigations may have been created, extended or withdrawn since.
          </p>
          <p aria-hidden="true" className="text-muted-foreground tabular-nums">
            {ageMs === null ? "No data received yet." : `Updated ${ago(ageMs)}.`}
          </p>
        </>
      ) : null}
    </div>
  )
}
