"use client"

import { Wifi, RefreshCw, Clock3 } from "lucide-react"
import { cn } from "@/lib/utils"
import { type ConnectionState } from "@/hooks/use-websocket"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"

interface ConnectionStatusProps {
  state: ConnectionState
  className?: string
}

export function ConnectionStatus({ state, className }: ConnectionStatusProps) {
  const getStatusConfig = () => {
    switch (state) {
      case "connected":
        return {
          icon: Wifi,
          color: "text-success",
          label: "Live",
          description: "Realtime feed connected. HTTP polling also remains active.",
        }
      case "connecting":
        return {
          icon: Clock3,
          color: "text-warning",
          label: "Polling",
          description: "Connecting to the realtime feed; using HTTP polling every 5 seconds while this tab is visible and the API is reachable.",
        }
      case "polling":
      case "disconnected":
      case "error":
        return {
          icon: RefreshCw,
          color: "text-warning",
          label: "Polling",
          description: "Realtime feed unavailable; live event toasts are paused. Operational data polls every 5 seconds while this tab is visible and the API is reachable. Next.js alone needs a WebSocket upgrade proxy for /v1/ws/feed, such as nginx. Network or authentication failures can also interrupt realtime.",
        }
    }
  }

  const config = getStatusConfig()
  const Icon = config.icon

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div role="status" tabIndex={0} aria-label={config.description} className={cn("flex items-center gap-1.5 rounded-sm focus-visible:outline-2 focus-visible:outline-ring focus-visible:outline-offset-2", className)}>
            <Icon className={cn("size-4", config.color)} aria-hidden="true" />
            <span className="text-xs text-muted-foreground">
              {config.label}
            </span>
          </div>
        </TooltipTrigger>
        <TooltipContent className="max-w-sm">
          <p>{config.description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
