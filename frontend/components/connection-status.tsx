"use client"

import { Wifi, WifiOff, Clock3 } from "lucide-react"
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
          label: "Connected",
          description: "Real-time updates active",
        }
      case "connecting":
        return {
          icon: Clock3,
          color: "text-warning",
          label: "Connecting…",
          description: "Establishing connection",
        }
      case "disconnected":
        return {
          icon: WifiOff,
          color: "text-warning",
          label: "Disconnected",
          description: "Live updates paused; reconnecting…",
        }
      case "error":
        return {
          icon: WifiOff,
          color: "text-destructive",
          label: "Error",
          description: "Connection failed",
        }
    }
  }

  const config = getStatusConfig()
  const Icon = config.icon

  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <div role="status" aria-label={config.description} className={cn("flex items-center gap-1.5", className)}>
            <Icon className={cn("size-4", config.color)} aria-hidden="true" />
            <span className="text-xs text-muted-foreground hidden sm:inline">
              {config.label}
            </span>
          </div>
        </TooltipTrigger>
        <TooltipContent>
          <p>{config.description}</p>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  )
}
