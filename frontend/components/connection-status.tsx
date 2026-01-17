"use client"

import { Wifi, WifiOff, Loader2 } from "lucide-react"
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
          color: "text-green-500",
          label: "Connected",
          description: "Real-time updates active",
        }
      case "connecting":
        return {
          icon: Loader2,
          color: "text-yellow-500",
          label: "Connecting...",
          description: "Establishing connection",
          animate: true,
        }
      case "disconnected":
        return {
          icon: WifiOff,
          color: "text-muted-foreground",
          label: "Disconnected",
          description: "Reconnecting...",
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
          <div className={cn("flex items-center gap-1.5", className)}>
            <Icon
              className={cn(
                "h-4 w-4",
                config.color,
                config.animate && "animate-spin"
              )}
            />
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
