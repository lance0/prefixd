"use client"

import { useEffect, useState } from "react"
import { Menu, Search } from "lucide-react"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { ConnectionStatus } from "@/components/connection-status"
import { UserMenu } from "@/components/user-menu"
import { useWebSocket } from "@/hooks/use-websocket"
import { usePops, useHealth } from "@/hooks/use-api"

interface TopBarProps {
  onMenuClick?: () => void
  onSearchClick?: () => void
}

export function TopBar({ onMenuClick, onSearchClick }: TopBarProps) {
  const [time, setTime] = useState<string>("")
  const { connectionState } = useWebSocket()
  const { data: popsData } = usePops()
  const { data: health } = useHealth()

  const currentPop = health?.pop?.toUpperCase()
  const pops = popsData?.map((p) => p.pop.toUpperCase()) ?? (currentPop ? [currentPop] : [])

  useEffect(() => {
    const updateTime = () => {
      const now = new Date()
      setTime(
        now.toLocaleTimeString("en-US", {
          timeZone: "UTC",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }) + " UTC",
      )
    }
    updateTime()
    const interval = setInterval(updateTime, 1000)
    return () => clearInterval(interval)
  }, [])

  return (
    <header className="sticky top-0 z-30 flex h-12 items-center justify-between border-b border-border bg-background/95 px-3 sm:px-4 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="flex items-center gap-3">
        <button
          onClick={onMenuClick}
          className="lg:hidden p-2 -ml-2 text-muted-foreground hover:text-foreground min-h-[44px] min-w-[44px] flex items-center justify-center"
        >
          <Menu className="h-4 w-4" />
        </button>

        <div className="flex lg:hidden items-center gap-2">
          <div className="flex h-6 w-6 items-center justify-center bg-primary">
            <span className="font-mono text-[10px] font-bold text-primary-foreground">P</span>
          </div>
        </div>

        <Select defaultValue={currentPop}>
          <SelectTrigger className="w-20 h-7 bg-secondary border-border text-xs font-mono">
            <SelectValue placeholder={currentPop ?? "..."} />
          </SelectTrigger>
          <SelectContent>
            {pops.map((pop) => (
              <SelectItem key={pop} value={pop} className="text-xs font-mono">
                {pop}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <button
          onClick={onSearchClick}
          className="hidden sm:flex items-center gap-2 h-7 px-2 border border-border bg-secondary/50 text-xs text-muted-foreground hover:bg-secondary hover:text-foreground transition-colors"
        >
          <Search className="h-3 w-3" />
          <span className="hidden md:inline font-mono">Search</span>
          <kbd className="kbd">⌘K</kbd>
        </button>
      </div>
      <div className="flex items-center gap-3">
        <ConnectionStatus state={connectionState} />
        <div className="text-[10px] font-mono text-muted-foreground tabular-nums">{time}</div>
        <UserMenu />
      </div>
    </header>
  )
}
