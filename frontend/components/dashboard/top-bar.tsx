"use client"

import { useEffect, useState } from "react"
import { Menu, Search, Sun, Moon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { DialogTrigger } from "@/components/ui/dialog"
import { ConnectionStatus } from "@/components/connection-status"
import { UserMenu } from "@/components/user-menu"
import { useWebSocket } from "@/hooks/use-websocket"
import { useHealthDetail } from "@/hooks/use-api"
import { useTheme } from "next-themes"

interface TopBarProps {
  onSearchClick?: () => void
}

export function TopBar({ onSearchClick }: TopBarProps) {
  const [time, setTime] = useState("")
  const [mounted, setMounted] = useState(false)
  const { connectionState } = useWebSocket()
  const { data: health, error } = useHealthDetail()
  const { resolvedTheme, setTheme } = useTheme()
  const currentPop = !error ? health?.pop?.toUpperCase() : undefined

  useEffect(() => { setMounted(true) }, [])
  useEffect(() => {
    const updateTime = () => setTime(new Date().toLocaleTimeString("en-GB", { timeZone: "UTC", hour12: false }) + " UTC")
    updateTime()
    const interval = setInterval(updateTime, 1000)
    return () => clearInterval(interval)
  }, [])

  return (
    <header className="sticky top-0 z-30 flex h-14 min-w-0 items-center justify-between gap-2 border-b bg-background px-4 sm:px-6">
      <div className="flex min-w-0 items-center gap-2 sm:gap-4">
        <DialogTrigger asChild><Button variant="ghost" className="size-11 shrink-0 p-0 lg:hidden" aria-label="Open navigation"><Menu className="size-4" /></Button></DialogTrigger>
        <span className="whitespace-nowrap text-xs text-muted-foreground">POP <span className="font-mono font-medium text-foreground">{currentPop ?? "unknown"}</span></span>
        <Button variant="outline" size="sm" onClick={onSearchClick} aria-label="Search workspace" className="hidden gap-2 text-muted-foreground sm:inline-flex">
          <Search className="size-3.5" aria-hidden="true" />Search<kbd className="kbd ml-3">⌘K</kbd>
        </Button>
      </div>
      <div className="flex shrink-0 items-center gap-1.5 sm:gap-4">
        <ConnectionStatus state={connectionState} />
        <time className="hidden text-xs text-muted-foreground tabular-nums xl:block">{time}</time>
        {mounted ? <Button variant="ghost" className="size-11 p-0 sm:size-9" onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")} aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} mode`}>
          {resolvedTheme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </Button> : null}
        <UserMenu />
      </div>
    </header>
  )
}
