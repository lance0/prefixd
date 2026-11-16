"use client"

import type React from "react"
import { useState, useEffect } from "react"
import { Sidebar } from "./sidebar"
import { Dialog } from "@/components/ui/dialog"
import { TopBar } from "./top-bar"
import { StaleDataNotice } from "@/components/connection-status"
import { CommandPalette } from "./command-palette"
import { KeyboardShortcutsModal } from "./keyboard-shortcuts-modal"
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcuts"
import { usePermissions } from "@/hooks/use-permissions"
import { cn } from "@/lib/utils"

const SIDEBAR_COLLAPSED_KEY = "prefixd-sidebar-collapsed"

export function DashboardLayout({ children }: { children: React.ReactNode }) {
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false)
  const [shortcutsModalOpen, setShortcutsModalOpen] = useState(false)

  // Load collapsed state from localStorage
  useEffect(() => {
    const stored = localStorage.getItem(SIDEBAR_COLLAPSED_KEY)

    if (stored !== null) {
      setSidebarCollapsed(stored === "true")
    }
  }, [])

  // Save collapsed state to localStorage
  const handleToggleCollapse = () => {
    const newState = !sidebarCollapsed
    setSidebarCollapsed(newState)
    localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(newState))
  }

  const { canWithdraw } = usePermissions()

  useKeyboardShortcuts({
    canMitigate: canWithdraw,
    onCommandPalette: () => setCommandPaletteOpen(true),
    onToggleSidebar: handleToggleCollapse,
    onToggleHelp: () => setShortcutsModalOpen((prev) => !prev),
  })

  return (
    <Dialog open={sidebarOpen} onOpenChange={setSidebarOpen}>
      <div className="min-h-dvh bg-background">
        <a href="#main-content" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-md focus:border focus:bg-card focus:p-3">Skip to content</a>
        <Sidebar
          onClose={() => setSidebarOpen(false)}
          isCollapsed={sidebarCollapsed}
          onToggleCollapse={handleToggleCollapse}
        />
        <div className={cn(sidebarCollapsed ? "lg:pl-16" : "lg:pl-56")}>
          <TopBar onSearchClick={() => setCommandPaletteOpen(true)} />
          <main id="main-content" tabIndex={-1} className="min-w-0 p-4 sm:p-6 lg:p-8"><div className="mx-auto max-w-7xl"><StaleDataNotice />{children}</div></main>
        </div>

        {/* Command palette */}
        <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} canMitigate={canWithdraw} />

        <KeyboardShortcutsModal open={shortcutsModalOpen} onOpenChange={setShortcutsModalOpen} canMitigate={canWithdraw} />
      </div>
    </Dialog>
  )
}
