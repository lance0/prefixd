"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { LayoutDashboard, Shield, Activity, FileText, Settings, X, ChevronsLeft, ChevronsRight, FileCode, Database, History, Waypoints } from "lucide-react"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { DialogClose, DialogContent, DialogTitle } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { usePermissions } from "@/hooks/use-permissions"
import { useStats, useOpenSignalGroupCount } from "@/hooks/use-api"

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard, adminOnly: false },
  { href: "/mitigations", label: "Mitigations", icon: Shield, adminOnly: false },
  { href: "/events", label: "Events", icon: Activity, adminOnly: false },
  { href: "/correlation", label: "Correlation", icon: Waypoints, adminOnly: false },
  { href: "/inventory", label: "Inventory", icon: Database, adminOnly: false },
  { href: "/ip-history", label: "IP history", icon: History, adminOnly: false },
  { href: "/audit-log", label: "Audit log", icon: FileText, adminOnly: false },
  { href: "/config", label: "Configuration", icon: FileCode, adminOnly: false },
  { href: "/admin", label: "Administration", icon: Settings, adminOnly: true },
]

interface SidebarProps {
  onClose?: () => void
  isCollapsed?: boolean
  onToggleCollapse?: () => void
}

export function Sidebar({ onClose, isCollapsed = false, onToggleCollapse }: SidebarProps) {
  const pathname = usePathname()
  const permissions = usePermissions()
  const { data: stats } = useStats()
  const openGroupCount = useOpenSignalGroupCount()
  const visibleNavItems = navItems.filter(item => !item.adminOnly || permissions.isAdmin)

  const navigation = (collapsed: boolean) => (
    <nav aria-label="Main navigation" className="flex-1 space-y-1 overflow-y-auto px-3 py-5">
      {visibleNavItems.map(item => {
        const isActive = item.href === "/" ? pathname === "/" : pathname === item.href || pathname.startsWith(`${item.href}/`)
        const count = item.href === "/mitigations" ? stats?.total_active ?? 0 : item.href === "/correlation" ? openGroupCount : 0
        const displayCount = count > 99 ? "99+" : count
        const accessibleLabel = count > 0 ? `${item.label} (${displayCount})` : item.label

        const link = (
          <Link href={item.href} onClick={onClose} aria-current={isActive ? "page" : undefined} aria-label={collapsed ? accessibleLabel : undefined}
            className={cn("relative flex min-h-10 items-center gap-3 rounded-md px-3 text-sm", collapsed && "justify-center px-0", isActive ? "bg-sidebar-accent font-medium text-primary" : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground")}>
            <item.icon className="size-4 shrink-0" aria-hidden="true" />
            {!collapsed ? <span className="flex-1">{item.label}</span> : null}
            {count > 0 ? <span className={cn("rounded-sm bg-muted px-1.5 text-xs text-foreground", collapsed && "absolute -right-1 -top-1")}>{displayCount}</span> : null}
          </Link>
        )

        return collapsed ? <Tooltip key={item.href}><TooltipTrigger asChild>{link}</TooltipTrigger><TooltipContent side="right">{accessibleLabel}</TooltipContent></Tooltip> : <div key={item.href}>{link}</div>
      })}
    </nav>
  )

  const brand = (
    <Link href="/" aria-label="prefixd overview" onClick={onClose} className="flex items-center gap-2.5 rounded-sm font-semibold">
      <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-primary font-mono text-xs text-primary-foreground" aria-hidden="true">P</span>
      <span>prefixd</span>
    </Link>
  )

  return (
    <TooltipProvider delayDuration={150}>
      <aside aria-label="Workspace" className={cn("fixed inset-y-0 left-0 z-40 hidden flex-col border-r bg-sidebar lg:flex", isCollapsed ? "w-16" : "w-56")}>
        <div className={cn("flex h-14 shrink-0 items-center border-b px-6", isCollapsed && "justify-center px-0")}>
          {isCollapsed ? <Link href="/" aria-label="prefixd overview" className="flex size-8 items-center justify-center rounded-md bg-primary font-mono font-semibold text-primary-foreground">P</Link> : brand}
        </div>
        {navigation(isCollapsed)}
        {permissions.authDisabled && !isCollapsed ? <p className="mx-3 mb-3 rounded-md border px-3 py-2 text-xs text-muted-foreground">Authentication disabled</p> : null}
        <div className="border-t p-3">
          <Button variant="ghost" className="w-full justify-start text-muted-foreground" onClick={onToggleCollapse} aria-label={isCollapsed ? "Expand sidebar" : "Collapse sidebar"}>
            {isCollapsed ? <ChevronsRight className="size-4" /> : <><ChevronsLeft className="size-4" />Collapse sidebar</>}
          </Button>
        </div>
      </aside>
      <DialogContent aria-describedby={undefined} showCloseButton={false} className="left-0 top-0 flex h-dvh w-72 max-w-[calc(100%-3rem)] translate-x-0 translate-y-0 flex-col gap-0 rounded-none border-y-0 border-l-0 bg-sidebar p-0 pb-[env(safe-area-inset-bottom)] pt-[env(safe-area-inset-top)] data-[state=open]:animate-none data-[state=closed]:animate-none sm:max-w-72">
        <DialogTitle className="sr-only">Navigation</DialogTitle>
        <div className="flex h-14 shrink-0 items-center justify-between border-b px-5">
          {brand}
          <DialogClose asChild><Button variant="ghost" className="size-11 p-0" aria-label="Close navigation"><X className="size-4" /></Button></DialogClose>
        </div>
        {navigation(false)}
      </DialogContent>
    </TooltipProvider>
  )
}
