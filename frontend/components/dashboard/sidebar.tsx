"use client"

import Link from "next/link"
import { usePathname } from "next/navigation"
import { cn } from "@/lib/utils"
import { LayoutDashboard, Shield, Activity, FileText, Settings, X, ChevronsLeft, ChevronsRight, FileCode, Database, History } from "lucide-react"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { usePermissions } from "@/hooks/use-permissions"

const navItems = [
  { href: "/", label: "Overview", icon: LayoutDashboard, adminOnly: false },
  { href: "/mitigations", label: "Mitigations", icon: Shield, adminOnly: false },
  { href: "/events", label: "Events", icon: Activity, adminOnly: false },
  { href: "/inventory", label: "Inventory", icon: Database, adminOnly: false },
  { href: "/ip-history", label: "IP History", icon: History, adminOnly: false },
  { href: "/audit-log", label: "Audit Log", icon: FileText, adminOnly: false },
  { href: "/config", label: "Config", icon: FileCode, adminOnly: false },
  { href: "/admin", label: "Admin", icon: Settings, adminOnly: true },
]

interface SidebarProps {
  isOpen?: boolean
  onClose?: () => void
  isCollapsed?: boolean
  onToggleCollapse?: () => void
}

export function Sidebar({ isOpen, onClose, isCollapsed = false, onToggleCollapse }: SidebarProps) {
  const pathname = usePathname()
  const permissions = usePermissions()

  // Filter nav items based on permissions
  const visibleNavItems = navItems.filter(item => !item.adminOnly || permissions.isAdmin)

  return (
    <TooltipProvider delayDuration={0}>
      {isOpen && <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 lg:hidden" onClick={onClose} />}

      <aside
        className={cn(
          "fixed left-0 top-0 z-50 h-dvh border-r border-border bg-sidebar",
          "transition-[transform,width] duration-150 ease-out",
          isCollapsed ? "lg:w-14" : "lg:w-48",
          "w-56 lg:translate-x-0",
          isOpen ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-full flex-col">
          <div
            className={cn(
              "flex h-12 items-center border-b border-border",
              isCollapsed ? "justify-center px-2" : "justify-between px-3",
            )}
          >
            <Link href="/" className="flex items-center gap-2" onClick={onClose}>
              <div className="flex h-7 w-7 items-center justify-center bg-primary shrink-0">
                <span className="font-mono text-xs font-bold text-primary-foreground">P</span>
              </div>
              {!isCollapsed && (
                <span className="text-sm font-mono font-medium text-foreground tracking-tight">prefixd</span>
              )}
            </Link>

            <button
              onClick={onClose}
              className="lg:hidden p-2 -mr-2 text-muted-foreground hover:text-foreground min-h-[44px] min-w-[44px] flex items-center justify-center"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <nav className={cn("flex-1 py-2", isCollapsed ? "px-2" : "px-2")}>
            {visibleNavItems.map((item) => {
              const isActive = pathname === item.href

              if (isCollapsed) {
                return (
                  <Tooltip key={item.href}>
                    <TooltipTrigger asChild>
                      <Link
                        href={item.href}
                        onClick={onClose}
                        className={cn(
                          "flex h-9 w-full items-center justify-center transition-colors",
                          isActive
                            ? "bg-sidebar-accent text-primary"
                            : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
                        )}
                      >
                        <item.icon className="h-4 w-4" />
                      </Link>
                    </TooltipTrigger>
                    <TooltipContent side="right" className="font-mono text-xs">
                      {item.label}
                    </TooltipContent>
                  </Tooltip>
                )
              }

              return (
                <Link
                  key={item.href}
                  href={item.href}
                  onClick={onClose}
                  className={cn(
                    "flex items-center gap-2 px-2 py-2 text-xs font-mono transition-colors",
                    isActive
                      ? "bg-sidebar-accent text-primary"
                      : "text-muted-foreground hover:bg-sidebar-accent hover:text-foreground",
                  )}
                >
                  <item.icon className="h-4 w-4" />
                  {item.label}
                </Link>
              )
            })}
          </nav>

          {permissions.authDisabled && !isCollapsed && (
            <div className="mx-2 mb-1 px-2 py-1 text-[10px] font-mono text-muted-foreground bg-muted/50 border border-border">
              Auth disabled
            </div>
          )}

          <div className={cn("hidden lg:flex border-t border-border p-2", isCollapsed && "justify-center")}>
            <button
              onClick={onToggleCollapse}
              className={cn(
                "flex items-center gap-2 px-2 py-1.5 text-xs font-mono text-muted-foreground hover:bg-sidebar-accent hover:text-foreground transition-colors",
                isCollapsed && "w-full justify-center px-0",
              )}
            >
              {isCollapsed ? (
                <ChevronsRight className="h-4 w-4" />
              ) : (
                <>
                  <ChevronsLeft className="h-4 w-4" />
                  <span>Collapse</span>
                </>
              )}
            </button>
          </div>
        </div>
      </aside>
    </TooltipProvider>
  )
}
