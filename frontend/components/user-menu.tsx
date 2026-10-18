"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/hooks/use-auth"
import { useHealth } from "@/hooks/use-api"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { User, LogOut, Shield, Loader2, Bell } from "lucide-react"
import { NotificationPreferencesPanel } from "@/components/dashboard/notification-preferences"

export function UserMenu() {
  const { operator, logout, isLoading: authLoading } = useAuth()
  const { data: health, isLoading: healthLoading } = useHealth()
  const router = useRouter()
  const [isLoggingOut, setIsLoggingOut] = useState(false)
  const [showPrefs, setShowPrefs] = useState(false)

  if (authLoading || healthLoading || !health || health.auth_mode === "none" || !operator) return null

  const handleLogout = async () => {
    setIsLoggingOut(true)
    try {
      await logout()
      router.push("/login")
    } finally {
      setIsLoggingOut(false)
    }
  }

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="sm" className="h-11 gap-2 sm:h-8" aria-label={`Operator menu for ${operator.username}`}>
            <User className="h-4 w-4" />
            <span className="hidden max-w-32 truncate sm:inline">{operator.username}</span>
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuLabel className="font-normal">
            <div className="flex flex-col space-y-1">
              <p className="text-sm font-medium">{operator.username}</p>
              <p className="text-xs text-muted-foreground flex items-center gap-1">
                <Shield className="h-3 w-3" />
                {operator.role}
              </p>
            </div>
          </DropdownMenuLabel>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => setShowPrefs(true)}>
            <Bell className="mr-2 h-4 w-4" />
            Notifications
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleLogout} disabled={isLoggingOut}>
            {isLoggingOut ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <LogOut className="mr-2 h-4 w-4" />
            )}
            Sign out
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <Dialog open={showPrefs} onOpenChange={setShowPrefs}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-sm">Notification preferences</DialogTitle>
          </DialogHeader>
          <NotificationPreferencesPanel />
        </DialogContent>
      </Dialog>
    </>
  )
}
