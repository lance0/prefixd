"use client"

import { useState } from "react"
import { useSWRConfig } from "swr"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { useHealth, useSafelist, useStats, usePops } from "@/hooks/use-api"
import { addSafelist, removeSafelist, reloadConfig } from "@/lib/api"
import {
  Shield,
  Server,
  AlertCircle,
  RefreshCw,
  CheckCircle,
  XCircle,
  Globe,
  Clock,
  Plus,
  Trash2,
  RotateCcw,
} from "lucide-react"
import { cn } from "@/lib/utils"

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)

  if (days > 0) return `${days}d ${hours}h`
  if (hours > 0) return `${hours}h ${mins}m`
  return `${mins}m`
}

function StatusIndicator({ up }: { up: boolean }) {
  return (
    <div className={cn("flex items-center gap-2", up ? "text-green-500" : "text-red-500")}>
      {up ? <CheckCircle className="size-4" /> : <XCircle className="size-4" />}
      <span className="text-sm font-medium">{up ? "Connected" : "Disconnected"}</span>
    </div>
  )
}

function LoadingCard({ title }: { title: string }) {
  return (
    <Card className="bg-card border-border">
      <CardHeader>
        <CardTitle className="text-foreground text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center justify-center py-4">
          <RefreshCw className="size-5 animate-spin text-muted-foreground" />
        </div>
      </CardContent>
    </Card>
  )
}

function ErrorCard({ title, error }: { title: string; error: string }) {
  return (
    <Card className="bg-card border-border border-destructive/50">
      <CardHeader>
        <CardTitle className="text-foreground text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-center gap-2 text-destructive">
          <AlertCircle className="size-4" />
          <span className="text-sm">{error}</span>
        </div>
      </CardContent>
    </Card>
  )
}

export default function AdminPage() {
  const { mutate } = useSWRConfig()
  const { data: health, error: healthError, isLoading: healthLoading } = useHealth()
  const { data: stats, error: statsError, isLoading: statsLoading } = useStats()
  const { data: safelist, error: safelistError, isLoading: safelistLoading, mutate: mutateSafelist } = useSafelist()
  const { data: pops, error: popsError, isLoading: popsLoading } = usePops()

  const [newPrefix, setNewPrefix] = useState("")
  const [newReason, setNewReason] = useState("")
  const [isAddingSafelist, setIsAddingSafelist] = useState(false)
  const [safelistError2, setSafelistError2] = useState<string | null>(null)
  const [isReloading, setIsReloading] = useState(false)
  const [reloadStatus, setReloadStatus] = useState<"idle" | "success" | "error">("idle")

  const handleAddSafelist = async () => {
    if (!newPrefix.trim()) return
    
    setIsAddingSafelist(true)
    setSafelistError2(null)
    
    try {
      await addSafelist(newPrefix.trim(), newReason.trim(), "dashboard")
      await mutateSafelist()
      setNewPrefix("")
      setNewReason("")
    } catch (err) {
      setSafelistError2(err instanceof Error ? err.message : "Failed to add prefix")
    } finally {
      setIsAddingSafelist(false)
    }
  }

  const handleRemoveSafelist = async (prefix: string) => {
    try {
      await removeSafelist(prefix)
      await mutateSafelist()
    } catch (err) {
      setSafelistError2(err instanceof Error ? err.message : "Failed to remove prefix")
    }
  }

  const handleReloadConfig = async () => {
    setIsReloading(true)
    setReloadStatus("idle")
    
    try {
      await reloadConfig()
      setReloadStatus("success")
      // Refresh all data
      mutate(() => true)
      setTimeout(() => setReloadStatus("idle"), 3000)
    } catch (err) {
      setReloadStatus("error")
      setTimeout(() => setReloadStatus("idle"), 3000)
    } finally {
      setIsReloading(false)
    }
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Actions */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2 text-balance">
            <RotateCcw className="size-5" />
            Actions
          </h2>
          <Card className="bg-card border-border">
            <CardContent className="pt-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm font-medium text-foreground">Reload Configuration</p>
                  <p className="text-xs text-muted-foreground text-pretty">
                    Hot-reload inventory and playbooks without restarting the daemon
                  </p>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleReloadConfig}
                  disabled={isReloading}
                  className={cn(
                    reloadStatus === "success" && "border-green-500 text-green-500",
                    reloadStatus === "error" && "border-destructive text-destructive"
                  )}
                >
                  {isReloading ? (
                    <RefreshCw className="size-4 animate-spin" />
                  ) : reloadStatus === "success" ? (
                    <>
                      <CheckCircle className="size-4 mr-1" />
                      Reloaded
                    </>
                  ) : reloadStatus === "error" ? (
                    <>
                      <XCircle className="size-4 mr-1" />
                      Failed
                    </>
                  ) : (
                    <>
                      <RefreshCw className="size-4 mr-1" />
                      Reload
                    </>
                  )}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* System Status */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2 text-balance">
            <Server className="size-5" />
            System Status
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {healthLoading ? (
              <LoadingCard title="Daemon Status" />
            ) : healthError ? (
              <ErrorCard title="Daemon Status" error="Failed to connect" />
            ) : health ? (
              <Card className="bg-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-foreground text-sm">Daemon Status</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Status</span>
                    <Badge variant={health.status === "healthy" ? "default" : "destructive"}>
                      {health.status}
                    </Badge>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Version</span>
                    <span className="font-mono text-sm tabular-nums">{health.version || "dev"}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">POP</span>
                    <span className="font-mono text-sm">{health.pop}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Uptime</span>
                    <span className="font-mono text-sm tabular-nums flex items-center gap-1">
                      <Clock className="size-3" />
                      {formatUptime(health.uptime_seconds)}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ) : null}

            {healthLoading ? (
              <LoadingCard title="BGP Session" />
            ) : healthError ? (
              <ErrorCard title="BGP Session" error="Failed to connect" />
            ) : health ? (
              <Card className="bg-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-foreground text-sm">BGP Session</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <StatusIndicator up={health.bgp_session_up} />
                  <p className="text-xs text-muted-foreground text-pretty">
                    FlowSpec announcements are {health.bgp_session_up ? "active" : "paused"}
                  </p>
                </CardContent>
              </Card>
            ) : null}

            {statsLoading ? (
              <LoadingCard title="Current Usage" />
            ) : statsError ? (
              <ErrorCard title="Current Usage" error="Failed to load" />
            ) : stats ? (
              <Card className="bg-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-foreground text-sm">Current Usage</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Active Mitigations</span>
                    <span className="font-mono text-sm tabular-nums">{stats.total_active}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Total Mitigations</span>
                    <span className="font-mono text-sm tabular-nums">{stats.total_mitigations}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Total Events</span>
                    <span className="font-mono text-sm tabular-nums">{stats.total_events}</span>
                  </div>
                </CardContent>
              </Card>
            ) : null}
          </div>
        </div>

        {/* POPs */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2 text-balance">
            <Globe className="size-5" />
            Points of Presence
          </h2>
          {popsLoading ? (
            <LoadingCard title="POPs" />
          ) : popsError ? (
            <ErrorCard title="POPs" error="Failed to load POPs" />
          ) : pops && pops.length > 0 ? (
            <Card className="bg-card border-border">
              <CardContent className="pt-4">
                <div className="flex flex-wrap gap-2">
                  {pops.map((pop) => (
                    <Badge key={pop.pop} variant="outline" className="font-mono">
                      {pop.pop}
                      {pop.active_mitigations > 0 && (
                        <span className="ml-2 text-primary tabular-nums">{pop.active_mitigations} active</span>
                      )}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          ) : (
            <Card className="bg-card border-border">
              <CardContent className="pt-4">
                <p className="text-sm text-muted-foreground">No POPs configured</p>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Safelist */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2 text-balance">
            <Shield className="size-5" />
            Safelist
          </h2>
          <Card className="bg-card border-border">
            <CardHeader className="pb-2">
              <CardDescription className="text-pretty">
                Protected prefixes that will never be mitigated. Add infrastructure IPs, router loopbacks, and critical services.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Add new entry */}
              <div className="flex gap-2">
                <Input
                  placeholder="Prefix (e.g., 10.0.0.1/32)"
                  value={newPrefix}
                  onChange={(e) => setNewPrefix(e.target.value)}
                  className="font-mono flex-1"
                />
                <Input
                  placeholder="Reason (optional)"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="flex-1"
                />
                <Button
                  onClick={handleAddSafelist}
                  disabled={!newPrefix.trim() || isAddingSafelist}
                  size="sm"
                >
                  {isAddingSafelist ? (
                    <RefreshCw className="size-4 animate-spin" />
                  ) : (
                    <>
                      <Plus className="size-4 mr-1" />
                      Add
                    </>
                  )}
                </Button>
              </div>

              {safelistError2 && (
                <div className="flex items-center gap-2 text-destructive text-sm">
                  <AlertCircle className="size-4" />
                  {safelistError2}
                </div>
              )}

              {/* Safelist table */}
              {safelistLoading ? (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="size-5 animate-spin text-muted-foreground" />
                </div>
              ) : safelistError ? (
                <div className="flex items-center gap-2 text-destructive py-4">
                  <AlertCircle className="size-4" />
                  <span className="text-sm">Failed to load safelist</span>
                </div>
              ) : safelist && safelist.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left py-2 px-2 font-medium text-muted-foreground">Prefix</th>
                        <th className="text-left py-2 px-2 font-medium text-muted-foreground">Reason</th>
                        <th className="text-left py-2 px-2 font-medium text-muted-foreground">Added By</th>
                        <th className="text-left py-2 px-2 font-medium text-muted-foreground">Added At</th>
                        <th className="w-10"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {safelist.map((entry) => (
                        <tr key={entry.prefix} className="border-b border-border/50 hover:bg-secondary/50">
                          <td className="py-2 px-2 font-mono text-foreground">{entry.prefix}</td>
                          <td className="py-2 px-2 text-muted-foreground truncate max-w-48">{entry.reason || "-"}</td>
                          <td className="py-2 px-2 text-muted-foreground">{entry.added_by}</td>
                          <td className="py-2 px-2 text-muted-foreground font-mono text-xs tabular-nums">
                            {new Date(entry.added_at).toLocaleDateString()}
                          </td>
                          <td className="py-2 px-2">
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="size-8 p-0 text-muted-foreground hover:text-destructive"
                                  aria-label={`Remove ${entry.prefix} from safelist`}
                                >
                                  <Trash2 className="size-4" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>Remove from safelist?</AlertDialogTitle>
                                  <AlertDialogDescription className="text-pretty">
                                    This will allow <span className="font-mono">{entry.prefix}</span> to be mitigated
                                    if an attack is detected. This action cannot be undone.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => handleRemoveSafelist(entry.prefix)}
                                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                  >
                                    Remove
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-sm text-muted-foreground py-4">No safelist entries configured</p>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  )
}
