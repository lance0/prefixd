"use client"

import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { useHealth, useSafelist, useStats, usePops } from "@/hooks/use-api"
import { Shield, Server, Activity, AlertCircle, RefreshCw, CheckCircle, XCircle, Globe, Clock } from "lucide-react"
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
      {up ? <CheckCircle className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
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
          <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
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
          <AlertCircle className="h-4 w-4" />
          <span className="text-sm">{error}</span>
        </div>
      </CardContent>
    </Card>
  )
}

export default function ConfigPage() {
  const { data: health, error: healthError, isLoading: healthLoading } = useHealth()
  const { data: stats, error: statsError, isLoading: statsLoading } = useStats()
  const { data: safelist, error: safelistError, isLoading: safelistLoading } = useSafelist()
  const { data: pops, error: popsError, isLoading: popsLoading } = usePops()

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* System Status */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Server className="h-5 w-5" />
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
                    <span className="font-mono text-sm">{health.version || "dev"}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">POP</span>
                    <span className="font-mono text-sm">{health.pop}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Uptime</span>
                    <span className="font-mono text-sm flex items-center gap-1">
                      <Clock className="h-3 w-3" />
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
                  <p className="text-xs text-muted-foreground">
                    FlowSpec announcements are {health.bgp_session_up ? "active" : "paused"}
                  </p>
                </CardContent>
              </Card>
            ) : null}

            {statsLoading ? (
              <LoadingCard title="Quotas" />
            ) : statsError ? (
              <ErrorCard title="Quotas" error="Failed to load" />
            ) : stats ? (
              <Card className="bg-card border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-foreground text-sm">Current Usage</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Active Mitigations</span>
                    <span className="font-mono text-sm">{stats.total_active}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Total Mitigations</span>
                    <span className="font-mono text-sm">{stats.total_mitigations}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground text-sm">Total Events</span>
                    <span className="font-mono text-sm">{stats.total_events}</span>
                  </div>
                </CardContent>
              </Card>
            ) : null}
          </div>
        </div>

        {/* POPs */}
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Globe className="h-5 w-5" />
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
                        <span className="ml-2 text-primary">{pop.active_mitigations} active</span>
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
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Shield className="h-5 w-5" />
            Safelist
          </h2>
          <Card className="bg-card border-border">
            <CardHeader className="pb-2">
              <CardDescription>
                Protected prefixes that will never be mitigated
              </CardDescription>
            </CardHeader>
            <CardContent>
              {safelistLoading ? (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="h-5 w-5 animate-spin text-muted-foreground" />
                </div>
              ) : safelistError ? (
                <div className="flex items-center gap-2 text-destructive py-4">
                  <AlertCircle className="h-4 w-4" />
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
                      </tr>
                    </thead>
                    <tbody>
                      {safelist.map((entry) => (
                        <tr key={entry.prefix} className="border-b border-border/50 hover:bg-secondary/50">
                          <td className="py-2 px-2 font-mono text-foreground">{entry.prefix}</td>
                          <td className="py-2 px-2 text-muted-foreground">{entry.reason || "-"}</td>
                          <td className="py-2 px-2 text-muted-foreground">{entry.added_by}</td>
                          <td className="py-2 px-2 text-muted-foreground font-mono text-xs">
                            {new Date(entry.added_at).toLocaleDateString()}
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

        {/* Info Card */}
        <Card className="bg-secondary/30 border-border">
          <CardContent className="pt-4">
            <div className="flex items-start gap-3">
              <Activity className="h-5 w-5 text-muted-foreground mt-0.5" />
              <div>
                <p className="text-sm text-muted-foreground">
                  Configuration changes are made via YAML files on the server. Use{" "}
                  <code className="bg-secondary px-1 py-0.5 rounded text-xs font-mono">prefixdctl reload</code>{" "}
                  to apply changes without restart.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </DashboardLayout>
  )
}
