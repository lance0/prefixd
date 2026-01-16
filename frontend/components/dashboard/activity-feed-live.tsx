"use client"

import { Shield, AlertTriangle, User, FileText, RefreshCw, AlertCircle } from "lucide-react"
import { cn } from "@/lib/utils"
import { useEvents, useAuditLog } from "@/hooks/use-api"

interface ActivityItem {
  id: string
  type: "mitigation" | "event" | "operator" | "system"
  timestamp: string
  description: string
  ip?: string
}

function formatTimestamp(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)

  if (diffMins < 1) return "just now"
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  
  return date.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  })
}

function getActivityIcon(type: ActivityItem["type"]) {
  switch (type) {
    case "mitigation":
      return <Shield className="h-3 w-3" />
    case "event":
      return <AlertTriangle className="h-3 w-3" />
    case "operator":
      return <User className="h-3 w-3" />
    case "system":
      return <FileText className="h-3 w-3" />
  }
}

export function ActivityFeedLive() {
  const { data: events, error: eventsError, isLoading: eventsLoading } = useEvents({ limit: 10 })
  const { data: audit, error: auditError, isLoading: auditLoading } = useAuditLog({ limit: 10 })

  const isLoading = eventsLoading || auditLoading
  const hasError = eventsError || auditError

  // Combine and sort activities
  const activities: ActivityItem[] = []

  if (events) {
    for (const event of events.slice(0, 5)) {
      activities.push({
        id: `event-${event.event_id}`,
        type: "event",
        timestamp: event.ingested_at,
        description: `${event.vector.replace("_", " ")} detected from ${event.source}`,
        ip: event.victim_ip,
      })
    }
  }

  if (audit) {
    for (const entry of audit.slice(0, 5)) {
      const actorType = entry.actor_type === "operator" ? "operator" : 
                        entry.actor_type === "system" ? "system" : "mitigation"
      
      let description = entry.action.replace(/_/g, " ")
      if (entry.target_id) {
        const shortId = entry.target_id.length > 8 ? entry.target_id.slice(0, 8) : entry.target_id
        description = `${description} (${shortId}...)`
      }

      activities.push({
        id: `audit-${entry.audit_id}`,
        type: actorType,
        timestamp: entry.timestamp,
        description,
        ip: entry.details?.victim_ip as string | undefined,
      })
    }
  }

  // Sort by timestamp descending
  activities.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  const displayActivities = activities.slice(0, 10)

  if (hasError) {
    return (
      <div className="border border-border bg-card p-4 h-full">
        <h3 className="text-xs font-mono uppercase tracking-wide text-muted-foreground mb-3">Recent Activity</h3>
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <AlertCircle className="h-6 w-6 mb-2 text-destructive" />
          <p className="text-xs">Failed to load activity</p>
        </div>
      </div>
    )
  }

  if (isLoading && displayActivities.length === 0) {
    return (
      <div className="border border-border bg-card p-4 h-full">
        <h3 className="text-xs font-mono uppercase tracking-wide text-muted-foreground mb-3">Recent Activity</h3>
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <RefreshCw className="h-5 w-5 animate-spin mb-2" />
          <p className="text-xs">Loading...</p>
        </div>
      </div>
    )
  }

  if (displayActivities.length === 0) {
    return (
      <div className="border border-border bg-card p-4 h-full">
        <h3 className="text-xs font-mono uppercase tracking-wide text-muted-foreground mb-3">Recent Activity</h3>
        <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
          <p className="text-xs">No recent activity</p>
        </div>
      </div>
    )
  }

  return (
    <div className="border border-border bg-card p-4 h-full">
      <h3 className="text-xs font-mono uppercase tracking-wide text-muted-foreground mb-3">Recent Activity</h3>
      <div className="space-y-0">
        {displayActivities.map((activity, index) => (
          <div
            key={activity.id}
            className={cn(
              "flex items-start gap-3 py-2 transition-colors hover:bg-secondary/50",
              index !== displayActivities.length - 1 && "border-b border-border/50"
            )}
          >
            <div className="mt-0.5 opacity-60">{getActivityIcon(activity.type)}</div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 text-xs">
                <span className="font-mono text-[10px] text-muted-foreground whitespace-nowrap tabular-nums">
                  {formatTimestamp(activity.timestamp)}
                </span>
                <span className="text-foreground truncate">{activity.description}</span>
              </div>
              {activity.ip && <span className="font-mono text-[10px] text-primary">{activity.ip}</span>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
