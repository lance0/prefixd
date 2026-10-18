"use client"

import Link from "next/link"
import { Shield, AlertTriangle, User, FileText } from "lucide-react"
import { cn } from "@/lib/utils"
import { useEvents, useAuditLog } from "@/hooks/use-api"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { formatRelative, formatUtc } from "@/lib/format"

interface ActivityItem {
  id: string
  type: "mitigation" | "event" | "operator" | "system"
  timestamp: string
  description: string
  ip?: string
  href?: string
}

function getActivityIcon(type: ActivityItem["type"]) {
  switch (type) {
    case "mitigation":
      return <Shield className="size-3.5" aria-hidden="true" />
    case "event":
      return <AlertTriangle className="size-3.5" aria-hidden="true" />
    case "operator":
      return <User className="size-3.5" aria-hidden="true" />
    case "system":
      return <FileText className="size-3.5" aria-hidden="true" />
  }
}

export function ActivityFeedLive() {
  const { data: eventsResp, error: eventsError, isLoading: eventsLoading, mutate: retryEvents } = useEvents({ limit: 10 })
  const { data: auditResp, error: auditError, isLoading: auditLoading, mutate: retryAudit } = useAuditLog({ limit: 10 })
  const events = eventsResp?.events
  const audit = auditResp?.entries

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
        description: `${event.vector.replace(/_/g, " ")} detected from ${event.source}`,
        ip: event.victim_ip,
        href: `/events?id=${encodeURIComponent(event.event_id)}`,
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
        description = `${description} (${shortId}…)`
      }

      const href = entry.target_type === "mitigation" && entry.target_id
        ? `/mitigations/${entry.target_id}`
        : undefined

      activities.push({
        id: `audit-${entry.audit_id}`,
        type: actorType,
        timestamp: entry.timestamp,
        description,
        ip: entry.details?.victim_ip as string | undefined,
        href,
      })
    }
  }

  // Sort by timestamp descending
  activities.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  const displayActivities = activities.slice(0, 10)

  const heading = <h2 className="mb-3 text-sm font-semibold text-balance">Recent activity</h2>

  if (hasError) {
    return (
      <section aria-label="Recent activity" className="min-w-0">
        {heading}
        <div className="rounded-md border bg-card">
          <ErrorState title="Unable to load recent activity" detail="Events and audit entries could not be refreshed. Open the audit log for the full record." onRetry={() => { void Promise.allSettled([retryEvents(), retryAudit()]) }} />
        </div>
      </section>
    )
  }

  if (isLoading && displayActivities.length === 0) {
    return (
      <section aria-label="Recent activity" className="min-w-0">
        {heading}
        <div className="rounded-md border bg-card"><LoadingRows label="Loading recent activity" /></div>
      </section>
    )
  }

  if (displayActivities.length === 0) {
    return (
      <section aria-label="Recent activity" className="min-w-0">
        {heading}
        <div className="rounded-md border bg-card">
          <EmptyState
            title="No recent activity"
            description="Events and operator actions will appear here."
            action={<Link href="/audit-log" className="rounded-sm text-sm text-primary hover:underline">View audit log</Link>}
          />
        </div>
      </section>
    )
  }

  const now = Date.now()

  return (
    <section aria-label="Recent activity" className="min-w-0">
      {heading}
      <div className="divide-y rounded-md border bg-card">
        {displayActivities.map((activity) => {
          const content = (
            <div className={cn("flex items-start gap-3 px-3 py-2", activity.href && "hover:bg-muted/40")}>
              <div className="mt-0.5 text-muted-foreground">{getActivityIcon(activity.type)}</div>
              <div className="min-w-0 flex-1 text-sm">
                <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
                  <time dateTime={activity.timestamp} title={formatUtc(activity.timestamp, now)} className="whitespace-nowrap text-xs text-muted-foreground tabular-nums">
                    {formatRelative(activity.timestamp, now)}
                  </time>
                  <span className="text-pretty">{activity.description}</span>
                </div>
                {activity.ip && <span className="font-mono text-xs text-muted-foreground">{activity.ip}</span>}
              </div>
            </div>
          )

          return activity.href ? (
            <Link key={activity.id} href={activity.href} className="block rounded-sm">
              {content}
            </Link>
          ) : (
            <div key={activity.id}>{content}</div>
          )
        })}
      </div>
    </section>
  )
}
