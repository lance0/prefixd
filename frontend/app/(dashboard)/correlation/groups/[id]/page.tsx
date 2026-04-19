"use client"

import { use } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { useSignalGroupDetail, useCorrelationConfig } from "@/hooks/use-api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import {
  ArrowLeft,
  Layers,
  RefreshCw,
  ShieldAlert,
  Clock,
  BarChart3,
  CheckCircle2,
  AlertTriangle,
  Link2,
  Info,
} from "lucide-react"

// ── Helpers ──────────────────────────────────────────────

function formatTimestamp(dateStr: string): string {
  return (
    new Date(dateStr).toLocaleString("en-US", {
      timeZone: "UTC",
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }) + " UTC"
  )
}

function statusBadge(status: string, corroborated: boolean) {
  if (status === "resolved") {
    return (
      <Badge variant="default" className="bg-green-600 hover:bg-green-600 text-xs">
        Resolved
      </Badge>
    )
  }
  if (status === "expired") {
    return (
      <Badge variant="secondary" className="text-xs">
        Expired
      </Badge>
    )
  }
  return (
    <Badge variant={corroborated ? "default" : "outline"} className="text-xs">
      {corroborated ? "Corroborated" : "Open"}
    </Badge>
  )
}

const SOURCE_COLORS: Record<string, string> = {
  fastnetmon: "bg-blue-500",
  alertmanager: "bg-orange-500",
  dashboard: "bg-purple-500",
}

function sourceColor(source: string): string {
  return SOURCE_COLORS[source] ?? "bg-gray-500"
}

// ── Page Component ───────────────────────────────────────

export default function SignalGroupDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)
  const router = useRouter()

  const { data: group, isLoading, error } = useSignalGroupDetail(id)
  const { data: correlationConfig } = useCorrelationConfig()

  // Loading state
  if (isLoading) {
    return (
      <DashboardLayout>
        <div className="flex h-[50vh] items-center justify-center">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </DashboardLayout>
    )
  }

  // 404 / error state
  if (error || !group) {
    return (
      <DashboardLayout>
        <div className="flex flex-col items-center justify-center h-[50vh] space-y-4">
          <ShieldAlert className="h-12 w-12 text-muted-foreground" />
          <h2 className="text-xl font-semibold">Signal Group Not Found</h2>
          <p className="text-muted-foreground text-sm">
            The requested signal group ID does not exist or has been removed.
          </p>
          <Button
            variant="outline"
            onClick={() => router.push("/correlation")}
          >
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Correlation
          </Button>
        </div>
      </DashboardLayout>
    )
  }

  // Sort events chronologically (earliest first)
  const sortedEvents = [...group.events].sort(
    (a, b) =>
      new Date(a.ingested_at ?? 0).getTime() - new Date(b.ingested_at ?? 0).getTime(),
  )

  // Confidence breakdown calculations
  const totalWeight = sortedEvents.reduce((sum, e) => sum + e.source_weight, 0)
  const confidenceRows = sortedEvents.map((e) => {
    const rawConfidence = e.confidence ?? 0
    const weightedContribution =
      totalWeight > 0 ? (rawConfidence * e.source_weight) / totalWeight : 0
    return {
      source: e.source,
      event_id: e.event_id,
      rawConfidence,
      weight: e.source_weight,
      weightedContribution,
    }
  })

  // Distinct source count for corroboration
  const distinctSources = new Set(sortedEvents.map((e) => e.source)).size
  const minSources = correlationConfig?.min_sources ?? 1

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* ── Header ────────────────────────────────────────── */}
        <div>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.push("/correlation")}
            className="-ml-3 mb-2 text-muted-foreground"
          >
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Correlation
          </Button>

          <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
            <div>
              <div className="flex items-center gap-3 mt-1">
                {statusBadge(group.status, group.corroboration_met)}
                <Link
                  href={`/ip-history?ip=${encodeURIComponent(group.victim_ip)}`}
                  className="text-2xl font-bold font-mono tracking-tight text-primary hover:underline"
                >
                  {group.victim_ip}
                </Link>
              </div>
              <div className="flex items-center gap-2 mt-2">
                <Badge
                  variant="outline"
                  className="font-mono text-muted-foreground"
                >
                  {group.vector.replace(/_/g, " ")}
                </Badge>
                <span className="text-xs text-muted-foreground font-mono">
                  {group.source_count} source{group.source_count !== 1 ? "s" : ""}
                </span>
              </div>
            </div>

            <div className="text-right text-xs font-mono text-muted-foreground space-y-1">
              <div>Created: {formatTimestamp(group.created_at)}</div>
              <div>
                Window:{" "}
                {group.status === "open"
                  ? `Expires ${formatTimestamp(group.window_expires_at)}`
                  : group.status === "expired"
                    ? `Expired ${formatTimestamp(group.window_expires_at)}`
                    : `Closed ${formatTimestamp(group.window_expires_at)}`}
              </div>
              <div className="text-[10px] break-all">ID: {group.group_id}</div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* ── Main Column ─────────────────────────────────── */}
          <div className="lg:col-span-2 space-y-6">
            {/* Contributing Events Timeline */}
            <Card className="border-border shadow-sm">
              <CardHeader className="pb-4">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">
                    Contributing Events
                  </CardTitle>
                  <Badge variant="secondary" className="text-[10px] ml-auto">
                    {sortedEvents.length} event{sortedEvents.length !== 1 ? "s" : ""}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                {sortedEvents.length === 0 ? (
                  <p className="text-sm text-muted-foreground italic">
                    No contributing events recorded.
                  </p>
                ) : (
                  <div className="space-y-6 pl-4 border-l-2 border-muted relative">
                    {sortedEvents.map((event, idx) => (
                      <div key={event.event_id} className="relative">
                        <div
                          className={`absolute -left-[21px] top-1 h-3 w-3 rounded-full ${sourceColor(event.source)}`}
                        />
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge
                              variant="outline"
                              className="text-[10px] font-mono"
                            >
                              {event.source}
                            </Badge>
                            {event.is_corroborating && (
                              <Badge
                                variant="secondary"
                                className="text-[10px] font-mono bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30"
                                title="Corroborating signal — strengthened the group but cannot trigger mitigations alone"
                              >
                                corroborating
                              </Badge>
                            )}
                            <span className="text-xs text-muted-foreground tabular-nums">
                              Confidence:{" "}
                              {event.confidence != null
                                ? `${Math.round(event.confidence * 100)}%`
                                : "N/A"}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground font-mono mt-1">
                            {event.ingested_at ? formatTimestamp(event.ingested_at) : "Unknown ingest time"}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            Event{" "}
                            <Link
                              href={`/events?id=${encodeURIComponent(event.event_id)}`}
                              className="font-mono text-primary hover:underline"
                            >
                              {event.event_id.slice(0, 8)}
                            </Link>
                            <span className="text-muted-foreground/60 ml-2">
                              weight: {event.source_weight.toFixed(1)}
                            </span>
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Confidence Breakdown */}
            <Card className="border-border shadow-sm">
              <CardHeader className="pb-4">
                <div className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">
                    Confidence Breakdown
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs font-mono">
                    <thead>
                      <tr className="border-b border-border text-left text-muted-foreground">
                        <th className="pb-2 pr-3 font-medium">Source</th>
                        <th className="pb-2 pr-3 font-medium text-right">
                          Raw Confidence
                        </th>
                        <th className="pb-2 pr-3 font-medium text-right">
                          Weight
                        </th>
                        <th className="pb-2 font-medium text-right">
                          Weighted Contribution
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {confidenceRows.map((row) => (
                        <tr
                          key={row.event_id}
                          className="border-b border-border/50 last:border-0"
                        >
                          <td className="py-2 pr-3">
                            <div className="flex items-center gap-2">
                              <div
                                className={`h-2 w-2 rounded-full ${sourceColor(row.source)}`}
                              />
                              {row.source}
                            </div>
                          </td>
                          <td className="py-2 pr-3 text-right tabular-nums">
                            {Math.round(row.rawConfidence * 100)}%
                          </td>
                          <td className="py-2 pr-3 text-right tabular-nums">
                            {row.weight.toFixed(1)}
                          </td>
                          <td className="py-2 text-right tabular-nums">
                            {Math.round(row.weightedContribution * 100)}%
                          </td>
                        </tr>
                      ))}
                    </tbody>
                    <tfoot>
                      <tr className="border-t border-border font-semibold">
                        <td className="pt-2 pr-3">Derived Total</td>
                        <td className="pt-2 pr-3 text-right" />
                        <td className="pt-2 pr-3 text-right tabular-nums">
                          {totalWeight.toFixed(1)}
                        </td>
                        <td className="pt-2 text-right tabular-nums">
                          {Math.round(group.derived_confidence * 100)}%
                        </td>
                      </tr>
                    </tfoot>
                  </table>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* ── Sidebar Column ──────────────────────────────── */}
          <div className="space-y-6">
            {/* Corroboration Badge */}
            <Card className="border-border shadow-sm">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Layers className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">
                    Corroboration
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                {group.corroboration_met ? (
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-5 w-5 text-green-600 dark:text-green-400" />
                    <div>
                      <p className="text-sm font-medium text-green-700 dark:text-green-400">
                        Corroborated
                      </p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {distinctSources} of {minSources} required source{minSources !== 1 ? "s" : ""} confirmed
                      </p>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-amber-500 dark:text-amber-400" />
                    <div>
                      <p className="text-sm font-medium text-amber-600 dark:text-amber-400">
                        Pending Corroboration {distinctSources}/{minSources}
                      </p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        {minSources - distinctSources} more distinct source{(minSources - distinctSources) !== 1 ? "s" : ""} needed
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Linked Mitigation */}
            <Card className="border-border shadow-sm">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Link2 className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">
                    Linked Mitigation
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                {group.mitigation_id ? (
                  <div className="space-y-2">
                    <Link
                      href={`/mitigations/${group.mitigation_id}`}
                      className="block p-3 rounded-md border border-border hover:bg-muted/50 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono text-primary">
                          {group.mitigation_id.slice(0, 8)}…
                        </span>
                        <Badge
                          variant="default"
                          className="text-[10px] bg-green-600 hover:bg-green-600"
                        >
                          Active
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground mt-1">
                        Mitigation created from this signal group
                      </p>
                    </Link>
                  </div>
                ) : (
                  <div className="flex items-start gap-2">
                    <Info className="h-4 w-4 text-muted-foreground mt-0.5 flex-shrink-0" />
                    <div>
                      <p className="text-sm text-muted-foreground">
                        No mitigation created
                      </p>
                      <p className="text-xs text-muted-foreground/70 mt-1">
                        {group.status === "open"
                          ? "Corroboration threshold has not been met yet. A mitigation will be created when enough distinct sources confirm this attack."
                          : group.status === "expired"
                            ? "The correlation window expired before corroboration was achieved. No mitigation was triggered."
                            : "No linked mitigation is available for this signal group."}
                      </p>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Confidence Summary */}
            <Card className="border-border shadow-sm bg-secondary/10">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <BarChart3 className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">
                    Summary
                  </CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground mb-1">
                    Derived Confidence
                  </p>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full rounded-full bg-primary transition-all"
                        style={{
                          width: `${Math.round(group.derived_confidence * 100)}%`,
                        }}
                      />
                    </div>
                    <span className="text-sm font-mono font-medium tabular-nums">
                      {Math.round(group.derived_confidence * 100)}%
                    </span>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">
                    Distinct Sources
                  </p>
                  <p className="text-sm font-mono">{distinctSources}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">
                    Confidence Threshold
                  </p>
                  <p className="text-sm font-mono">
                    {correlationConfig
                      ? `${Math.round(correlationConfig.confidence_threshold * 100)}%`
                      : "—"}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">
                    Min Sources Required
                  </p>
                  <p className="text-sm font-mono">{minSources}</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </DashboardLayout>
  )
}
