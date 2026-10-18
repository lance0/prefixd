"use client"

import { formatConfidence } from "@/lib/confidence"
import { useState } from "react"
import { useSearchParams, useRouter } from "next/navigation"
import Link from "next/link"
import { useIpHistory } from "@/hooks/use-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Search, AlertTriangle, Shield, FileText } from "lucide-react"
import { PageHeader } from "@/components/dashboard/page-header"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { Tag } from "@/components/dashboard/status-pill"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { formatBps, formatUtc } from "@/lib/format"
import type { Mitigation } from "@/lib/api"
import { IncidentReportDialog } from "@/components/dashboard/incident-report-dialog"
import { getIncidentReport } from "@/lib/api"

type TimelineEntry =
  | { type: "event"; timestamp: string; data: { event_id: string; source: string; vector: string; bps: number | null; pps: number | null; confidence: number | null } }
  | { type: "mitigation"; timestamp: string; data: { mitigation_id: string; status: Mitigation["status"]; action_type: string; rate_bps: number | null; vector: string; created_at: string; withdrawn_at: string | null; expires_at: string } }

export default function IpHistoryPage() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const initialIp = searchParams.get("ip") || ""
  const [searchInput, setSearchInput] = useState(initialIp)
  const [activeIp, setActiveIp] = useState(initialIp)
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null)
  const [showReportDialog, setShowReportDialog] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)

  const { data, isLoading, error } = useIpHistory(activeIp || null)

  const handleGenerateReport = async () => {
    if (!activeIp) return
    setShowReportDialog(true)
    setReportLoading(true)
    try {
      const md = await getIncidentReport({ ip: activeIp })
      setReportMarkdown(md)
    } catch {
      setReportMarkdown(null)
    } finally {
      setReportLoading(false)
    }
  }

  function handleSearch(e: React.FormEvent) {
    e.preventDefault()
    const trimmed = searchInput.trim()
    if (trimmed) {
      setActiveIp(trimmed)
      router.replace(`/ip-history?ip=${encodeURIComponent(trimmed)}`)
    }
  }

  const timeline: TimelineEntry[] = []
  if (data) {
    for (const ev of data.events) {
      timeline.push({
        type: "event",
        timestamp: ev.event_timestamp,
        data: {
          event_id: ev.event_id,
          source: ev.source,
          vector: ev.vector,
          bps: ev.bps,
          pps: ev.pps,
          confidence: ev.confidence,
        },
      })
    }
    for (const m of data.mitigations) {
      timeline.push({
        type: "mitigation",
        timestamp: m.created_at,
        data: {
          mitigation_id: m.mitigation_id,
          status: m.status,
          action_type: m.action_type,
          rate_bps: m.rate_bps,
          vector: m.vector,
          created_at: m.created_at,
          withdrawn_at: m.withdrawn_at,
          expires_at: m.expires_at,
        },
      })
    }
    timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }

  return (
    <>
      <div className="space-y-6">
        <PageHeader
          title="IP history"
          description="Every event and mitigation recorded for one address, newest first."
          actions={activeIp ? (
            <Button variant="outline" size="sm" onClick={handleGenerateReport}>
              <FileText className="size-4" aria-hidden="true" />
              Report
            </Button>
          ) : null}
        />

        <form onSubmit={handleSearch} className="flex max-w-md gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              placeholder="203.0.113.10"
              aria-label="IP address"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="h-9 pl-9 font-mono text-base sm:text-sm"
              spellCheck={false}
              autoComplete="off"
              inputMode="text"
            />
          </div>
          <Button type="submit" size="sm" className="h-9">
            Look up
          </Button>
        </form>

        {!activeIp && (
          <div className="rounded-md border bg-card">
            <EmptyState title="No address selected" description="Enter an IP address above, or open one from a mitigation or event." />
          </div>
        )}

        {activeIp && isLoading && (
          <div className="rounded-md border bg-card"><LoadingRows label={`Loading history for ${activeIp}`} /></div>
        )}

        {activeIp && error && !isLoading && (
          <div className="rounded-md border bg-card">
            <ErrorState
              title={`Unable to load history for ${activeIp}`}
              detail={error instanceof Error && error.message.includes("400")
                ? "Enter a valid IP address and try again."
                : "Retry, or check that the controller API is reachable."}
            />
          </div>
        )}

        {data && (
          <section aria-label={`History for ${activeIp}`} className="overflow-hidden rounded-md border bg-card">
            {(data.customer || data.service) && (
              <div className="flex flex-wrap items-center gap-x-6 gap-y-2 border-b px-4 py-3 text-sm">
                {data.customer && (
                  <span className="flex items-center gap-2">
                    <span className="text-muted-foreground">Customer</span>
                    <span className="font-medium">{data.customer.name}</span>
                    <Tag>{data.customer.policy_profile}</Tag>
                  </span>
                )}
                {data.service && (
                  <span className="flex items-center gap-2">
                    <span className="text-muted-foreground">Service</span>
                    <span className="font-medium">{data.service.name}</span>
                  </span>
                )}
              </div>
            )}

            {timeline.length === 0 ? (
              <EmptyState title="No history" description={`No events or mitigations are recorded for ${activeIp}.`} />
            ) : (
              <ol className="divide-y">
                {timeline.map((entry, i) => (
                  <li key={i} className="flex flex-col gap-1 px-4 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
                    <div className="min-w-0 space-y-1">
                      <div className="flex flex-wrap items-center gap-2">
                        {entry.type === "event" ? (
                          <>
                            <AlertTriangle className="size-3.5 text-muted-foreground" aria-hidden="true" />
                            <span className="text-sm font-medium">Event</span>
                            <Tag>{entry.data.vector.replace(/_/g, " ")}</Tag>
                          </>
                        ) : (
                          <>
                            <Shield className="size-3.5 text-muted-foreground" aria-hidden="true" />
                            <Link href={`/mitigations/${entry.data.mitigation_id}`} className="rounded-sm text-sm font-medium hover:underline">
                              Mitigation
                            </Link>
                            <StatusBadge status={entry.data.status} />
                            <ActionBadge actionType={entry.data.action_type} rateBps={entry.data.rate_bps} />
                          </>
                        )}
                      </div>
                      <p className="text-xs text-muted-foreground tabular-nums">
                        {entry.type === "event" ? (
                          <>
                            {entry.data.source}
                            {entry.data.bps ? <> · {formatBps(entry.data.bps)}</> : null}
                            {" · "}<span>Confidence: {formatConfidence(entry.data.confidence)}</span>
                          </>
                        ) : (
                          <>
                            {entry.data.vector.replace(/_/g, " ")}
                            {entry.data.withdrawn_at && <> · withdrawn {formatUtc(entry.data.withdrawn_at)}</>}
                          </>
                        )}
                      </p>
                    </div>
                    <time dateTime={entry.timestamp} className="shrink-0 text-xs text-muted-foreground tabular-nums">
                      {formatUtc(entry.timestamp)}
                    </time>
                  </li>
                ))}
              </ol>
            )}
          </section>
        )}
      </div>

      <IncidentReportDialog
        markdown={reportMarkdown}
        filename={`incident-${activeIp}.md`}
        open={showReportDialog}
        onOpenChange={setShowReportDialog}
        loading={reportLoading}
      />
    </>
  )
}
