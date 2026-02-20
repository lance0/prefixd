"use client"

import { useState } from "react"
import { useSearchParams, useRouter } from "next/navigation"
import Link from "next/link"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { useIpHistory } from "@/hooks/use-api"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Search, AlertTriangle, Shield, ArrowRight, User, Server } from "lucide-react"

function formatDate(iso: string) {
  return new Date(iso).toLocaleString()
}

function formatBps(bps: number | null) {
  if (!bps) return null
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(1)} Gbps`
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`
  return `${(bps / 1e3).toFixed(0)} Kbps`
}

type TimelineEntry =
  | { type: "event"; timestamp: string; data: { event_id: string; source: string; vector: string; bps: number | null; pps: number | null; confidence: number | null } }
  | { type: "mitigation"; timestamp: string; data: { mitigation_id: string; status: string; action_type: string; vector: string; created_at: string; withdrawn_at: string | null; expires_at: string } }

export default function IpHistoryPage() {
  const searchParams = useSearchParams()
  const router = useRouter()
  const initialIp = searchParams.get("ip") || ""
  const [searchInput, setSearchInput] = useState(initialIp)
  const [activeIp, setActiveIp] = useState(initialIp)

  const { data, isLoading } = useIpHistory(activeIp || null)

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
          vector: m.vector,
          created_at: m.created_at,
          withdrawn_at: m.withdrawn_at,
          expires_at: m.expires_at,
        },
      })
    }
    timeline.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  }

  const statusColors: Record<string, string> = {
    active: "bg-green-500/10 text-green-500 border-green-500/20",
    escalated: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    withdrawn: "bg-muted text-muted-foreground border-border",
    expired: "bg-muted text-muted-foreground border-border",
  }

  return (
    <DashboardLayout>
      <div className="space-y-4">
        <div>
          <h1 className="text-lg font-semibold">IP History</h1>
          <p className="text-sm text-muted-foreground">
            View all events and mitigations for an IP address
          </p>
        </div>

        <form onSubmit={handleSearch} className="flex gap-2 max-w-md">
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Enter IP address..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              className="pl-9"
            />
          </div>
          <Button type="submit" size="default">
            Lookup
          </Button>
        </form>

        {!activeIp && (
          <div className="border border-border bg-card rounded-lg p-8 text-center text-muted-foreground text-sm">
            Enter an IP address above to view its history
          </div>
        )}

        {activeIp && isLoading && (
          <div className="border border-border bg-card rounded-lg p-8 text-center text-muted-foreground text-sm">
            Loading history for {activeIp}...
          </div>
        )}

        {data && (
          <>
            {(data.customer || data.service) && (
              <div className="border border-border bg-card rounded-lg p-4 flex flex-wrap gap-4">
                {data.customer && (
                  <div className="flex items-center gap-2">
                    <User className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm font-medium">{data.customer.name}</span>
                    <Badge variant="outline" className="text-[10px]">
                      {data.customer.policy_profile}
                    </Badge>
                  </div>
                )}
                {data.service && (
                  <div className="flex items-center gap-2">
                    <Server className="h-4 w-4 text-muted-foreground" />
                    <span className="text-sm">{data.service.name}</span>
                  </div>
                )}
              </div>
            )}

            {timeline.length === 0 ? (
              <div className="border border-border bg-card rounded-lg p-8 text-center text-muted-foreground text-sm">
                No events or mitigations found for {activeIp}
              </div>
            ) : (
              <div className="relative border-l-2 border-border ml-4 space-y-0">
                {timeline.map((entry, i) => (
                  <div key={i} className="relative pl-6 pb-4">
                    <div className="absolute -left-[9px] top-1.5 size-4 rounded-full border-2 border-background flex items-center justify-center"
                      style={{
                        backgroundColor: entry.type === "event"
                          ? "var(--color-chart-2)"
                          : "var(--color-chart-1)",
                      }}
                    />
                    <div className="border border-border bg-card rounded-lg p-3">
                      <div className="flex items-center justify-between mb-1">
                        <div className="flex items-center gap-2">
                          {entry.type === "event" ? (
                            <>
                              <AlertTriangle className="h-3.5 w-3.5 text-chart-2" />
                              <span className="text-xs font-medium">Event</span>
                              <Badge variant="outline" className="text-[10px]">
                                {entry.data.vector.replace(/_/g, " ")}
                              </Badge>
                            </>
                          ) : (
                            <>
                              <Shield className="h-3.5 w-3.5 text-chart-1" />
                              <span className="text-xs font-medium">Mitigation</span>
                              <Badge variant="outline" className={`text-[10px] ${statusColors[entry.data.status] || ""}`}>
                                {entry.data.status}
                              </Badge>
                              <Badge variant="outline" className="text-[10px]">
                                {entry.data.action_type}
                              </Badge>
                            </>
                          )}
                        </div>
                        <span className="text-[10px] text-muted-foreground">
                          {formatDate(entry.timestamp)}
                        </span>
                      </div>

                      <div className="flex items-center justify-between">
                        <div className="text-xs text-muted-foreground space-x-3">
                          {entry.type === "event" ? (
                            <>
                              <span>src: {entry.data.source}</span>
                              {entry.data.bps && <span>{formatBps(entry.data.bps)}</span>}
                              {entry.data.confidence != null && (
                                <span>{(entry.data.confidence * 100).toFixed(0)}% confidence</span>
                              )}
                            </>
                          ) : (
                            <>
                              <span>{entry.data.vector.replace(/_/g, " ")}</span>
                              {entry.data.withdrawn_at && (
                                <span>withdrawn {formatDate(entry.data.withdrawn_at)}</span>
                              )}
                            </>
                          )}
                        </div>
                        {entry.type === "mitigation" && (
                          <Link
                            href={`/mitigations/${entry.data.mitigation_id}`}
                            className="text-xs text-primary hover:underline flex items-center gap-1"
                          >
                            Detail <ArrowRight className="h-3 w-3" />
                          </Link>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </DashboardLayout>
  )
}
