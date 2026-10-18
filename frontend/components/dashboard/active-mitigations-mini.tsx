"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { ArrowRight } from "lucide-react"
import { ActionBadge } from "./action-badge"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import type { Mitigation } from "@/lib/api"
import { formatConfidence } from "@/lib/confidence"
import { formatTimeRemaining } from "@/lib/format"

interface ActiveMitigationsMiniProps {
  mitigations: Mitigation[]
  limit?: number
  loading?: boolean
  error?: boolean
  hasMore?: boolean
  onRetry?: () => void
}

export { formatTimeRemaining }

export function formatSourceCount(value?: number): string {
  return value !== undefined && Number.isInteger(value) && value >= 0
    ? `${value} ${value === 1 ? "source" : "sources"}`
    : "Sources unavailable"
}

function expiryDeadline(value: string): string {
  const date = new Date(value)
  return Number.isFinite(date.getTime())
    ? date.toLocaleString("en-GB", { day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit", timeZone: "UTC" }) + " UTC"
    : "Deadline unavailable"
}

export function ActiveMitigationsMini({ mitigations, limit = 8, loading, error, hasMore, onRetry }: ActiveMitigationsMiniProps) {
  const [now, setNow] = useState<number | null>(null)
  useEffect(() => {
    const update = () => setNow(Date.now())
    update()
    const interval = setInterval(update, 15_000)
    return () => clearInterval(interval)
  }, [])
  const loaded = mitigations.filter(m => m.status === "active" || m.status === "escalated")
  const active = loaded.slice(0, limit)

  return (
    <section aria-labelledby="active-mitigations-heading" className="overflow-hidden rounded-lg border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-4">
        <div>
          <h2 id="active-mitigations-heading" className="font-semibold text-balance">Active mitigations</h2>
          <p className="mt-1 text-[13px] text-muted-foreground text-pretty">Saved intent. Router installation is unobserved.</p>
        </div>
        <Link href="/mitigations?status=active" className="inline-flex items-center gap-1.5 rounded-sm text-[13px] font-medium text-primary hover:underline">View all<ArrowRight className="size-3.5" aria-hidden="true" /></Link>
      </div>

      {error ? (
        <div role="alert" className="space-y-3 p-6">
          <p className="font-medium">Unable to load mitigations</p>
          <p className="text-muted-foreground text-pretty">Active intent could not be refreshed. This does not mean there are no rules.</p>
          {onRetry ? <Button variant="outline" size="sm" onClick={onRetry}>Retry mitigations</Button> : null}
        </div>
      ) : loading ? (
        <div role="status" aria-label="Loading active mitigations" className="divide-y">
          {[0, 1, 2].map(row => <div key={row} className="flex gap-6 p-5"><Skeleton className="h-10 w-1/3" /><Skeleton className="h-10 flex-1" /><Skeleton className="h-10 w-20" /></div>)}
        </div>
      ) : active.length === 0 ? (
        <div className="space-y-2 p-6">
          <p className="font-medium">No active mitigations</p>
          <p className="text-muted-foreground text-pretty">New mitigation intent will appear here.</p>
          <Link href="/events" className="inline-block rounded-sm text-primary hover:underline">Review incoming events</Link>
        </div>
      ) : (
        <>
          <table className="w-full text-left text-[13px]">
            <thead className="sr-only xl:not-sr-only">
              <tr className="border-b bg-muted/40 text-xs text-muted-foreground">
                <th scope="col" className="px-4 py-2.5 font-medium">Target</th>
                <th scope="col" className="px-4 py-2.5 font-medium">Action</th>
                <th scope="col" className="px-4 py-2.5 font-medium">Signal & reason</th>
                <th scope="col" className="px-4 py-2.5 font-medium">Router installation</th>
                <th scope="col" className="px-4 py-2.5 font-medium">Expires</th>
              </tr>
            </thead>
            <tbody className="divide-y">
              {active.map(m => (
                <tr key={m.mitigation_id} className="grid grid-cols-2 gap-y-3 py-4 hover:bg-muted/30 xl:table-row xl:py-0">
                  <td className="col-span-2 px-4 align-top xl:w-1/5 xl:py-4">
                    <Link href={`/mitigations/${m.mitigation_id}`} className="break-all rounded-sm font-mono font-medium text-primary hover:underline">{m.dst_prefix}</Link>
                    <div className="mt-1 text-xs text-muted-foreground">{m.pop} · {m.status}</div>
                  </td>
                  <td className="px-4 align-top xl:py-4"><span className="mb-1 block text-xs text-muted-foreground xl:hidden">Action</span><ActionBadge actionType={m.action_type} rateBps={m.rate_bps} /></td>
                  <td className="col-span-2 row-start-2 px-4 align-top xl:w-1/3 xl:py-4">
                    <div className="font-medium">{m.vector === "unknown" ? "Unclassified signal" : m.vector.replace(/_/g, " ")}</div>
                    <p className="mt-1 line-clamp-2 text-muted-foreground text-pretty">{m.reason.trim() || "Reason unavailable"}</p>
                    <div className="mt-1 text-xs text-muted-foreground tabular-nums">{formatSourceCount(m.correlation?.source_count)} · Confidence: {formatConfidence(m.correlation?.derived_confidence)}</div>
                  </td>
                  <td className="px-4 align-top xl:py-4"><span className="mb-1 block text-xs text-muted-foreground xl:hidden">Router installation</span><span className="text-muted-foreground">Unobserved</span></td>
                  <td className="col-span-2 px-4 align-top xl:py-4">
                    <span className="mb-1 block text-xs text-muted-foreground xl:hidden">Expires</span>
                    <div className="font-mono font-medium">{now === null ? "Calculating…" : formatTimeRemaining(m.expires_at, now)}</div>
                    <time dateTime={m.expires_at} className="mt-1 block whitespace-nowrap text-xs text-muted-foreground tabular-nums">{expiryDeadline(m.expires_at)}</time>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="flex flex-wrap justify-between gap-2 border-t px-4 py-3 text-xs text-muted-foreground">
            <span className="tabular-nums">Showing {active.length} of {loaded.length} loaded{hasMore ? " · more available" : ""}</span>
            <span>Expiry needs the running controller. Sessions do not confirm rule installation.</span>
          </div>
        </>
      )}
    </section>
  )
}
