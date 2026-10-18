"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { ArrowRight } from "lucide-react"
import { ActionBadge } from "./action-badge"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import type { Mitigation } from "@/lib/api"
import { formatConfidence } from "@/lib/confidence"
import { formatTimeRemaining, formatUtc } from "@/lib/format"

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
    <section aria-labelledby="active-mitigations-heading" className="overflow-hidden rounded-md border bg-card">
      <div className="flex flex-wrap items-center justify-between gap-3 border-b px-4 py-3">
        <div>
          <h2 id="active-mitigations-heading" className="text-sm font-semibold text-balance">Active mitigations</h2>
          <p className="mt-0.5 text-sm text-muted-foreground text-pretty">Saved intent. Router installation is unobserved.</p>
        </div>
        <Link href="/mitigations?status=active" className="inline-flex items-center gap-1.5 rounded-sm text-sm font-medium text-primary hover:underline">View all<ArrowRight className="size-3.5" aria-hidden="true" /></Link>
      </div>

      {error ? (
        <ErrorState
          title="Unable to load mitigations"
          detail="Active intent could not be refreshed. This does not mean there are no rules."
          onRetry={onRetry}
          retryLabel="Retry mitigations"
        />
      ) : loading ? (
        <LoadingRows label="Loading active mitigations" />
      ) : active.length === 0 ? (
        <EmptyState
          title="No active mitigations"
          description="New mitigation intent will appear here."
          action={<Link href="/events" className="rounded-sm text-sm text-primary hover:underline">Review incoming events</Link>}
        />
      ) : (
        <>
          <table className="w-full text-left text-sm">
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
                    <Link href={`/mitigations/${m.mitigation_id}`} className="break-all rounded-sm font-mono font-medium hover:underline">{m.dst_prefix}</Link>
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
                    <div className="font-medium tabular-nums">{now === null ? "Calculating…" : formatTimeRemaining(m.expires_at, now)}</div>
                    <time dateTime={m.expires_at} className="mt-1 block whitespace-nowrap text-xs text-muted-foreground tabular-nums">{formatUtc(m.expires_at, now ?? undefined)}</time>
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
