"use client"

import { useState, useCallback } from "react"
import { useSearchParams, useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { useSignalGroupsPaginated } from "@/hooks/use-api"
import { Loader2 } from "lucide-react"
import { SignalGroupStatusBadge } from "./signals-tab"
import { MISSING, formatRelative, formatUtc } from "@/lib/format"
import { formatConfidence, isConfidence } from "@/lib/confidence"

const STATUS_OPTIONS = [
  { value: "all", label: "All statuses" },
  { value: "open", label: "Open" },
  { value: "resolved", label: "Resolved" },
  { value: "expired", label: "Expired" },
]

const VECTOR_OPTIONS = [
  { value: "all", label: "All vectors" },
  { value: "udp_flood", label: "UDP flood" },
  { value: "syn_flood", label: "SYN flood" },
  { value: "ntp_amplification", label: "NTP amplification" },
  { value: "dns_amplification", label: "DNS amplification" },
  { value: "memcached_amplification", label: "Memcached amplification" },
  { value: "ssdp_amplification", label: "SSDP amplification" },
  { value: "icmp_flood", label: "ICMP flood" },
]

export function GroupsTab() {
  const searchParams = useSearchParams()
  const router = useRouter()

  // Read filters from URL params with sensible defaults
  const [status, setStatus] = useState(searchParams.get("status") || "open")
  const [vector, setVector] = useState(searchParams.get("vector") || "all")

  // Sync URL params when filters change
  const updateUrlParams = useCallback(
    (newStatus: string, newVector: string) => {
      const params = new URLSearchParams()
      if (newStatus !== "open") params.set("status", newStatus)
      if (newVector !== "all") params.set("vector", newVector)
      const query = params.toString()
      router.replace(`/correlation${query ? `?${query}` : ""}`, { scroll: false })
    },
    [router],
  )

  const handleStatusChange = (val: string) => {
    setStatus(val)
    updateUrlParams(val, vector)
  }

  const handleVectorChange = (val: string) => {
    setVector(val)
    updateUrlParams(status, val)
  }

  const clearFilters = () => {
    setStatus("open")
    setVector("all")
    updateUrlParams("open", "all")
  }

  const hasActiveFilters = status !== "open" || vector !== "all"

  const filterParams = {
    status: status === "all" ? undefined : status,
    vector: vector === "all" ? undefined : vector,
    limit: 25,
  }

  const { data, error, isLoading, isValidating, size, setSize, mutate } = useSignalGroupsPaginated(filterParams)

  const groups = data ? data.flatMap((page) => page.groups) : []
  const hasMore = data ? data[data.length - 1]?.has_more ?? false : false
  const isLoadingMore = isValidating && size > 1

  return (
    <section aria-label="Signal groups" className="overflow-hidden rounded-md border bg-card">
      <div className="flex flex-wrap items-center gap-2 border-b p-3">
        <Select value={status} onValueChange={handleStatusChange}>
          <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Status">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {STATUS_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={vector} onValueChange={handleVectorChange}>
          <SelectTrigger className="h-9 w-full sm:w-52" aria-label="Vector">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {VECTOR_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value}>
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={clearFilters} className="text-muted-foreground">
            Clear filters
          </Button>
        )}
      </div>

      {isLoading ? (
        <LoadingRows label="Loading signal groups" rows={5} />
      ) : error ? (
        <ErrorState
          title="Unable to load signal groups"
          detail="Signal groups could not be refreshed. Correlation continues on the controller; retry to reload this list."
          onRetry={() => { void mutate() }}
        />
      ) : groups.length === 0 ? (
        <EmptyState
          title={hasActiveFilters ? "No matching signal groups" : "No signal groups yet"}
          description={hasActiveFilters ? "Nothing matches this status and vector. Clear the filters to see every group." : "Signal groups will appear here when events are correlated."}
          action={hasActiveFilters ? <Button variant="outline" size="sm" onClick={clearFilters}>Clear filters</Button> : undefined}
        />
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead>Status</TableHead>
                <TableHead>Victim IP</TableHead>
                <TableHead>Vector</TableHead>
                <TableHead className="text-right">Confidence</TableHead>
                <TableHead className="text-right">Sources</TableHead>
                <TableHead className="text-right">Created</TableHead>
                <TableHead className="text-right">Window</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {groups.map((group) => (
                <TableRow key={group.group_id}>
                  <TableCell>
                    <SignalGroupStatusBadge status={group.status} corroborated={group.corroboration_met} />
                  </TableCell>
                  <TableCell>
                    <Link href={`/correlation/groups/${group.group_id}`} className="rounded-sm font-mono hover:underline">
                      {group.victim_ip}
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{group.vector.replace(/_/g, " ")}</TableCell>
                  <TableCell numeric>
                    <ConfidenceDisplay confidence={group.derived_confidence} />
                  </TableCell>
                  <TableCell numeric>{group.source_count}</TableCell>
                  <TableCell numeric className="text-muted-foreground">
                    <time dateTime={group.created_at} title={formatUtc(group.created_at)}>{formatRelative(group.created_at)}</time>
                  </TableCell>
                  <TableCell numeric className="text-muted-foreground">
                    {group.status === "open"
                      ? <>
                          <time dateTime={group.window_expires_at} className="text-foreground">{formatRelative(group.window_expires_at)}</time>
                          <span className="block whitespace-nowrap text-xs">{formatUtc(group.window_expires_at)}</span>
                        </>
                      : MISSING}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>

          {hasMore && (
            <div className="border-t p-3">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSize(size + 1)}
                disabled={isLoadingMore}
                className="w-full"
              >
                {isLoadingMore ? (
                  <>
                    <Loader2 className="size-3.5 animate-spin" aria-hidden="true" />
                    Loading…
                  </>
                ) : (
                  "Load more"
                )}
              </Button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

/** Below 50% reads as a warning; 80% and above is emphasised. Confidence is evidence, not status. */
function ConfidenceDisplay({ confidence }: { confidence: number }) {
  let colorClass = "text-muted-foreground"
  if (isConfidence(confidence)) {
    if (confidence >= 0.8) colorClass = "font-medium text-foreground"
    else if (confidence >= 0.5) colorClass = "text-foreground"
    else colorClass = "text-warning"
  }

  return <span className={colorClass}>{formatConfidence(confidence)}</span>
}
