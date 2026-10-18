"use client"

import { Fragment, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { Search, ChevronDown, ChevronUp, RefreshCw, Download } from "lucide-react"
import { ActorBadge } from "@/components/dashboard/actor-badge"
import { StatusPill, Tag, auditActionTone } from "@/components/dashboard/status-pill"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { MISSING, formatUtc } from "@/lib/format"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAuditLog } from "@/hooks/use-api"
import type { AuditEntry } from "@/lib/api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"

type SortField = "timestamp" | "actor" | "action" | "target"

type SortDirection = "asc" | "desc"

function AuditRow({ entry, isExpanded, onToggle }: {
  entry: AuditEntry
  isExpanded: boolean
  onToggle: () => void
}) {
  const detailsStr = JSON.stringify(entry.details)
  const isTruncated = detailsStr.length > 50
  const tone = auditActionTone(entry.action)

  return (
    <Fragment>
      <TableRow
        data-state={isExpanded ? "selected" : undefined}
        className={cn(isTruncated && "cursor-pointer")}
        onClick={onToggle}
      >
        <TableCell className="whitespace-nowrap text-muted-foreground tabular-nums">
          <time dateTime={entry.timestamp}>{formatUtc(entry.timestamp)}</time>
        </TableCell>
        <TableCell>
          <ActorBadge type={entry.actor_type} name={entry.actor_id || "system"} />
        </TableCell>
        <TableCell>
          {tone === "neutral" ? <Tag>{entry.action}</Tag> : <StatusPill tone={tone}>{entry.action}</StatusPill>}
        </TableCell>
        <TableCell className="font-mono">
          {entry.target_id ? (
            entry.target_type === "mitigation" ? (
              <Link
                href={`/mitigations/${entry.target_id}`}
                className="inline-block max-w-[200px] truncate rounded-sm hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                {entry.target_id.slice(0, 8)}
              </Link>
            ) : (
              <span className="inline-block max-w-[200px] truncate" title={entry.target_id}>
                {entry.target_id.length > 20 ? `${entry.target_id.slice(0, 20)}…` : entry.target_id}
              </span>
            )
          ) : (
            <span className="text-muted-foreground">{MISSING}</span>
          )}
        </TableCell>
        <TableCell className="max-w-[300px] text-muted-foreground">
          <span className="flex items-center gap-1">
            <span className="truncate font-mono text-xs">{detailsStr}</span>
            {isTruncated ? (
              <button
                type="button"
                aria-expanded={isExpanded}
                aria-label={isExpanded ? "Hide details" : "Show details"}
                className="shrink-0 rounded-sm p-1 hover:bg-muted hover:text-foreground"
                onClick={(e) => { e.stopPropagation(); onToggle() }}
              >
                {isExpanded ? <ChevronUp className="size-3.5" aria-hidden="true" /> : <ChevronDown className="size-3.5" aria-hidden="true" />}
              </button>
            ) : null}
          </span>
        </TableCell>
      </TableRow>
      {isExpanded && (
        <TableRow className="hover:bg-transparent">
          <TableCell colSpan={5} className="py-3">
            <pre className="max-h-[300px] overflow-auto whitespace-pre-wrap rounded-md bg-muted/50 p-3 font-mono text-xs">
              {JSON.stringify(entry.details, null, 2)}
            </pre>
          </TableCell>
        </TableRow>
      )}
    </Fragment>
  )
}

export function AuditLogContentLive() {
  const [actionFilter, setActionFilter] = useState<string>("All")
  const [actorFilter, setActorFilter] = useState<string>("All")
  const [searchQuery, setSearchQuery] = useState("")
  const [sortField, setSortField] = useState<SortField>("timestamp")
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const [currentPage, setCurrentPage] = useState(1)
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const itemsPerPage = 20

  const { data: auditResp, error, isLoading, mutate } = useAuditLog({ limit: 200 })
  const entries = auditResp?.entries

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"))
    } else {
      setSortField(field)
      setSortDirection("desc")
    }
  }

  const actions = useMemo(() => {
    if (!entries) return ["All"]
    const unique = [...new Set(entries.map((e) => e.action))]

    return ["All", ...unique]
  }, [entries])

  const filteredLogs = useMemo(() => {
    if (!entries) return []

    return entries
      .filter((entry) => {
        if (actionFilter !== "All" && entry.action !== actionFilter) return false

        if (actorFilter !== "All" && entry.actor_type !== actorFilter) return false

        if (searchQuery) {
          const target = entry.target_id || ""
          const details = JSON.stringify(entry.details)

          if (!target.includes(searchQuery) && !details.includes(searchQuery)) return false
        }

        return true
      })
      .sort((a, b) => {
        let comparison = 0

        switch (sortField) {
          case "timestamp":
            comparison = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
            break
          case "actor":
            comparison = (a.actor_id || "system").localeCompare(b.actor_id || "system")
            break
          case "action":
            comparison = a.action.localeCompare(b.action)
            break
          case "target":
            comparison = (a.target_id || "").localeCompare(b.target_id || "")
            break
        }

        return sortDirection === "asc" ? comparison : -comparison
      })
  }, [entries, actionFilter, actorFilter, searchQuery, sortField, sortDirection])

  const totalPages = Math.ceil(filteredLogs.length / itemsPerPage)

  const paginatedLogs = filteredLogs.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  useEffect(() => {
    setCurrentPage(1)
  }, [searchQuery, actionFilter, actorFilter])

  useEffect(() => {
    if (totalPages > 0 && currentPage > totalPages) {
      setCurrentPage(totalPages)
    }
  }, [currentPage, totalPages])

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null

    return sortDirection === "asc" ? (
      <ChevronUp className="size-3" aria-hidden="true" />
    ) : (
      <ChevronDown className="size-3" aria-hidden="true" />
    )
  }

  const sortHeader = (field: SortField, label: string) => (
    <TableHead aria-sort={sortField === field ? (sortDirection === "asc" ? "ascending" : "descending") : undefined}>
      <button type="button" onClick={() => handleSort(field)} className="inline-flex items-center gap-1 rounded-sm hover:text-foreground">
        {label}
        <SortIcon field={field} />
      </button>
    </TableHead>
  )

  const filtersActive = searchQuery !== "" || actionFilter !== "All" || actorFilter !== "All"

  return (
    <section aria-label="Audit entries" className="overflow-hidden rounded-md border bg-card">
      <div className="flex items-center gap-2 border-b p-3">
        <div className="relative min-w-0 flex-1">
          <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
          <Input
            placeholder="Search target or details…"
            aria-label="Search audit log"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-9 pl-9 text-base sm:text-sm"
            spellCheck={false}
            autoComplete="off"
          />
        </div>
        <Button
          variant="outline"
          size="icon"
          className="size-9 shrink-0"
          onClick={() => {
            const headers = ["timestamp", "actor_type", "actor_id", "action", "target_type", "target_id"]

            const rows = filteredLogs.map((e) => [
              e.timestamp, e.actor_type ?? "", e.actor_id ?? "", e.action,
              e.target_type ?? "", e.target_id ?? "",
            ])

            downloadCsv(`audit-log-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows)
          }}
          disabled={filteredLogs.length === 0}
          aria-label="Export CSV"
        >
          <Download className="size-4" aria-hidden="true" />
        </Button>
        <Button
          variant="outline"
          size="icon"
          className="size-9 shrink-0"
          onClick={() => mutate()}
          disabled={isLoading}
          aria-label="Refresh audit log"
        >
          <RefreshCw className={cn("size-4", isLoading && "animate-spin")} aria-hidden="true" />
        </Button>
      </div>

      <div className="flex flex-wrap gap-2 border-b p-3">
        <Select value={actionFilter} onValueChange={setActionFilter}>
          <SelectTrigger className="h-9 w-full sm:w-44" aria-label="Action">
            <SelectValue placeholder="Action" />
          </SelectTrigger>
          <SelectContent>
            {actions.map((a) => (
              <SelectItem key={a} value={a}>
                {a === "All" ? "All actions" : a}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select value={actorFilter} onValueChange={setActorFilter}>
          <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Actor">
            <SelectValue placeholder="Actor" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="All">All actors</SelectItem>
            <SelectItem value="system">System</SelectItem>
            <SelectItem value="operator">Operator</SelectItem>
            <SelectItem value="detector">Detector</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {error ? (
        <ErrorState
          title="Unable to load the audit log"
          detail={`${error.message}. Recorded entries are not lost; this view could not be refreshed.`}
          onRetry={() => { void mutate() }}
          retryLabel="Retry audit log"
        />
      ) : isLoading && !entries ? (
        <LoadingRows label="Loading audit log" rows={5} />
      ) : paginatedLogs.length === 0 ? (
        filtersActive ? (
          <EmptyState
            title="No matching entries"
            description="Nothing matches this search or filter."
            action={<Button variant="outline" size="sm" onClick={() => { setSearchQuery(""); setActionFilter("All"); setActorFilter("All") }}>Clear search and filters</Button>}
          />
        ) : (
          <EmptyState title="No audit entries yet" description="Withdrawals, safelist changes and configuration reloads will be recorded here." />
        )
      ) : (
        <>
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                {sortHeader("timestamp", "Time (UTC)")}
                {sortHeader("actor", "Actor")}
                {sortHeader("action", "Action")}
                {sortHeader("target", "Target")}
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {paginatedLogs.map((entry) => (
                <AuditRow
                  key={entry.audit_id}
                  entry={entry}
                  isExpanded={expandedId === entry.audit_id}
                  onToggle={() => {
                    const detailsStr = JSON.stringify(entry.details)

                    if (detailsStr.length > 50) {
                      setExpandedId(expandedId === entry.audit_id ? null : entry.audit_id)
                    }
                  }}
                />
              ))}
            </TableBody>
          </Table>

          <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
            <span className="tabular-nums">
              Showing {(currentPage - 1) * itemsPerPage + 1}–{Math.min(currentPage * itemsPerPage, filteredLogs.length)} of {filteredLogs.length} loaded
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                disabled={currentPage === 1}
              >
                Previous
              </Button>
              <span className="tabular-nums">
                Page {currentPage} of {totalPages || 1}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                disabled={currentPage === totalPages || totalPages === 0}
              >
                Next
              </Button>
            </div>
          </div>
        </>
      )}
    </section>
  )
}
