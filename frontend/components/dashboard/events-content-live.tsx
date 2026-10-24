"use client"

import { useState, useMemo, useEffect, useRef } from "react"
import Link from "next/link"
import { Eye, Search, ChevronDown, ChevronUp, Filter, RefreshCw, Download } from "lucide-react"
import { Tag } from "@/components/dashboard/status-pill"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatBps, formatPps, formatRelative } from "@/lib/format"
import { useTimeFormat } from "@/components/time-zone-provider"
import { ConfidenceBar } from "@/components/dashboard/confidence-bar"
import { EventDetailPanel } from "@/components/dashboard/event-detail-panel"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useEvents } from "@/hooks/use-api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"

type SortField = "timestamp" | "source" | "victim_ip" | "vector" | "bps" | "confidence"

type SortDirection = "asc" | "desc"

interface EventsContentLiveProps {
  initialEventId?: string | null
}

export function EventsContentLive({ initialEventId }: EventsContentLiveProps = {}) {
  const { formatTime } = useTimeFormat()
  const [sourceFilter, setSourceFilter] = useState<string>("All")
  const [vectorFilter, setVectorFilter] = useState("All")
  const [searchQuery, setSearchQuery] = useState("")
  const [sortField, setSortField] = useState<SortField>("timestamp")
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const [currentPage, setCurrentPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(initialEventId ?? null)
  const itemsPerPage = 20

  const { data: eventsResp, error, isLoading, mutate } = useEvents({ limit: 200 })
  const events = eventsResp?.events
  const listRef = useRef<HTMLElement>(null)
  const selectedEvent = selectedId ? events?.find((e) => e.event_id === selectedId) ?? null : null

  // Close rather than hide when the selected event leaves the loaded list, so it cannot reopen later.
  useEffect(() => {
    if (events && selectedId && !selectedEvent) setSelectedId(null)
  }, [events, selectedId, selectedEvent])

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"))
    } else {
      setSortField(field)
      setSortDirection("desc")
    }
  }

  const sources = useMemo(() => {
    if (!events) return ["All"]
    const unique = [...new Set(events.map((e) => e.source))]

    return ["All", ...unique]
  }, [events])

  const vectors = useMemo(() => {
    if (!events) return ["All"]
    const unique = [...new Set(events.map((e) => e.vector))]

    return ["All", ...unique]
  }, [events])

  const filteredEvents = useMemo(() => {
    if (!events) return []

    return events
      .filter((e) => {
        if (sourceFilter !== "All" && e.source !== sourceFilter) return false

        if (vectorFilter !== "All" && e.vector !== vectorFilter) return false

        if (searchQuery && !e.victim_ip.includes(searchQuery)) return false

        return true
      })
      .sort((a, b) => {
        let comparison = 0

        switch (sortField) {
          case "timestamp":
            comparison = new Date(a.event_timestamp).getTime() - new Date(b.event_timestamp).getTime()
            break
          case "source":
            comparison = a.source.localeCompare(b.source)
            break
          case "victim_ip":
            comparison = a.victim_ip.localeCompare(b.victim_ip)
            break
          case "vector":
            comparison = a.vector.localeCompare(b.vector)
            break
          case "bps":
            comparison = (a.bps || 0) - (b.bps || 0)
            break
          case "confidence":
            comparison = (a.confidence || 0) - (b.confidence || 0)
            break
        }

        return sortDirection === "asc" ? comparison : -comparison
      })
  }, [events, sourceFilter, vectorFilter, searchQuery, sortField, sortDirection])

  const totalPages = Math.ceil(filteredEvents.length / itemsPerPage)

  const paginatedEvents = filteredEvents.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  useEffect(() => {
    setCurrentPage(1)
  }, [searchQuery, sourceFilter, vectorFilter])

  useEffect(() => {
    if (totalPages > 0) {
      setCurrentPage((page) => Math.min(page, totalPages))
    }
  }, [totalPages])

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null

    return sortDirection === "asc" ? (
      <ChevronUp className="size-3" aria-hidden="true" />
    ) : (
      <ChevronDown className="size-3" aria-hidden="true" />
    )
  }

  const sortHeader = (field: SortField, label: string, className?: string) => (
    <TableHead className={className} aria-sort={sortField === field ? (sortDirection === "asc" ? "ascending" : "descending") : undefined}>
      <button type="button" onClick={() => handleSort(field)} className="inline-flex items-center gap-1 rounded-sm hover:text-foreground">
        {label}
        <SortIcon field={field} />
      </button>
    </TableHead>
  )

  const filtersActive = searchQuery !== "" || sourceFilter !== "All" || vectorFilter !== "All"
  const now = Date.now()

  return (
    <div className="space-y-4">
      <section ref={listRef} tabIndex={-1} aria-label="Events" className="overflow-hidden rounded-md border bg-card">
        <div className="flex items-center gap-2 border-b p-3">
          <div className="relative min-w-0 flex-1">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              placeholder="Search IP…"
              aria-label="Search events by IP"
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
              const headers = ["event_id", "event_timestamp", "ingested_at", "source", "victim_ip", "vector", "bps", "pps", "confidence"]

              const rows = filteredEvents.map((e) => [
                e.event_id, e.event_timestamp, e.ingested_at, e.source, e.victim_ip, e.vector,
                String(e.bps ?? ""), String(e.pps ?? ""), String(e.confidence ?? ""),
              ])

              downloadCsv(`events-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows)
            }}
            disabled={filteredEvents.length === 0}
            aria-label="Export CSV"
            title="CSV timestamps remain UTC"
          >
            <Download className="size-4" aria-hidden="true" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-9 shrink-0"
            onClick={() => mutate()}
            disabled={isLoading}
            aria-label="Refresh events"
          >
            <RefreshCw className={cn("size-4", isLoading && "animate-spin")} aria-hidden="true" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-9 shrink-0 lg:hidden"
            onClick={() => setShowFilters(!showFilters)}
            aria-label="Toggle filters"
            aria-expanded={showFilters}
          >
            <Filter className="size-4" aria-hidden="true" />
          </Button>
        </div>

        <div className={cn("flex-wrap items-center gap-2 border-b p-3", showFilters ? "flex" : "hidden lg:flex")}>
          <Select value={sourceFilter} onValueChange={setSourceFilter}>
            <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Source">
              <SelectValue placeholder="Source" />
            </SelectTrigger>
            <SelectContent>
              {sources.map((s) => (
                <SelectItem key={s} value={s}>
                  {s === "All" ? "All sources" : s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={vectorFilter} onValueChange={setVectorFilter}>
            <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Vector">
              <SelectValue placeholder="Vector" />
            </SelectTrigger>
            <SelectContent>
              {vectors.map((v) => (
                <SelectItem key={v} value={v}>
                  {v === "All" ? "All vectors" : v.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>

        {error ? (
          <ErrorState
            title="Unable to load events"
            detail={`${error.message}. Detectors may still be sending signals; this list could not be refreshed.`}
            onRetry={() => { void mutate() }}
            retryLabel="Retry events"
          />
        ) : isLoading && !events ? (
          <LoadingRows label="Loading events" rows={5} />
        ) : paginatedEvents.length === 0 ? (
          filtersActive ? (
            <EmptyState
              title="No matching events"
              description="Nothing matches this search or filter."
              action={<Button variant="outline" size="sm" onClick={() => { setSearchQuery(""); setSourceFilter("All"); setVectorFilter("All") }}>Clear search and filters</Button>}
            />
          ) : (
            <EmptyState title="No events yet" description="Signals from detectors and operators will appear here as they arrive." />
          )
        ) : (
          <>
            <Table>
              <TableHeader className="sr-only md:not-sr-only md:table-header-group">
                <TableRow className="hover:bg-transparent">
                  {sortHeader("timestamp", "Received")}
                  {sortHeader("victim_ip", "Target")}
                  {sortHeader("source", "Source")}
                  {sortHeader("vector", "Vector")}
                  {sortHeader("bps", "Traffic", "text-right")}
                  {sortHeader("confidence", "Confidence")}
                  <TableHead><span className="sr-only">Row actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedEvents.map((event) => {
                  const vector = event.vector.replace(/_/g, " ")

                  return (
                    <TableRow
                      key={event.event_id}
                      className="grid cursor-pointer grid-cols-[1fr_auto] gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0"
                      onClick={() => setSelectedId(event.event_id)}
                    >
                      <TableCell className="hidden whitespace-nowrap text-muted-foreground tabular-nums md:table-cell">
                        <time dateTime={event.event_timestamp} title={formatTime(event.event_timestamp, now)}>
                          {formatRelative(event.event_timestamp, now)}
                        </time>
                      </TableCell>
                      <TableCell className="min-w-0 p-0 md:px-3 md:py-2">
                        <Link
                          href={`/ip-history?ip=${encodeURIComponent(event.victim_ip)}`}
                          onClick={(e) => e.stopPropagation()}
                          className="break-all rounded-sm font-mono font-medium hover:underline"
                        >
                          {event.victim_ip}
                        </Link>
                        <span className="mt-0.5 block text-xs text-muted-foreground md:hidden">
                          {vector} · {event.source} · {formatRelative(event.event_timestamp, now)}
                        </span>
                      </TableCell>
                      <TableCell className="hidden md:table-cell">
                        <Tag>{event.source}</Tag>
                      </TableCell>
                      <TableCell className="hidden text-muted-foreground md:table-cell">{vector}</TableCell>
                      <TableCell numeric className="p-0 md:px-3 md:py-2">
                        <span className="block whitespace-nowrap">{formatBps(event.bps)}</span>
                        <span className="block whitespace-nowrap text-xs text-muted-foreground">{formatPps(event.pps)}</span>
                      </TableCell>
                      <TableCell className="self-center p-0 md:px-3 md:py-2">
                        <ConfidenceBar value={event.confidence} />
                      </TableCell>
                      <TableCell className="justify-self-end p-0 md:px-3 md:py-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="size-9 md:size-8"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedId(event.event_id)
                          }}
                          aria-label="View event details"
                        >
                          <Eye className="size-4" aria-hidden="true" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>

            <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
              <span className="tabular-nums">
                Showing {(currentPage - 1) * itemsPerPage + 1}–{Math.min(currentPage * itemsPerPage, filteredEvents.length)} of {filteredEvents.length} loaded
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

      {/* Detail Panel */}
      {selectedEvent && (
        <EventDetailPanel
          event={selectedEvent}
          onClose={() => setSelectedId(null)}
          fallbackFocusRef={listRef}
        />
      )}
    </div>
  )
}
