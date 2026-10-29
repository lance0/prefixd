"use client"

import { useState, useEffect, useRef } from "react"
import Link from "next/link"
import { Eye, Search, Filter, RefreshCw, Download } from "lucide-react"
import { Tag } from "@/components/dashboard/status-pill"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatBps, formatPps, formatRelative } from "@/lib/format"
import { useTimeFormat } from "@/components/time-zone-provider"
import { ConfidenceBar } from "@/components/dashboard/confidence-bar"
import { EventDetailPanel } from "@/components/dashboard/event-detail-panel"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useEvents } from "@/hooks/use-api"
import { cn } from "@/lib/utils"
import { getAllEvents } from "@/lib/api"
import { downloadCsv } from "@/lib/csv"

function validFilter(value: string): boolean {
  return !value.includes("\0") && new TextEncoder().encode(value).length <= 256
}

interface EventsContentLiveProps {
  initialEventId?: string | null
}

export function EventsContentLive({ initialEventId }: EventsContentLiveProps = {}) {
  const { formatTime } = useTimeFormat()
  const [drafts, setDrafts] = useState({ q: initialEventId ?? "", source: "", vector: "" })
  const [filters, setFilters] = useState({ q: validFilter(initialEventId ?? "") ? initialEventId ?? "" : "", source: "", vector: "" })
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [showFilters, setShowFilters] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(initialEventId?.toLowerCase() ?? null)
  const [isExporting, setIsExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const exportInFlight = useRef(false)
  const listRef = useRef<HTMLElement>(null)
  const params = { q: filters.q || undefined, source: filters.source || undefined, vector: filters.vector || undefined }
  const { data: eventsResp, error, isLoading, mutate } = useEvents({ ...params, limit: 20, cursor: cursors.at(-1) })
  const events = eventsResp?.events
  const currentPage = cursors.length
  const selectedEvent = selectedId ? events?.find((e) => e.event_id === selectedId) ?? null : null
  const filtersInvalid = Object.values(drafts).some((value) => !validFilter(value))
  const filtersActive = Object.values(filters).some(Boolean)

  const changeFilter = (name: keyof typeof filters, value: string) => {
    const next = { ...drafts, [name]: value }
    setDrafts(next)

    if (Object.values(next).some((value) => !validFilter(value))) return
    setFilters(next)
    setCursors([undefined])
    setSelectedId(null)
    setExportError(null)
  }

  // Close rather than hide when the selected event leaves the loaded page.
  useEffect(() => {
    if (events && selectedId && !selectedEvent) setSelectedId(null)
  }, [events, selectedId, selectedEvent])

  useEffect(() => {
    if (!error && !isLoading && events?.length === 0 && cursors.length > 1) {
      setCursors((previous) => previous.slice(0, -1))
      setSelectedId(null)
    }
  }, [error, isLoading, events, cursors.length])

  const handleExport = async () => {
    if (exportInFlight.current) return
    exportInFlight.current = true
    setIsExporting(true)
    setExportError(null)

    try {
      const matching = await getAllEvents(params)
      const headers = ["event_id", "event_timestamp", "ingested_at", "source", "victim_ip", "vector", "bps", "pps", "confidence"]

      const rows = matching.map((e) => [
        e.event_id, e.event_timestamp, e.ingested_at, e.source, e.victim_ip, e.vector,
        String(e.bps ?? ""), String(e.pps ?? ""), String(e.confidence ?? ""),
      ])

      downloadCsv(`events-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows)
    } catch (error) {
      setExportError(error instanceof Error ? error.message : "Event export failed")
    } finally {
      exportInFlight.current = false
      setIsExporting(false)
    }
  }

  const now = Date.now()

  return (
    <div className="space-y-4">
      <section ref={listRef} tabIndex={-1} aria-label="Events" className="overflow-hidden rounded-md border bg-card">
        <div className="flex items-center gap-2 border-b p-3">
          <div className="relative min-w-0 flex-1">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              placeholder="Search IP or event ID…"
              aria-label="Search events"
              value={drafts.q}
              onChange={(e) => changeFilter("q", e.target.value)}
              aria-invalid={!validFilter(drafts.q)}
              aria-describedby={filtersInvalid ? "event-filter-error" : undefined}
              className="h-9 pl-9 text-base sm:text-sm"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          <Button
            variant="outline"
            size="icon"
            className="size-9 shrink-0"
            onClick={() => { void handleExport() }}
            disabled={isExporting || filtersInvalid || !events?.length || !!error || isLoading}
            aria-label="Export CSV"
            title="Export all matching events; live traversal, timestamps remain UTC"
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
          {(["source", "vector"] as const).map((name) => (
            <Input
              key={name}
              aria-label={name === "source" ? "Exact source" : "Exact vector"}
              placeholder={name === "source" ? "Exact source (blank = all)" : "Exact vector (blank = all)"}
              value={drafts[name]}
              onChange={(e) => changeFilter(name, e.target.value)}
              aria-invalid={!validFilter(drafts[name])}
              aria-describedby={filtersInvalid ? "event-filter-error" : undefined}
              className="h-9 w-full sm:w-60"
              spellCheck={false}
              autoComplete="off"
            />
          ))}
        </div>
        {filtersInvalid && <p id="event-filter-error" role="alert" className="p-3 text-sm text-destructive">Filters must be at most 256 UTF-8 bytes without null characters. Showing the last valid filters.</p>}
        {exportError && <p role="alert" className="p-3 text-sm text-destructive">{exportError}. No file was downloaded.</p>}
        {isExporting && <p role="status" className="p-3 text-sm text-muted-foreground">Exporting all matching events…</p>}

        {error ? (
          <ErrorState
            title="Unable to load events"
            detail={`${error.message}. Detectors may still be sending signals; this list could not be refreshed.`}
            onRetry={() => { void mutate() }}
            retryLabel="Retry events"
          />
        ) : isLoading && !events ? (
          <LoadingRows label="Loading events" rows={5} />
        ) : !events?.length ? (
          filtersActive ? (
            <EmptyState
              title="No matching events"
              description="Nothing matches this search or filter."
              action={<Button variant="outline" size="sm" onClick={() => { setDrafts({ q: "", source: "", vector: "" }); setFilters({ q: "", source: "", vector: "" }); setCursors([undefined]); setSelectedId(null) }}>Clear search and filters</Button>}
            />
          ) : (
            <EmptyState title="No events yet" description="Signals from detectors and operators will appear here as they arrive." />
          )
        ) : (
            <Table>
              <TableHeader className="sr-only md:not-sr-only md:table-header-group">
                <TableRow className="hover:bg-transparent">
                  <TableHead aria-sort="descending">Received</TableHead>
                  <TableHead>Target</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Vector</TableHead>
                  <TableHead className="text-right">Traffic</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead><span className="sr-only">Row actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.map((event) => {
                  const vector = event.vector.replace(/_/g, " ")

                  return (
                    <TableRow
                      key={event.event_id}
                      className="grid cursor-pointer grid-cols-[1fr_auto] gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0"
                      onClick={() => setSelectedId(event.event_id)}
                    >
                      <TableCell className="hidden whitespace-nowrap text-muted-foreground tabular-nums md:table-cell">
                        <time dateTime={event.ingested_at} title={formatTime(event.ingested_at, now)}>
                          {formatRelative(event.ingested_at, now)}
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
                          {vector} · {event.source} · {formatRelative(event.ingested_at, now)}
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
        )}
        <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
          <span className="tabular-nums">{error ? "Page unavailable" : `${events?.length ?? 0} events on this page`} · Newest received first</span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => { setCursors((previous) => previous.slice(0, -1)); setSelectedId(null) }} disabled={currentPage === 1}>Previous</Button>
            <span className="tabular-nums">Page {currentPage}</span>
            <Button variant="outline" size="sm" onClick={() => {
              if (eventsResp?.next_cursor) setCursors((previous) => [...previous, eventsResp.next_cursor!])
              setSelectedId(null)
            }} disabled={isLoading || !!error || !eventsResp?.has_more || !eventsResp.next_cursor}>Next</Button>
          </div>
        </div>
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
