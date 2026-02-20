"use client"

import { useState, useMemo } from "react"
import { Eye, Search, ChevronDown, ChevronUp, Filter, RefreshCw, AlertCircle, Download } from "lucide-react"
import { SourceBadge } from "@/components/dashboard/source-badge"
import { ConfidenceBar } from "@/components/dashboard/confidence-bar"
import { EventDetailPanel } from "@/components/dashboard/event-detail-panel"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useEvents } from "@/hooks/use-api"
import type { Event } from "@/lib/api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"

type SortField = "timestamp" | "source" | "victim_ip" | "vector" | "bps" | "confidence"
type SortDirection = "asc" | "desc"

function formatTimestamp(dateStr: string): string {
  const date = new Date(dateStr)
  return date.toLocaleTimeString("en-US", {
    timeZone: "UTC",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }) + " UTC"
}

function formatBps(bps: number | null): string {
  if (!bps) return "N/A"
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`
  return `${bps} bps`
}

function formatPps(pps: number | null): string {
  if (!pps) return "N/A"
  if (pps >= 1_000_000) return `${(pps / 1_000_000).toFixed(1)}M pps`
  if (pps >= 1_000) return `${(pps / 1_000).toFixed(0)}K pps`
  return `${pps} pps`
}

interface EventsContentLiveProps {
  initialEventId?: string | null
}

export function EventsContentLive({ initialEventId }: EventsContentLiveProps = {}) {
  const [sourceFilter, setSourceFilter] = useState<string>("All")
  const [vectorFilter, setVectorFilter] = useState("All")
  const [searchQuery, setSearchQuery] = useState("")
  const [sortField, setSortField] = useState<SortField>("timestamp")
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const [currentPage, setCurrentPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)
  const [selectedId, setSelectedId] = useState<string | null>(initialEventId ?? null)
  const itemsPerPage = 20

  const { data: events, error, isLoading, mutate } = useEvents({ limit: 200 })

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

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return null
    return sortDirection === "asc" ? (
      <ChevronUp className="h-3 w-3 ml-1" />
    ) : (
      <ChevronDown className="h-3 w-3 ml-1" />
    )
  }

  if (error) {
    return (
      <div className="bg-destructive/10 border border-destructive/50 rounded-lg p-6 text-center">
        <AlertCircle className="h-8 w-8 mx-auto mb-2 text-destructive" />
        <p className="text-destructive font-medium">Failed to load events</p>
        <p className="text-sm text-muted-foreground mt-1">{error.message}</p>
        <Button variant="outline" className="mt-4" onClick={() => mutate()}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Retry
        </Button>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      <div className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="flex items-center gap-2 p-3 sm:p-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search IP..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 h-10 bg-secondary border-border text-base font-mono"
            />
          </div>
          <Button
            variant="outline"
            size="icon"
            className="h-10 w-10 shrink-0"
            onClick={() => {
              const headers = ["event_id", "timestamp", "source", "victim_ip", "vector", "bps", "pps", "confidence"]
              const rows = filteredEvents.map((e) => [
                e.event_id, e.timestamp, e.source, e.victim_ip, e.vector,
                String(e.bps ?? ""), String(e.pps ?? ""), String(e.confidence ?? ""),
              ])
              downloadCsv(`events-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows)
            }}
            disabled={filteredEvents.length === 0}
            aria-label="Export CSV"
          >
            <Download className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-10 w-10 shrink-0"
            onClick={() => mutate()}
            disabled={isLoading}
            aria-label="Refresh events"
          >
            <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-10 w-10 lg:hidden shrink-0"
            onClick={() => setShowFilters(!showFilters)}
            aria-label="Toggle filters"
          >
            <Filter className="h-4 w-4" />
          </Button>
        </div>

        <div
          className={cn(
            "border-t border-border p-3 sm:p-4 space-y-3",
            "lg:flex lg:flex-wrap lg:items-center lg:gap-3 lg:space-y-0",
            showFilters ? "block" : "hidden lg:flex"
          )}
        >
          <Select value={sourceFilter} onValueChange={setSourceFilter}>
            <SelectTrigger className="w-full sm:w-36 h-10 bg-secondary border-border text-sm">
              <SelectValue placeholder="Source" />
            </SelectTrigger>
            <SelectContent>
              {sources.map((s) => (
                <SelectItem key={s} value={s}>
                  {s === "All" ? "All Sources" : s}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={vectorFilter} onValueChange={setVectorFilter}>
            <SelectTrigger className="w-full sm:w-40 h-10 bg-secondary border-border text-sm">
              <SelectValue placeholder="Vector" />
            </SelectTrigger>
            <SelectContent>
              {vectors.map((v) => (
                <SelectItem key={v} value={v}>
                  {v === "All" ? "All Vectors" : v.replace(/_/g, " ")}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading && !events ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-muted-foreground" />
          <p className="text-muted-foreground">Loading events...</p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-secondary">
                <tr className="border-b border-border">
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("timestamp")}
                  >
                    <span className="flex items-center">
                      Timestamp
                      <SortIcon field="timestamp" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("source")}
                  >
                    <span className="flex items-center">
                      Source
                      <SortIcon field="source" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("victim_ip")}
                  >
                    <span className="flex items-center">
                      Victim IP
                      <SortIcon field="victim_ip" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("vector")}
                  >
                    <span className="flex items-center">
                      Vector
                      <SortIcon field="vector" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("bps")}
                  >
                    <span className="flex items-center">
                      Traffic
                      <SortIcon field="bps" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("confidence")}
                  >
                    <span className="flex items-center">
                      Confidence
                      <SortIcon field="confidence" />
                    </span>
                  </th>
                  <th className="text-center px-4 py-3 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedEvents.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">
                      No events found
                    </td>
                  </tr>
                ) : (
                  paginatedEvents.map((event, index) => (
                    <tr
                      key={event.event_id}
                      className={cn(
                        "border-b border-border/50 hover:bg-secondary/50 transition-colors cursor-pointer",
                        index % 2 === 1 && "bg-secondary/20"
                      )}
                      onClick={() => setSelectedId(event.event_id)}
                    >
                      <td className="px-4 py-3 font-mono text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(event.event_timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <SourceBadge source={event.source} />
                      </td>
                      <td className="px-4 py-3 font-mono text-foreground">{event.victim_ip}</td>
                      <td className="px-4 py-3 text-muted-foreground">
                        {event.vector.replace(/_/g, " ")}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-col">
                          <span className="font-mono text-foreground">{formatBps(event.bps)}</span>
                          <span className="text-xs text-muted-foreground">{formatPps(event.pps)}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <ConfidenceBar value={event.confidence || 0} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedId(event.event_id)
                          }}
                          aria-label="View event details"
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-secondary">
            <span className="text-sm text-muted-foreground">
              Showing {filteredEvents.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0} to{" "}
              {Math.min(currentPage * itemsPerPage, filteredEvents.length)} of{" "}
              {filteredEvents.length} events
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
              <span className="text-sm text-muted-foreground">
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
        </div>
      )}

      {/* Detail Panel */}
      {selectedId && (
        <EventDetailPanel
          event={events?.find(e => e.event_id === selectedId) || null}
          onClose={() => setSelectedId(null)}
        />
      )}
    </div>
  )
}
