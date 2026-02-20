"use client"

import { useState, useMemo } from "react"
import Link from "next/link"
import { Search, ChevronDown, ChevronUp, RefreshCw, AlertCircle, Download } from "lucide-react"
import { ActionTypeBadge } from "@/components/dashboard/action-type-badge"
import { ActorBadge } from "@/components/dashboard/actor-badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useAuditLog } from "@/hooks/use-api"
import type { AuditEntry } from "@/lib/api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"

type SortField = "timestamp" | "actor" | "action" | "target"
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

export function AuditLogContentLive() {
  const [actionFilter, setActionFilter] = useState<string>("All")
  const [actorFilter, setActorFilter] = useState<string>("All")
  const [searchQuery, setSearchQuery] = useState("")
  const [sortField, setSortField] = useState<SortField>("timestamp")
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const [currentPage, setCurrentPage] = useState(1)
  const itemsPerPage = 20

  const { data: entries, error, isLoading, mutate } = useAuditLog({ limit: 200 })

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
        <p className="text-destructive font-medium">Failed to load audit log</p>
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
              placeholder="Search..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="pl-9 h-10 bg-secondary border-border text-base"
            />
          </div>
          <Button
            variant="outline"
            size="icon"
            className="h-10 w-10 shrink-0"
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
            <Download className="h-4 w-4" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="h-10 w-10 shrink-0"
            onClick={() => mutate()}
            disabled={isLoading}
            aria-label="Refresh audit log"
          >
            <RefreshCw className={cn("h-4 w-4", isLoading && "animate-spin")} />
          </Button>
        </div>

        <div className="border-t border-border p-3 sm:p-4 flex flex-wrap gap-3">
          <Select value={actionFilter} onValueChange={setActionFilter}>
            <SelectTrigger className="w-full sm:w-40 h-10 bg-secondary border-border text-sm">
              <SelectValue placeholder="Action" />
            </SelectTrigger>
            <SelectContent>
              {actions.map((a) => (
                <SelectItem key={a} value={a}>
                  {a === "All" ? "All Actions" : a}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={actorFilter} onValueChange={setActorFilter}>
            <SelectTrigger className="w-full sm:w-36 h-10 bg-secondary border-border text-sm">
              <SelectValue placeholder="Actor" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="All">All Actors</SelectItem>
              <SelectItem value="system">System</SelectItem>
              <SelectItem value="operator">Operator</SelectItem>
              <SelectItem value="detector">Detector</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      {isLoading && !entries ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-muted-foreground" />
          <p className="text-muted-foreground">Loading audit log...</p>
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
                    onClick={() => handleSort("actor")}
                  >
                    <span className="flex items-center">
                      Actor
                      <SortIcon field="actor" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("action")}
                  >
                    <span className="flex items-center">
                      Action
                      <SortIcon field="action" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("target")}
                  >
                    <span className="flex items-center">
                      Target
                      <SortIcon field="target" />
                    </span>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">Details</th>
                </tr>
              </thead>
              <tbody>
                {paginatedLogs.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                      No audit log entries found
                    </td>
                  </tr>
                ) : (
                  paginatedLogs.map((entry, index) => (
                    <tr
                      key={entry.audit_id}
                      className={cn(
                        "border-b border-border/50 hover:bg-secondary/50 transition-colors",
                        index % 2 === 1 && "bg-secondary/20"
                      )}
                    >
                      <td className="px-4 py-3 font-mono text-muted-foreground whitespace-nowrap">
                        {formatTimestamp(entry.timestamp)}
                      </td>
                      <td className="px-4 py-3">
                        <ActorBadge actor={{ type: entry.actor_type, name: entry.actor_id || "system" }} />
                      </td>
                      <td className="px-4 py-3">
                        <ActionTypeBadge action={entry.action} />
                      </td>
                      <td className="px-4 py-3 font-mono text-foreground">
                        {entry.target_id ? (
                          entry.target_type === "mitigation" ? (
                            <Link href={`/mitigations/${entry.target_id}`} className="truncate max-w-[200px] inline-block text-primary hover:underline">
                              {entry.target_id.slice(0, 8)}
                            </Link>
                          ) : (
                            <span className="truncate max-w-[200px] inline-block">
                              {entry.target_id.length > 20 ? `${entry.target_id.slice(0, 20)}...` : entry.target_id}
                            </span>
                          )
                        ) : (
                          <span className="text-muted-foreground">-</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-muted-foreground max-w-[300px]">
                        <span className="truncate block text-xs font-mono">
                          {JSON.stringify(entry.details).slice(0, 50)}
                          {JSON.stringify(entry.details).length > 50 && "..."}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-secondary">
            <span className="text-sm text-muted-foreground">
              Showing {filteredLogs.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0} to{" "}
              {Math.min(currentPage * itemsPerPage, filteredLogs.length)} of{" "}
              {filteredLogs.length} entries
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
    </div>
  )
}
