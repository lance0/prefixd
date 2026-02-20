"use client"

import { useState, useMemo } from "react"
import { useRouter } from "next/navigation"
import { Eye, Search, ChevronDown, ChevronUp, Filter, RefreshCw, AlertCircle, XCircle, Plus, Download } from "lucide-react"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip"
import { useMitigations } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { withdrawMitigation, type Mitigation } from "@/lib/api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"

type SortField = "status" | "victim_ip" | "vector" | "customer_id" | "created_at" | "expires_at"
type SortDirection = "asc" | "desc"

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSecs = Math.floor(diffMs / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const diffHours = Math.floor(diffMins / 60)

  if (diffSecs < 60) return `${diffSecs}s ago`
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  return date.toLocaleDateString()
}

function formatTimeRemaining(dateStr: string): { text: string; isWarning: boolean } {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = date.getTime() - now.getTime()

  if (diffMs <= 0) return { text: "Expired", isWarning: true }

  const diffSecs = Math.floor(diffMs / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const remainingSecs = diffSecs % 60

  if (diffMins < 1) return { text: `in ${diffSecs}s`, isWarning: true }
  if (diffMins < 2) return { text: `in ${diffMins}m ${remainingSecs}s`, isWarning: true }
  return { text: `in ${diffMins}m`, isWarning: false }
}

function formatBps(bps: number | null): string {
  if (!bps) return "N/A"
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`
  return `${bps} bps`
}

interface MitigationsContentLiveProps {
  initialSearch?: string | null
}

export function MitigationsContentLive({ initialSearch }: MitigationsContentLiveProps = {}) {
  const router = useRouter()
  const [statusFilters, setStatusFilters] = useState<string[]>(initialSearch ? [] : ["active", "escalated"])
  const [searchQuery, setSearchQuery] = useState(initialSearch ?? "")
  const [sortField, setSortField] = useState<SortField>("created_at")
  const [sortDirection, setSortDirection] = useState<SortDirection>("desc")
  const [currentPage, setCurrentPage] = useState(1)
  const [showFilters, setShowFilters] = useState(false)
  const [withdrawTarget, setWithdrawTarget] = useState<Mitigation | null>(null)
  const [withdrawReason, setWithdrawReason] = useState("")
  const [isWithdrawing, setIsWithdrawing] = useState(false)
  const [withdrawError, setWithdrawError] = useState<string | null>(null)
  const permissions = usePermissions()
  const itemsPerPage = 20

  const { data: mitigations, error, isLoading, mutate } = useMitigations({
    status: statusFilters.length > 0 ? statusFilters : undefined,
    limit: 100,
  })

  const toggleStatusFilter = (status: string) => {
    setStatusFilters((prev) =>
      prev.includes(status) ? prev.filter((s) => s !== status) : [...prev, status]
    )
    setCurrentPage(1)
  }

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection((prev) => (prev === "asc" ? "desc" : "asc"))
    } else {
      setSortField(field)
      setSortDirection("desc")
    }
  }

  const handleWithdraw = async () => {
    if (!withdrawTarget) return
    setIsWithdrawing(true)
    setWithdrawError(null)
    try {
      await withdrawMitigation(withdrawTarget.mitigation_id, withdrawReason || "Manual withdrawal", "dashboard")
      setWithdrawTarget(null)
      setWithdrawReason("")
      mutate()
    } catch (e) {
      setWithdrawError(e instanceof Error ? e.message : "Failed to withdraw")
    } finally {
      setIsWithdrawing(false)
    }
  }

  const filteredMitigations = useMemo(() => {
    if (!mitigations) return []
    return mitigations
      .filter((m) => {
        if (searchQuery) {
          const q = searchQuery.toLowerCase()
          const matches = m.victim_ip.includes(q) ||
            m.vector.toLowerCase().includes(q) ||
            (m.customer_id && m.customer_id.toLowerCase().includes(q)) ||
            m.mitigation_id.toLowerCase().includes(q)
          if (!matches) return false
        }
        return true
      })
      .sort((a, b) => {
        let comparison = 0
        switch (sortField) {
          case "status":
            comparison = a.status.localeCompare(b.status)
            break
          case "victim_ip":
            comparison = a.victim_ip.localeCompare(b.victim_ip)
            break
          case "vector":
            comparison = a.vector.localeCompare(b.vector)
            break
          case "customer_id":
            comparison = (a.customer_id || "").localeCompare(b.customer_id || "")
            break
          case "created_at":
            comparison = new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
            break
          case "expires_at":
            comparison = new Date(a.expires_at).getTime() - new Date(b.expires_at).getTime()
            break
        }
        return sortDirection === "asc" ? comparison : -comparison
      })
  }, [mitigations, searchQuery, sortField, sortDirection])

  const totalPages = Math.ceil(filteredMitigations.length / itemsPerPage)
  const paginatedMitigations = filteredMitigations.slice(
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
        <p className="text-destructive font-medium">Failed to load mitigations</p>
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
          {permissions.canWithdraw && (
            <Button
              variant="default"
              size="sm"
              className="h-10 shrink-0"
              onClick={() => router.push("/mitigations/create")}
            >
              <Plus className="h-4 w-4 mr-1.5" />
              <span className="hidden sm:inline">Mitigate Now</span>
            </Button>
          )}
          <Button
            variant="outline"
            size="icon"
            className="h-10 w-10 shrink-0"
            onClick={() => {
              const headers = ["mitigation_id", "status", "victim_ip", "vector", "action_type", "customer_id", "created_at", "expires_at"]
              const rows = filteredMitigations.map((m) => [
                m.mitigation_id, m.status, m.victim_ip, m.vector, m.action_type,
                m.customer_id ?? "", m.created_at, m.expires_at,
              ])
              downloadCsv(`mitigations-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows)
            }}
            disabled={filteredMitigations.length === 0}
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
            aria-label="Refresh mitigations"
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
          <div className="flex flex-wrap items-center gap-2">
            {(["active", "escalated", "expired", "withdrawn", "pending"] as const).map((status) => (
              <button
                key={status}
                onClick={() => toggleStatusFilter(status)}
                className={cn(
                  "px-3 py-2 rounded-full text-xs font-medium transition-colors capitalize min-h-[36px]",
                  statusFilters.includes(status)
                    ? status === "active"
                      ? "bg-success/20 text-success border border-success/50"
                      : status === "escalated"
                        ? "bg-destructive/20 text-destructive border border-destructive/50"
                        : "bg-secondary text-foreground border border-border"
                    : "bg-secondary/50 text-muted-foreground border border-transparent hover:border-border"
                )}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      {isLoading && !mitigations ? (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-muted-foreground" />
          <p className="text-muted-foreground">Loading mitigations...</p>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-secondary">
                <tr className="border-b border-border">
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("status")}
                  >
                    <span className="flex items-center">
                      Status
                      <SortIcon field="status" />
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
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">Action</th>
                  <th className="text-left px-4 py-3 font-medium text-muted-foreground">Ports</th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("created_at")}
                  >
                    <span className="flex items-center">
                      Created
                      <SortIcon field="created_at" />
                    </span>
                  </th>
                  <th
                    className="text-left px-4 py-3 font-medium text-muted-foreground cursor-pointer hover:text-foreground"
                    onClick={() => handleSort("expires_at")}
                  >
                    <span className="flex items-center">
                      Expires
                      <SortIcon field="expires_at" />
                    </span>
                  </th>
                  <th className="text-center px-4 py-3 font-medium text-muted-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {paginatedMitigations.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-muted-foreground">
                      No mitigations found
                    </td>
                  </tr>
                ) : (
                  paginatedMitigations.map((mitigation, index) => {
                    const expiresInfo = formatTimeRemaining(mitigation.expires_at)
                    return (
                      <tr
                        key={mitigation.mitigation_id}
                        className={cn(
                          "border-b border-border/50 hover:bg-secondary/50 transition-colors cursor-pointer",
                          index % 2 === 1 && "bg-secondary/20"
                        )}
                        onClick={() => router.push(`/mitigations/${mitigation.mitigation_id}`)}
                      >
                        <td className="px-4 py-3">
                          <StatusBadge status={mitigation.status} />
                        </td>
                        <td className="px-4 py-3 font-mono text-foreground">{mitigation.victim_ip}</td>
                        <td className="px-4 py-3 text-muted-foreground">
                          {mitigation.vector.replace(/_/g, " ")}
                        </td>
                        <td className="px-4 py-3">
                          <ActionBadge
                            actionType={mitigation.action_type}
                            rateBps={mitigation.rate_bps}
                          />
                        </td>
                        <td className="px-4 py-3 font-mono text-muted-foreground">
                          {mitigation.dst_ports.length > 0
                            ? mitigation.dst_ports.join(", ")
                            : "any"}
                        </td>
                        <td className="px-4 py-3 text-muted-foreground">
                          {formatRelativeTime(mitigation.created_at)}
                        </td>
                        <td
                          className={cn(
                            "px-4 py-3 font-mono",
                            expiresInfo.isWarning ? "text-warning" : "text-muted-foreground"
                          )}
                        >
                          {expiresInfo.text}
                        </td>
                        <td className="px-4 py-3 text-center">
                          <div className="flex items-center justify-center gap-1">
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="h-8 w-8"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    router.push(`/mitigations/${mitigation.mitigation_id}`)
                                  }}
                                  aria-label="View mitigation details"
                                >
                                  <Eye className="h-4 w-4" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>View details</TooltipContent>
                            </Tooltip>
                            {permissions.canWithdraw && (mitigation.status === "active" || mitigation.status === "escalated") && (
                              <Tooltip>
                                <TooltipTrigger asChild>
                                  <Button
                                    variant="ghost"
                                    size="icon"
                                    className="h-8 w-8 text-destructive hover:text-destructive hover:bg-destructive/10"
                                    onClick={(e) => {
                                      e.stopPropagation()
                                      setWithdrawTarget(mitigation)
                                    }}
                                    aria-label="Withdraw mitigation"
                                  >
                                    <XCircle className="h-4 w-4" />
                                  </Button>
                                </TooltipTrigger>
                                <TooltipContent>Withdraw</TooltipContent>
                              </Tooltip>
                            )}
                          </div>
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between px-4 py-3 border-t border-border bg-secondary">
            <span className="text-sm text-muted-foreground">
              Showing {filteredMitigations.length > 0 ? (currentPage - 1) * itemsPerPage + 1 : 0} to{" "}
              {Math.min(currentPage * itemsPerPage, filteredMitigations.length)} of{" "}
              {filteredMitigations.length} mitigations
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

      {/* Inline Withdraw Dialog */}
      <AlertDialog open={!!withdrawTarget} onOpenChange={(open) => { if (!open) { setWithdrawTarget(null); setWithdrawReason(""); setWithdrawError(null) } }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Withdraw Mitigation</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately withdraw the FlowSpec rule from all BGP peers.
              Traffic to <span className="font-mono font-semibold">{withdrawTarget?.victim_ip}</span> will
              no longer be filtered.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Label htmlFor="withdraw-reason">Reason (optional)</Label>
            <Input
              id="withdraw-reason"
              placeholder="e.g., False positive, attack subsided"
              value={withdrawReason}
              onChange={(e) => setWithdrawReason(e.target.value)}
              className="mt-2"
            />
            {withdrawError && (
              <p className="text-sm text-destructive mt-2">{withdrawError}</p>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isWithdrawing}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleWithdraw}
              disabled={isWithdrawing}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isWithdrawing ? "Withdrawing..." : "Withdraw"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  )
}
