"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { Eye, Search, ChevronDown, ChevronUp, Filter, RefreshCw, XCircle, Plus, Download, Trash2 } from "lucide-react"
import { Checkbox } from "@/components/ui/checkbox"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  AlertDialog,
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
import { withdrawMitigation, bulkWithdrawMitigations, type BulkWithdrawResult, type Mitigation } from "@/lib/api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"
import { MitigateNowDialog } from "@/components/dashboard/mitigate-now-dialog"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatRelative, formatTimeRemaining, formatUtc } from "@/lib/format"

type SortField = "status" | "victim_ip" | "vector" | "customer_id" | "created_at" | "expires_at"

type SortDirection = "asc" | "desc"

const STATUS_FILTERS = ["active", "escalated", "pending", "expired", "withdrawn"] as const

// A countdown under this many minutes reads as a warning.
const EXPIRY_WARNING_MS = 5 * 60_000

interface MitigationsContentLiveProps {
  initialSearch?: string | null
  initialMitigateOpen?: boolean
}

export function MitigationsContentLive({ initialSearch, initialMitigateOpen }: MitigationsContentLiveProps = {}) {
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
  const withdrawInFlight = useRef(false)
  const withdrawCompleted = useRef(false)
  const withdrawTrigger = useRef<HTMLButtonElement | null>(null)
  const searchInput = useRef<HTMLInputElement | null>(null)
  const [mitigateNowOpen, setMitigateNowOpen] = useState(initialMitigateOpen ?? false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkWithdrawOpen, setBulkWithdrawOpen] = useState(false)
  const [bulkWithdrawReason, setBulkWithdrawReason] = useState("")
  const [isBulkWithdrawing, setIsBulkWithdrawing] = useState(false)
  const [bulkWithdrawError, setBulkWithdrawError] = useState<string | null>(null)
  const [bulkWithdrawResults, setBulkWithdrawResults] = useState<BulkWithdrawResult[]>([])
  const bulkWithdrawInFlight = useRef(false)
  const bulkWithdrawTrigger = useRef<HTMLButtonElement | null>(null)
  const [customerFilter, setCustomerFilter] = useState("All")
  const [popFilter, setPopFilter] = useState("All")
  const permissions = usePermissions()
  const itemsPerPage = 20

  const { data: mitigationsResp, error, isLoading, mutate } = useMitigations({
    status: statusFilters.length > 0 ? statusFilters : undefined,
    limit: 100,
  })

  const mitigations = mitigationsResp?.mitigations

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
    if (!withdrawTarget || withdrawInFlight.current) return
    withdrawInFlight.current = true
    setIsWithdrawing(true)
    setWithdrawError(null)

    try {
      await withdrawMitigation(withdrawTarget.mitigation_id, withdrawReason || "Manual withdrawal", "dashboard")
      withdrawCompleted.current = true
      setWithdrawTarget(null)
      setWithdrawReason("")
      mutate()
    } catch (e) {
      setWithdrawError(e instanceof Error ? e.message : "Failed to withdraw")
    } finally {
      withdrawInFlight.current = false
      setIsWithdrawing(false)
    }
  }

  const { customers, pops } = useMemo(() => {
    if (!mitigations) return { customers: [] as string[], pops: [] as string[] }
    const customerSet = new Set<string>()
    const popSet = new Set<string>()

    for (const m of mitigations) {
      if (m.customer_id) customerSet.add(m.customer_id)

      if (m.pop) popSet.add(m.pop)
    }

    return { customers: [...customerSet].sort(), pops: [...popSet].sort() }
  }, [mitigations])

  const filteredMitigations = useMemo(() => {
    if (!mitigations) return []

    return mitigations
      .filter((m) => {
        if (customerFilter !== "All" && m.customer_id !== customerFilter) return false

        if (popFilter !== "All" && m.pop !== popFilter) return false

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
  }, [mitigations, customerFilter, popFilter, searchQuery, sortField, sortDirection])

  const selectableIds = useMemo(() => {
    return new Set(
      filteredMitigations
        .filter((m) => m.status === "active" || m.status === "escalated")
        .map((m) => m.mitigation_id)
    )
  }, [filteredMitigations])

  const toggleSelectAll = () => {
    if (selectedIds.size === selectableIds.size && selectableIds.size > 0) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(selectableIds))
    }
  }

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)

      if (next.has(id)) {
        next.delete(id)
      } else {
        next.add(id)
      }

      return next
    })
  }

  const handleBulkWithdraw = async () => {
    if (selectedIds.size === 0 || bulkWithdrawInFlight.current) return
    bulkWithdrawInFlight.current = true
    setIsBulkWithdrawing(true)
    setBulkWithdrawError(null)

    try {
      const result = await bulkWithdrawMitigations(
        [...selectedIds],
        bulkWithdrawReason || "Bulk withdrawal",
        "dashboard"
      )

      setBulkWithdrawResults(result.results)
      setSelectedIds(new Set(result.results
        .filter((item) => item.status !== "withdrawn")
        .map((item) => item.mitigation_id)))
      mutate()

      if (result.failed > 0) {
        setBulkWithdrawError(`${result.withdrawn} completed locally, ${result.failed} failed. Retry the failed mitigations.`)
      } else {
        setBulkWithdrawOpen(false)
        setBulkWithdrawReason("")
        setBulkWithdrawResults([])
      }
    } catch (e) {
      setBulkWithdrawError(e instanceof Error ? e.message : "Bulk withdraw failed")
    } finally {
      bulkWithdrawInFlight.current = false
      setIsBulkWithdrawing(false)
    }
  }

  const totalPages = Math.ceil(filteredMitigations.length / itemsPerPage)

  const paginatedMitigations = filteredMitigations.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  )

  useEffect(() => {
    setCurrentPage(1)
  }, [searchQuery, statusFilters, customerFilter, popFilter])

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

  const filtersActive = searchQuery !== "" || customerFilter !== "All" || popFilter !== "All"

  const clearFilters = () => {
    setSearchQuery("")
    setCustomerFilter("All")
    setPopFilter("All")
  }

  const now = Date.now()

  return (
    <div className="space-y-4">
      {permissions.canWithdraw && selectedIds.size > 0 && (
        <div className="flex items-center gap-3 rounded-md border bg-card px-4 py-2">
          <span className="text-sm font-medium tabular-nums">
            {selectedIds.size} selected
          </span>
          <Button
            variant="destructive"
            size="sm"
            onClick={(event) => {
              bulkWithdrawTrigger.current = event.currentTarget
              setBulkWithdrawError(null)
              setBulkWithdrawResults([])
              setBulkWithdrawReason("")
              setBulkWithdrawOpen(true)
            }}
          >
            <Trash2 className="size-4" aria-hidden="true" />
            Withdraw all
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setSelectedIds(new Set())}
          >
            Clear
          </Button>
        </div>
      )}

      <section aria-label="Mitigations" className="overflow-hidden rounded-md border bg-card">
        <div className="flex items-center gap-2 border-b p-3">
          <div className="relative min-w-0 flex-1">
            <Search className="absolute left-3 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" aria-hidden="true" />
            <Input
              ref={searchInput}
              placeholder="Search IP, vector or ID…"
              aria-label="Search mitigations"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="h-9 pl-9 text-base sm:text-sm"
              spellCheck={false}
              autoComplete="off"
            />
          </div>
          {permissions.canWithdraw && (
            <Button
              size="sm"
              className="h-9 shrink-0"
              onClick={() => setMitigateNowOpen(true)}
              aria-label="Mitigate now"
            >
              <Plus className="size-4" aria-hidden="true" />
              <span className="hidden sm:inline">Mitigate now</span>
            </Button>
          )}
          <Button
            variant="outline"
            size="icon"
            className="size-9 shrink-0"
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
            <Download className="size-4" aria-hidden="true" />
          </Button>
          <Button
            variant="outline"
            size="icon"
            className="size-9 shrink-0"
            onClick={() => mutate()}
            disabled={isLoading}
            aria-label="Refresh mitigations"
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

        <div
          className={cn(
            "flex-wrap items-center gap-2 border-b p-3",
            showFilters ? "flex" : "hidden lg:flex"
          )}
        >
          <Select
            value={customerFilter}
            onValueChange={(v) => { setCustomerFilter(v); setCurrentPage(1) }}
          >
            <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Customer">
              <SelectValue placeholder="Customer" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="All">All customers</SelectItem>
              {customers.map((c) => (
                <SelectItem key={c} value={c}>{c}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            value={popFilter}
            onValueChange={(v) => { setPopFilter(v); setCurrentPage(1) }}
          >
            <SelectTrigger className="h-9 w-full sm:w-32" aria-label="POP">
              <SelectValue placeholder="POP" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="All">All POPs</SelectItem>
              {pops.map((p) => (
                <SelectItem key={p} value={p}>{p}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <div role="group" aria-label="Status" className="flex flex-wrap items-center gap-1.5">
            {STATUS_FILTERS.map((status) => {
              const pressed = statusFilters.includes(status)

              return (
                <button
                  key={status}
                  type="button"
                  aria-pressed={pressed}
                  onClick={() => toggleStatusFilter(status)}
                  className={cn(
                    "min-h-9 rounded-md border px-3 text-sm capitalize",
                    pressed
                      ? "border-foreground/30 bg-secondary font-medium text-foreground"
                      : "border-transparent text-muted-foreground hover:border-border hover:text-foreground"
                  )}
                >
                  {status}
                </button>
              )
            })}
          </div>
        </div>

        {error ? (
          <ErrorState
            title="Unable to load mitigations"
            detail={`${error.message}. Rules may still be active; this list could not be refreshed.`}
            onRetry={() => { void mutate() }}
            retryLabel="Retry mitigations"
          />
        ) : isLoading && !mitigations ? (
          <LoadingRows label="Loading mitigations" rows={5} />
        ) : paginatedMitigations.length === 0 ? (
          filtersActive ? (
            <EmptyState
              title="No matching mitigations"
              description="Nothing matches this search or filter."
              action={<Button variant="outline" size="sm" onClick={clearFilters}>Clear search and filters</Button>}
            />
          ) : (
            <EmptyState
              title={statusFilters.length > 0 ? "No mitigations with these statuses" : "No mitigations yet"}
              description={statusFilters.length > 0 ? "Choose other statuses above, or review incoming events." : "Mitigation intent will appear here when a detector or operator requests it."}
              action={<Link href="/events" className="rounded-sm text-sm text-primary hover:underline">Review events</Link>}
            />
          )
        ) : (
          <>
            <Table>
              <TableHeader className="sr-only md:not-sr-only md:table-header-group">
                <TableRow className="hover:bg-transparent">
                  {permissions.canWithdraw && (
                    <TableHead className="w-10">
                      <Checkbox
                        checked={selectableIds.size > 0 && selectedIds.size === selectableIds.size}
                        onCheckedChange={toggleSelectAll}
                        aria-label="Select all active mitigations"
                        disabled={selectableIds.size === 0}
                      />
                    </TableHead>
                  )}
                  {sortHeader("victim_ip", "Target")}
                  {sortHeader("status", "Status")}
                  <TableHead>Action</TableHead>
                  {sortHeader("vector", "Vector")}
                  <TableHead>Ports</TableHead>
                  {sortHeader("created_at", "Created")}
                  {sortHeader("expires_at", "Expires")}
                  <TableHead><span className="sr-only">Row actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {paginatedMitigations.map((mitigation) => {
                  const live = mitigation.status === "active" || mitigation.status === "escalated" || mitigation.status === "pending"
                  const remaining = Date.parse(mitigation.expires_at) - now
                  const vector = mitigation.vector.replace(/_/g, " ")
                  const ports = mitigation.dst_ports.length > 0 ? mitigation.dst_ports.join(", ") : "any"
                  const isSelectable = mitigation.status === "active" || mitigation.status === "escalated"

                  return (
                    <TableRow
                      key={mitigation.mitigation_id}
                      data-state={selectedIds.has(mitigation.mitigation_id) ? "selected" : undefined}
                      className="grid cursor-pointer grid-cols-[1fr_auto] gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0"
                      onClick={() => router.push(`/mitigations/${mitigation.mitigation_id}`)}
                    >
                      {permissions.canWithdraw && (
                        <TableCell className="order-5 self-center p-0 md:p-2 md:px-3" onClick={(e) => e.stopPropagation()}>
                          {isSelectable ? (
                            <Checkbox
                              checked={selectedIds.has(mitigation.mitigation_id)}
                              onCheckedChange={() => toggleSelect(mitigation.mitigation_id)}
                              aria-label={`Select mitigation ${mitigation.victim_ip}`}
                            />
                          ) : null}
                        </TableCell>
                      )}
                      <TableCell className="order-1 min-w-0 p-0 md:px-3 md:py-2">
                        <Link
                          href={`/ip-history?ip=${encodeURIComponent(mitigation.victim_ip)}`}
                          onClick={(e) => e.stopPropagation()}
                          className="break-all rounded-sm font-mono font-medium hover:underline"
                        >
                          {mitigation.victim_ip}
                        </Link>
                        <span className="mt-0.5 block text-xs text-muted-foreground md:hidden">
                          {vector} · ports {ports} · created {formatRelative(mitigation.created_at, now)}
                        </span>
                      </TableCell>
                      <TableCell className="order-2 justify-self-end p-0 md:px-3 md:py-2">
                        <StatusBadge status={mitigation.status} />
                      </TableCell>
                      <TableCell className="order-3 p-0 md:px-3 md:py-2">
                        <ActionBadge actionType={mitigation.action_type} rateBps={mitigation.rate_bps} />
                      </TableCell>
                      <TableCell className="hidden text-muted-foreground md:table-cell">{vector}</TableCell>
                      <TableCell className="hidden font-mono text-muted-foreground md:table-cell">{ports}</TableCell>
                      <TableCell className="hidden text-muted-foreground tabular-nums md:table-cell">
                        <time dateTime={mitigation.created_at} title={formatUtc(mitigation.created_at, now)}>
                          {formatRelative(mitigation.created_at, now)}
                        </time>
                      </TableCell>
                      <TableCell className="order-4 justify-self-end p-0 text-right tabular-nums md:px-3 md:py-2 md:text-left">
                        <time
                          dateTime={mitigation.expires_at}
                          className={cn(live && remaining < EXPIRY_WARNING_MS ? "text-warning" : live ? "font-medium text-foreground" : "text-muted-foreground")}
                        >
                          {live ? <><span className="md:hidden">Expires in </span>{formatTimeRemaining(mitigation.expires_at, now)}</> : formatRelative(mitigation.expires_at, now)}
                        </time>
                        <span className="block whitespace-nowrap text-xs text-muted-foreground">{formatUtc(mitigation.expires_at, now)}</span>
                      </TableCell>
                      <TableCell className="order-6 col-start-2 justify-self-end p-0 md:px-3 md:py-1">
                        <div className="flex items-center justify-end gap-1">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button
                                variant="ghost"
                                size="icon"
                                className="size-9 md:size-8"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  router.push(`/mitigations/${mitigation.mitigation_id}`)
                                }}
                                aria-label="View mitigation details"
                              >
                                <Eye className="size-4" aria-hidden="true" />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>View details</TooltipContent>
                          </Tooltip>
                          {permissions.canWithdraw && isSelectable && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="icon"
                                  className="size-9 text-destructive hover:bg-destructive/10 hover:text-destructive md:size-8"
                                  onClick={(e) => {
                                    e.stopPropagation()
                                    withdrawTrigger.current = e.currentTarget
                                    withdrawCompleted.current = false
                                    setWithdrawTarget(mitigation)
                                  }}
                                  aria-label="Withdraw mitigation"
                                >
                                  <XCircle className="size-4" aria-hidden="true" />
                                </Button>
                              </TooltipTrigger>
                              <TooltipContent>Withdraw</TooltipContent>
                            </Tooltip>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>

            <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
              <span className="tabular-nums">
                Showing {(currentPage - 1) * itemsPerPage + 1}–{Math.min(currentPage * itemsPerPage, filteredMitigations.length)} of {filteredMitigations.length} loaded
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

      {/* Inline Withdraw Dialog */}
      <AlertDialog open={!!withdrawTarget} onOpenChange={(open) => {
        if (!open && !withdrawInFlight.current) {
          setWithdrawTarget(null)
          setWithdrawReason("")
          setWithdrawError(null)
        }
      }}>
        <AlertDialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto" onCloseAutoFocus={(event) => {
          event.preventDefault()
          const target = !withdrawCompleted.current && withdrawTrigger.current?.isConnected ? withdrawTrigger.current : searchInput.current
          target?.focus()
        }}>
          <AlertDialogHeader>
            <AlertDialogTitle>Withdraw Mitigation</AlertDialogTitle>
            <AlertDialogDescription>
              Request withdrawal for <span className="font-mono font-semibold">{withdrawTarget?.victim_ip}</span>.
              Local completion is recorded in the audit log. Router convergence and traffic filtering are not verified here.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Label htmlFor="withdraw-reason">Reason (optional)</Label>
            <Input
              id="withdraw-reason"
              placeholder="e.g., False positive, attack subsided"
              value={withdrawReason}
              disabled={isWithdrawing}
              onChange={(e) => setWithdrawReason(e.target.value)}
              className="mt-2"
            />
            {withdrawError && (
              <div role="alert" className="text-sm text-destructive mt-2">
                <p>{withdrawError}</p>
                <p>Cleanup may still be pending; a pending request retains its original recorded reason.</p>
              </div>
            )}
            <p role="status" className="text-sm text-muted-foreground mt-2">{isWithdrawing ? "Waiting for local withdrawal completion..." : ""}</p>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isWithdrawing}>Cancel</AlertDialogCancel>
            <Button
              type="button"
              onClick={handleWithdraw}
              disabled={isWithdrawing}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isWithdrawing ? "Withdrawing..." : "Withdraw"}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Bulk Withdraw Dialog */}
      <AlertDialog open={bulkWithdrawOpen} onOpenChange={(open) => {
        if (!open && !bulkWithdrawInFlight.current) {
          setBulkWithdrawOpen(false)
          setBulkWithdrawReason("")
          setBulkWithdrawError(null)
          setBulkWithdrawResults([])
        }
      }}>
        <AlertDialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto" onCloseAutoFocus={(event) => {
          event.preventDefault()
          const target = bulkWithdrawTrigger.current?.isConnected ? bulkWithdrawTrigger.current : searchInput.current
          target?.focus()
        }}>
          <AlertDialogHeader>
            <AlertDialogTitle>Bulk Withdraw Mitigations</AlertDialogTitle>
            <AlertDialogDescription>
              Request withdrawal of <span className="font-semibold">{selectedIds.size}</span> FlowSpec
              {selectedIds.size === 1 ? " rule" : " rules"}. Local completion is recorded in the audit log.
              Router convergence and traffic filtering are not verified here.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Label htmlFor="bulk-withdraw-reason">Reason (optional)</Label>
            <Input
              id="bulk-withdraw-reason"
              placeholder="e.g., False positive wave, incident resolved"
              value={bulkWithdrawReason}
              disabled={isBulkWithdrawing}
              onChange={(e) => setBulkWithdrawReason(e.target.value)}
              className="mt-2"
            />
            {bulkWithdrawError && (
              <div role="alert" className="text-sm text-destructive mt-2">
                <p>{bulkWithdrawError}</p>
                <p>Cleanup may still be pending; a pending request retains its original recorded reason.</p>
              </div>
            )}
            <p role="status" className="text-sm text-muted-foreground mt-2">{isBulkWithdrawing ? "Waiting for local withdrawal completion..." : ""}</p>
            {bulkWithdrawResults.length > 0 && (
              <ul aria-label="Withdrawal results" className="max-h-48 overflow-y-auto space-y-1 text-sm mt-2">
                {bulkWithdrawResults.map((item) => (
                  <li key={item.mitigation_id}>
                    <span className="font-mono break-all">{item.mitigation_id}</span>: {item.status === "withdrawn" ? "Completed locally" : item.error || "Withdrawal failed"}
                  </li>
                ))}
              </ul>
            )}
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isBulkWithdrawing}>Cancel</AlertDialogCancel>
            <Button
              type="button"
              onClick={handleBulkWithdraw}
              disabled={isBulkWithdrawing}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isBulkWithdrawing ? "Withdrawing..." : `Withdraw ${selectedIds.size}`}
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <MitigateNowDialog open={mitigateNowOpen} onOpenChange={setMitigateNowOpen} />
    </div>
  )
}
