"use client"

import { useEffect, useMemo, useRef, useState } from "react"
import Link from "next/link"
import { mitigationTargetHref } from "@/lib/destination"
import { useRouter } from "next/navigation"
import { Ban, Eye, Search, ShieldPlus, Filter, RefreshCw, XCircle, Plus, Download, Trash2 } from "lucide-react"
import { Checkbox } from "@/components/ui/checkbox"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { OriginTag } from "@/components/dashboard/status-pill"
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
import { useConfigInventory, useMitigations, usePops } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { getAllMitigations, withdrawMitigation, bulkWithdrawMitigations, type BulkWithdrawResult, type Mitigation } from "@/lib/api"
import { cn } from "@/lib/utils"
import { downloadCsv } from "@/lib/csv"
import { MitigateNowDialog } from "@/components/dashboard/mitigate-now-dialog"
import { BlackholeDialog } from "@/components/dashboard/blackhole-dialog"
import { FlowSpecRuleDialog } from "@/components/dashboard/flowspec-rule-dialog"
import { describeMatch } from "@/components/dashboard/flowspec-preview"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatRelative, formatTimeRemaining } from "@/lib/format"
import { useTimeFormat } from "@/components/time-zone-provider"

// Escalated is hidden: no code path produces it. Legacy rows still render with a danger pill.
const STATUS_FILTERS = ["active", "pending", "expired", "withdrawn"] as const

// A countdown under this many minutes reads as a warning.
const EXPIRY_WARNING_MS = 5 * 60_000

function validSearch(value: string): boolean {
  return !value.includes("\0") && new TextEncoder().encode(value).length <= 256
}

interface MitigationsContentLiveProps {
  initialSearch?: string | null
  initialMitigateOpen?: boolean
}

export function MitigationsContentLive({ initialSearch, initialMitigateOpen }: MitigationsContentLiveProps = {}) {
  const { formatTime } = useTimeFormat()
  const router = useRouter()
  const [statusFilters, setStatusFilters] = useState<string[]>(initialSearch && validSearch(initialSearch) ? [] : ["active"])
  const [searchDraft, setSearchDraft] = useState(initialSearch ?? "")
  const [searchQuery, setSearchQuery] = useState(() => validSearch(initialSearch ?? "") ? initialSearch ?? "" : "")
  const [cursors, setCursors] = useState<(string | undefined)[]>([undefined])
  const [isExporting, setIsExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)
  const exportInFlight = useRef(false)
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
  const [blackholeOpen, setBlackholeOpen] = useState(false)
  const [ruleOpen, setRuleOpen] = useState(false)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())
  const [bulkWithdrawOpen, setBulkWithdrawOpen] = useState(false)
  const [bulkWithdrawReason, setBulkWithdrawReason] = useState("")
  const [isBulkWithdrawing, setIsBulkWithdrawing] = useState(false)
  const [bulkWithdrawError, setBulkWithdrawError] = useState<string | null>(null)
  const [bulkWithdrawResults, setBulkWithdrawResults] = useState<BulkWithdrawResult[]>([])
  const bulkWithdrawInFlight = useRef(false)
  const bulkWithdrawTrigger = useRef<HTMLButtonElement | null>(null)
  const [customerFilter, setCustomerFilter] = useState<string | null>(null)
  const [popFilter, setPopFilter] = useState<string | null>(null)
  const permissions = usePermissions()
  const itemsPerPage = 20

  const filters = {
    status: statusFilters.length > 0 ? statusFilters : undefined,
    customer_id: customerFilter ?? undefined,
    pop: popFilter ?? undefined,
    q: searchQuery || undefined,
  }

  const { data: mitigationsResp, error, isLoading, mutate } = useMitigations({
    ...filters,
    limit: itemsPerPage,
    cursor: cursors.at(-1),
  })

  const { data: inventory, error: inventoryError } = useConfigInventory()
  const { data: popInventory, error: popsError } = usePops()
  const customers = [...new Set(inventory?.customers.map((customer) => customer.customer_id).filter(Boolean))].sort()
  const pops = [...new Set(popInventory?.map((pop) => pop.pop).filter((pop) => pop !== "" && pop !== "all"))].sort()
  const mitigations = mitigationsResp?.mitigations
  const currentPage = cursors.length
  const searchInvalid = !validSearch(searchDraft)

  const resetPage = () => {
    setCursors([undefined])
    setSelectedIds(new Set())
  }

  const toggleStatusFilter = (status: string) => {
    setStatusFilters((prev) =>
      prev.includes(status) ? prev.filter((s) => s !== status) : [...prev, status]
    )
    resetPage()
  }

  const handleExport = async () => {
    if (exportInFlight.current) return
    exportInFlight.current = true
    setIsExporting(true)
    setExportError(null)

    try {
      const matching = await getAllMitigations(filters)
      const headers = ["mitigation_id", "status", "victim_ip", "vector", "action_type", "customer_id", "created_at", "expires_at"]

      const rows = matching.map((m) => [
        m.mitigation_id, m.status, m.victim_ip, m.vector, m.action_type,
        m.customer_id ?? "", m.created_at, m.expires_at,
      ])

      downloadCsv(`mitigations-${new Date().toISOString().slice(0, 10)}.csv`, headers, rows)
    } catch (error) {
      setExportError(error instanceof Error ? error.message : "Mitigation export failed")
    } finally {
      exportInFlight.current = false
      setIsExporting(false)
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

  const selectableIds = useMemo(() => {
    return new Set(
      (mitigations ?? [])
        .filter((m) => m.status === "active" || m.status === "escalated")
        .map((m) => m.mitigation_id)
    )
  }, [mitigations])

  const allSelected = selectableIds.size > 0 && selectedIds.size === selectableIds.size && [...selectableIds].every((id) => selectedIds.has(id))

  useEffect(() => {
    if (bulkWithdrawOpen || error || !mitigations) return
    setSelectedIds((previous) => {
      const retained = [...previous].filter((id) => selectableIds.has(id))

      return retained.length === previous.size ? previous : new Set(retained)
    })
  }, [bulkWithdrawOpen, error, mitigations, selectableIds])

  const toggleSelectAll = () => {
    if (allSelected) {
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

  useEffect(() => {
    if (!bulkWithdrawOpen && !error && mitigations?.length === 0 && cursors.length > 1) {
      setCursors((previous) => previous.slice(0, -1))
      setSelectedIds(new Set())
    }
  }, [bulkWithdrawOpen, error, mitigations, cursors.length])

  const filtersActive = searchQuery !== "" || customerFilter !== null || popFilter !== null

  const clearFilters = () => {
    setSearchQuery("")
    setSearchDraft("")
    setCustomerFilter(null)
    setPopFilter(null)
    resetPage()
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
              value={searchDraft}
              onChange={(e) => {
                const value = e.target.value
                setSearchDraft(value)

                if (validSearch(value)) {
                  setSearchQuery(value)
                  resetPage()
                }
              }}
              aria-invalid={searchInvalid}
              aria-describedby="mitigation-search-help"
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
          {permissions.canWithdraw && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 shrink-0"
              onClick={() => setRuleOpen(true)}
              aria-label="Create FlowSpec rule"
            >
              <ShieldPlus className="size-4" aria-hidden="true" />
              <span className="hidden sm:inline">Rule</span>
            </Button>
          )}
          {permissions.isAdmin && (
            <Button
              variant="outline"
              size="sm"
              className="h-9 shrink-0 text-destructive"
              onClick={() => setBlackholeOpen(true)}
              aria-label="Blackhole a host"
            >
              <Ban className="size-4" aria-hidden="true" />
              <span className="hidden sm:inline">Blackhole</span>
            </Button>
          )}
          <Button
            variant="outline"
            size="icon"
            className="size-9 shrink-0"
            onClick={handleExport}
            disabled={searchInvalid || !mitigations?.length || isExporting || Boolean(error)}
            aria-label="Export CSV"
            title="Export all matching mitigations; timestamps remain UTC"
            aria-busy={isExporting}
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

        <p id="mitigation-search-help" role={searchInvalid ? "alert" : undefined} className={cn("border-b px-4 py-2 text-sm", searchInvalid ? "text-destructive" : "text-muted-foreground")}>
          {searchInvalid ? "Search must be at most 256 UTF-8 bytes without null characters. Showing results for the last valid search." : "Search IP, vector, customer or ID. Maximum 256 UTF-8 bytes."}
        </p>

        <div
          className={cn(
            "flex-wrap items-center gap-2 border-b p-3",
            showFilters ? "flex" : "hidden lg:flex"
          )}
        >
          <Select
            disabled={!inventory}
            value={customerFilter === null ? "all" : `customer:${customerFilter}`}
            onValueChange={(v) => { setCustomerFilter(v === "all" ? null : v.slice("customer:".length)); resetPage() }}
          >
            <SelectTrigger className="h-9 w-full sm:w-40" aria-label="Customer">
              <SelectValue placeholder="Customer" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All customers</SelectItem>
              {customers.map((c) => (
                <SelectItem key={c} value={`customer:${c}`}>{c}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select
            disabled={!popInventory}
            value={popFilter === null ? "all" : `pop:${popFilter}`}
            onValueChange={(v) => { setPopFilter(v === "all" ? null : v.slice("pop:".length)); resetPage() }}
          >
            <SelectTrigger className="h-9 w-full sm:w-32" aria-label="POP">
              <SelectValue placeholder="POP" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All POPs</SelectItem>
              {pops.map((p) => (
                <SelectItem key={p} value={`pop:${p}`}>{p}</SelectItem>
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

        {(inventoryError || popsError) && (
          <p className="border-b px-4 py-2 text-sm text-destructive">Some filter choices could not be loaded. Search still covers stored customer IDs.</p>
        )}
        {exportError && <p role="alert" className="border-b px-4 py-2 text-sm text-destructive">CSV export failed: {exportError}. No file was downloaded.</p>}
        {error ? (
          <ErrorState
            title="Unable to load mitigations"
            detail={`${error.message}. Rules may still be active; this list could not be refreshed.`}
            onRetry={() => { void mutate() }}
            retryLabel="Retry mitigations"
          />
        ) : isLoading && !mitigations ? (
          <LoadingRows label="Loading mitigations" rows={5} />
        ) : !mitigations?.length ? (
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
                        checked={allSelected}
                        onCheckedChange={toggleSelectAll}
                        aria-label="Select all active mitigations on this page"
                        disabled={selectableIds.size === 0}
                      />
                    </TableHead>
                  )}
                  <TableHead>Target</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Vector</TableHead>
                  <TableHead>Match</TableHead>
                  <TableHead aria-sort="descending">Created</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead><span className="sr-only">Row actions</span></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {mitigations.map((mitigation) => {
                  const live = mitigation.status === "active" || mitigation.status === "escalated" || mitigation.status === "pending"
                  const remaining = Date.parse(mitigation.expires_at) - now
                  const vector = mitigation.vector.replace(/_/g, " ")
                  const match = describeMatch(mitigation)
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
                          href={mitigationTargetHref(mitigation)}
                          onClick={(e) => e.stopPropagation()}
                          className="break-all rounded-sm font-mono font-medium hover:underline"
                        >
                          {mitigation.victim_ip}
                        </Link>
                        <span className="mt-0.5 block text-xs text-muted-foreground md:hidden">
                          {vector} · {match} · created {formatRelative(mitigation.created_at, now)}
                        </span>
                      </TableCell>
                      <TableCell className="order-2 justify-self-end p-0 md:px-3 md:py-2">
                        <span className="flex flex-wrap items-center justify-end gap-1 md:justify-start">
                          <StatusBadge status={mitigation.status} />
                          <OriginTag origin={mitigation.origin_mode} />
                        </span>
                      </TableCell>
                      <TableCell className="order-3 p-0 md:px-3 md:py-2">
                        <ActionBadge actionType={mitigation.action_type} rateBps={mitigation.rate_bps} />
                      </TableCell>
                      <TableCell className="hidden text-muted-foreground md:table-cell">{vector}</TableCell>
                      <TableCell className="hidden max-w-56 whitespace-normal break-words text-muted-foreground md:table-cell">{match}</TableCell>
                      <TableCell className="hidden text-muted-foreground tabular-nums md:table-cell">
                        <time dateTime={mitigation.created_at} title={formatTime(mitigation.created_at, now)}>
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
                        <span className="block whitespace-nowrap text-xs text-muted-foreground">{formatTime(mitigation.expires_at, now)}</span>
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
          </>
        )}
        {(currentPage > 1 || Boolean(mitigations?.length)) && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t px-4 py-3 text-sm text-muted-foreground">
            <span className="tabular-nums">
              {error ? "Page unavailable" : isLoading ? "Loading page…" : `${mitigations?.length ?? 0} on this page · Newest first`}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  setCursors((previous) => previous.slice(0, -1))
                  setSelectedIds(new Set())
                }}
                disabled={currentPage === 1 || isLoading}
              >
                Previous
              </Button>
              <span className="tabular-nums">
                Page {currentPage}
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const nextCursor = mitigationsResp?.next_cursor

                  if (nextCursor) {
                    setCursors((previous) => [...previous, nextCursor])
                    setSelectedIds(new Set())
                  }
                }}
                disabled={isLoading || Boolean(error) || !mitigationsResp?.has_more || !mitigationsResp.next_cursor}
              >
                Next
              </Button>
            </div>
          </div>
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
      {permissions.canWithdraw && <FlowSpecRuleDialog open={ruleOpen} onOpenChange={setRuleOpen} />}
      {permissions.isAdmin && <BlackholeDialog open={blackholeOpen} onOpenChange={setBlackholeOpen} />}
    </div>
  )
}
