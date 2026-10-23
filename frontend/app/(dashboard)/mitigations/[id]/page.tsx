"use client"

import { use, useEffect, useRef, useState } from "react"
import Link from "next/link"
import { mitigationTargetHref } from "@/lib/destination"
import { useMitigation, useMitigations, useConfigInventory, useSignalGroupDetail } from "@/hooks/use-api"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Check, Copy, FileText, AlertTriangle, Terminal, CheckCircle2, Info } from "lucide-react"
import { PageHeader } from "@/components/dashboard/page-header"
import { OriginTag, StatusPill, Tag } from "@/components/dashboard/status-pill"
import { Field, FieldList } from "@/components/dashboard/field"
import { ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatBps, formatTimeRemaining } from "@/lib/format"
import { useTimeFormat } from "@/components/time-zone-provider"
import { FlowSpecPreview, describeMatch, formatFlowSpecRule } from "@/components/dashboard/flowspec-preview"
import { IncidentReportDialog } from "@/components/dashboard/incident-report-dialog"
import { withdrawMitigation, getIncidentReport, isNotFound, type Mitigation } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { toast } from "sonner"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { usePermissions } from "@/hooks/use-permissions"
import { formatConfidence } from "@/lib/confidence"
import { ConfidenceBar } from "@/components/dashboard/confidence-bar"
import { ExportEvidenceCard } from "@/components/dashboard/export-evidence"

function protocolName(proto: number | null): string {
  if (proto === null) return "any"

  switch (proto) {
    case 1: return "ICMP"
    case 6: return "TCP"
    case 17: return "UDP"
    default: return `${proto}`
  }
}

/** The saved blackhole route (ADR 027): the frozen next hop and communities, not router state. */
function BlackholeRouteCard({ mitigation }: { mitigation: Mitigation }) {
  const route = mitigation.blackhole

  return (
    <Card data-testid="blackhole-card">
      <CardHeader>
        <CardTitle>Blackhole route</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p role="note" className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
          <span>
            All traffic to <span className="font-mono">{mitigation.victim_ip}</span> is dropped, including legitimate traffic.
            This is the route prefixd saved; router enforcement depends on the router&apos;s blackhole policy and is not verified here.
          </span>
        </p>
        <FieldList className="grid-cols-1 sm:grid-cols-3">
          <Field label="Host prefix"><span className="font-mono">{mitigation.dst_prefix}</span></Field>
          <Field label="Next hop"><span className="font-mono">{route?.next_hop ?? "unknown"}</span></Field>
          <Field label="Communities"><span className="font-mono">{route?.communities.join(" ") || "unknown"}</span></Field>
          {route && route.large_communities.length > 0 && (
            <Field label="Large communities" className="sm:col-span-3"><span className="font-mono">{route.large_communities.join(" ")}</span></Field>
          )}
        </FieldList>
      </CardContent>
    </Card>
  )
}

export default function MitigationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { formatTime } = useTimeFormat()
  const { id } = use(params)
  const permissions = usePermissions()
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const interval = setInterval(() => setNow(Date.now()), 15_000)

    return () => clearInterval(interval)
  }, [])

  const { data: mitigation, error: mitigationError, isLoading, mutate } = useMitigation(id)
  const { data: inventory } = useConfigInventory()

  // Rules one event produced share triggering_event_id (ADR 028); list them as siblings.
  const { data: victimMitigations } = useMitigations(mitigation ? { victim_ip: mitigation.victim_ip, limit: 100 } : null)

  const siblings = (victimMitigations?.mitigations ?? []).filter(
    (other) => mitigation && other.triggering_event_id === mitigation.triggering_event_id && other.mitigation_id !== mitigation.mitigation_id,
  )

  const { data: signalGroupDetail, error: signalGroupError, isLoading: isSignalGroupLoading, mutate: mutateSignalGroup } = useSignalGroupDetail(
    mitigation?.correlation?.signal_group_id ?? null
  )

  const [copied, setCopied] = useState<string | null>(null)
  const [showWithdrawDialog, setShowWithdrawDialog] = useState(false)
  const [withdrawReason, setWithdrawReason] = useState("")
  const [isWithdrawing, setIsWithdrawing] = useState(false)
  const [withdrawError, setWithdrawError] = useState<string | null>(null)
  const withdrawInFlight = useRef(false)
  const withdrawCompleted = useRef(false)
  const withdrawTrigger = useRef<HTMLButtonElement | null>(null)
  const victimLink = useRef<HTMLAnchorElement | null>(null)
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null)
  const [showReportDialog, setShowReportDialog] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)

  const copyToClipboard = async (text: string, field: string) => {
    if (!(await copyText(text))) {
      toast.error("Copy failed — clipboard unavailable")

      return
    }

    setCopied(field)
    setTimeout(() => setCopied(null), 2000)
  }

  const handleWithdraw = async () => {
    if (!mitigation || withdrawInFlight.current) return
    withdrawInFlight.current = true
    setIsWithdrawing(true)
    setWithdrawError(null)

    try {
      await withdrawMitigation(mitigation.mitigation_id, withdrawReason || "Manual withdrawal", "dashboard")
      withdrawCompleted.current = true
      setShowWithdrawDialog(false)
      setWithdrawReason("")
      mutate()
    } catch (e) {
      setWithdrawError(e instanceof Error ? e.message : "Failed to withdraw")
    } finally {
      withdrawInFlight.current = false
      setIsWithdrawing(false)
    }
  }

  const handleGenerateReport = async () => {
    if (!mitigation) return
    setShowReportDialog(true)
    setReportLoading(true)

    try {
      const md = await getIncidentReport({ mitigation_id: mitigation.mitigation_id })
      setReportMarkdown(md)
    } catch {
      setReportMarkdown(null)
    } finally {
      setReportLoading(false)
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader back={{ href: "/mitigations", label: "Mitigations" }} title="Mitigation" />
        <div className="rounded-md border bg-card"><LoadingRows label="Loading mitigation" /></div>
      </div>
    )
  }

  if (!mitigation && mitigationError && !isNotFound(mitigationError)) {
    return (
      <div className="space-y-6">
        <PageHeader back={{ href: "/mitigations", label: "Mitigations" }} title="Mitigation" />
        <div className="rounded-md border bg-card">
          <ErrorState
            title="Unable to load this mitigation"
            detail={`${mitigationError.message}. The rule may still be active; retry, or check that the controller is reachable.`}
            onRetry={() => { void mutate() }}
          />
        </div>
      </div>
    )
  }

  if (!mitigation) {
    return (
      <PageHeader
        back={{ href: "/mitigations", label: "Mitigations" }}
        title="Mitigation not found"
        description="This mitigation ID does not exist or is no longer retained."
      />
    )
  }

  const canWithdraw = mitigation.status === "active" || mitigation.status === "escalated"
  const expired = Date.parse(mitigation.expires_at) <= now

  // Find customer context
  const customer = inventory?.customers.find(c => c.customer_id === mitigation.customer_id)
  const service = customer?.services.find(s => s.service_id === mitigation.service_id)

  return (
    <>
      <div className="space-y-6">
        <PageHeader
          back={{ href: "/mitigations", label: "Mitigations" }}
          title={
            <Link
              ref={victimLink}
              href={mitigationTargetHref(mitigation)}
              className="break-all rounded-sm font-mono hover:underline"
            >
              {mitigation.victim_ip}
            </Link>
          }
          meta={
            <>
              <StatusBadge status={mitigation.status} />
              <OriginTag origin={mitigation.origin_mode} showUnknown />
              <ActionBadge actionType={mitigation.action_type} rateBps={mitigation.rate_bps} />
              <Tag>{mitigation.vector.replace(/_/g, " ")}</Tag>
              <span className="text-muted-foreground">POP <span className="font-mono text-foreground">{mitigation.pop}</span></span>
              <span className="text-muted-foreground tabular-nums">
                {mitigation.withdrawn_at
                  ? <>Withdrawn <time dateTime={mitigation.withdrawn_at}>{formatTime(mitigation.withdrawn_at, now)}</time></>
                  : expired
                    ? <>Expired <time dateTime={mitigation.expires_at}>{formatTime(mitigation.expires_at, now)}</time></>
                    : <>Expires in <span className="font-medium text-foreground">{formatTimeRemaining(mitigation.expires_at, now)}</span> · <time dateTime={mitigation.expires_at}>{formatTime(mitigation.expires_at, now)}</time></>}
              </span>
            </>
          }
          actions={
            <>
              <Button variant="outline" size="sm" onClick={handleGenerateReport}>
                <FileText className="size-4" aria-hidden="true" />
                Report
              </Button>
              {permissions.canWithdraw && canWithdraw ? (
                <Button
                  ref={withdrawTrigger}
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    withdrawCompleted.current = false
                    setShowWithdrawDialog(true)
                  }}
                >
                  <AlertTriangle className="size-4" aria-hidden="true" />
                  Withdraw
                </Button>
              ) : null}
            </>
          }
        />

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          <div className="space-y-6 lg:col-span-2">
            {mitigation.export_evidence && <ExportEvidenceCard evidence={mitigation.export_evidence} now={now} />}
            {mitigation.action_type === "blackhole" ? <BlackholeRouteCard mitigation={mitigation} /> : (
            <Card>
              <CardHeader className="flex flex-wrap items-center justify-between gap-2">
                <CardTitle>FlowSpec rule</CardTitle>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2"
                    onClick={() => copyToClipboard(formatFlowSpecRule(mitigation), "flowspec")}
                  >
                    {copied === "flowspec" ? <Check className="size-3.5 text-success" aria-hidden="true" /> : <Terminal className="size-3.5" aria-hidden="true" />}
                    Copy rule
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2"
                    onClick={() => copyToClipboard(JSON.stringify(mitigation, null, 2), "rule")}
                  >
                    {copied === "rule" ? <Check className="size-3.5 text-success" aria-hidden="true" /> : <Copy className="size-3.5" aria-hidden="true" />}
                    Copy JSON
                  </Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <FlowSpecPreview {...mitigation} />
                <p className="text-sm">
                  <span className="text-muted-foreground">Matches </span>
                  <span className="font-medium">{describeMatch(mitigation)}</span>
                  <span className="text-muted-foreground"> → </span>
                  <span className="font-mono">{mitigation.victim_ip}</span>
                </p>
                {mitigation.victim_ip.includes("/") && (
                  <p className="text-xs text-muted-foreground">
                    This mitigation and its report use the exact destination. Events and mitigations for individual addresses inside it are not aggregated.
                  </p>
                )}
                <FieldList className="grid-cols-2 sm:grid-cols-4">
                  <Field label="Destination prefix"><span className="font-mono">{mitigation.dst_prefix}</span></Field>
                  <Field label="Protocol">{protocolName(mitigation.protocol)}</Field>
                  <Field label="Destination ports"><span className="font-mono">{mitigation.dst_ports.length > 0 ? mitigation.dst_ports.join(", ") : "any"}</span></Field>
                  {mitigation.src_prefix ? (
                    <Field label="Source prefix"><span className="font-mono break-all">{mitigation.src_prefix}</span></Field>
                  ) : null}
                  {mitigation.src_ports?.length ? (
                    <Field label="Source ports"><span className="font-mono">{mitigation.src_ports.join(", ")}</span></Field>
                  ) : null}
                  {mitigation.fragment === "non_first" ? (
                    <Field label="Fragments">non-first fragments only</Field>
                  ) : null}
                  {mitigation.packet_length ? (
                    <Field label="Packet length">
                      <span className="tabular-nums">{mitigation.packet_length.min}–{mitigation.packet_length.max} bytes</span>
                    </Field>
                  ) : null}
                  <Field label="Action applied">
                    <span className="font-medium">{mitigation.action_type === "discard" ? "discard" : `rate-limit ${formatBps(mitigation.rate_bps)}`}</span>
                  </Field>
                </FieldList>
              </CardContent>
            </Card>
            )}

            {siblings.length > 0 && (
              <Card data-testid="sibling-rules">
                <CardHeader>
                  <CardTitle>Other rules from this event</CardTitle>
                </CardHeader>
                <CardContent>
                  <ul className="space-y-2">
                    {siblings.map((sibling) => (
                      <li key={sibling.mitigation_id} className="flex flex-wrap items-center gap-2 text-sm">
                        <StatusBadge status={sibling.status} />
                        <ActionBadge actionType={sibling.action_type} rateBps={sibling.rate_bps} />
                        <Link href={`/mitigations/${sibling.mitigation_id}`} className="min-w-0 break-words rounded-sm hover:underline">
                          {describeMatch(sibling)}
                        </Link>
                      </li>
                    ))}
                  </ul>
                  <p className="mt-3 text-xs text-muted-foreground">Each rule is withdrawn on its own.</p>
                </CardContent>
              </Card>
            )}

            <Card>
              <CardHeader>
                <CardTitle>Timeline</CardTitle>
              </CardHeader>
              <CardContent>
                <ol className="relative space-y-5 border-l pl-4">
                  <li className="relative">
                    <span aria-hidden="true" className="absolute -left-[21px] top-1.5 size-2.5 rounded-full bg-muted-foreground" />
                    <p className="text-sm font-medium">Created</p>
                    <p className="mt-0.5 text-xs text-muted-foreground tabular-nums">{formatTime(mitigation.created_at, now)}</p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Triggered by event{" "}
                      <Link
                        href={`/events?id=${encodeURIComponent(String(mitigation.triggering_event_id))}`}
                        className="rounded-sm font-mono text-foreground hover:underline"
                      >
                        {mitigation.triggering_event_id.slice(0, 8)}
                      </Link>
                    </p>
                  </li>

                  {mitigation.updated_at !== mitigation.created_at && (
                    <li className="relative">
                      <span aria-hidden="true" className="absolute -left-[21px] top-1.5 size-2.5 rounded-full bg-muted-foreground" />
                      <p className="text-sm font-medium">Updated</p>
                      <p className="mt-0.5 text-xs text-muted-foreground tabular-nums">{formatTime(mitigation.updated_at, now)}</p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Rule set to {mitigation.action_type}{mitigation.rate_bps ? ` (${formatBps(mitigation.rate_bps)})` : ""}
                      </p>
                    </li>
                  )}

                  {mitigation.withdrawn_at ? (
                    <li className="relative">
                      <span aria-hidden="true" className="absolute -left-[21px] top-1.5 size-2.5 rounded-full bg-muted-foreground" />
                      <p className="text-sm font-medium">Withdrawn</p>
                      <p className="mt-0.5 text-xs text-muted-foreground tabular-nums">{formatTime(mitigation.withdrawn_at, now)}</p>
                    </li>
                  ) : (
                    <li className="relative">
                      <span aria-hidden="true" className={expired ? "absolute -left-[21px] top-1.5 size-2.5 rounded-full bg-muted-foreground" : "absolute -left-[21px] top-1.5 size-2.5 rounded-full border-2 border-muted-foreground bg-card"} />
                      <p className="text-sm font-medium">{expired ? "Expired" : "Expires"}</p>
                      <p className="mt-0.5 text-xs text-muted-foreground tabular-nums">{formatTime(mitigation.expires_at, now)}</p>
                    </li>
                  )}
                </ol>
              </CardContent>
            </Card>

            {mitigation.correlation ? (
              <Card data-testid="correlation-card">
                <CardHeader className="flex flex-wrap items-center justify-between gap-2">
                  <CardTitle>Correlation</CardTitle>
                  {mitigation.correlation.corroboration_met ? (
                    <StatusPill tone="success" icon={<CheckCircle2 aria-hidden="true" />}>Corroborated</StatusPill>
                  ) : (
                    <StatusPill tone="warning" icon={<AlertTriangle aria-hidden="true" />}>Pending</StatusPill>
                  )}
                </CardHeader>
                <CardContent className="space-y-4">
                  <FieldList>
                    <Field label="Signal group">
                      <Link
                        href={`/correlation/groups/${mitigation.correlation.signal_group_id}`}
                        className="break-all rounded-sm font-mono hover:underline"
                      >
                        {mitigation.correlation.signal_group_id}
                      </Link>
                    </Field>
                    <Field label="Derived confidence">
                      <ConfidenceBar value={mitigation.correlation.derived_confidence} />
                    </Field>
                    <Field label="Sources" className="sm:col-span-2">
                      <span className="flex flex-wrap items-center gap-2">
                        <span className="tabular-nums">{mitigation.correlation.source_count} source{mitigation.correlation.source_count !== 1 ? "s" : ""}</span>
                        {mitigation.correlation.contributing_sources?.map((source) => (
                          <Tag key={source}>{source}</Tag>
                        ))}
                      </span>
                    </Field>
                  </FieldList>

                  {isSignalGroupLoading ? (
                    <div className="space-y-2">
                      <p className="text-xs text-muted-foreground">Contributing sources</p>
                      <Skeleton className="h-4 w-full" />
                      <Skeleton className="h-4 w-3/4" />
                    </div>
                  ) : signalGroupError && !signalGroupDetail ? (
                    <div className="rounded-md border">
                      <ErrorState
                        title="Unable to load contributing sources"
                        detail="The correlation summary above is unaffected. Retry, or open the signal group."
                        onRetry={() => { void mutateSignalGroup() }}
                      />
                    </div>
                  ) : signalGroupDetail?.events && signalGroupDetail.events.length > 0 ? (
                    <div>
                      <p className="mb-2 text-xs text-muted-foreground">Contributing sources</p>
                      <div className="overflow-hidden rounded-md border">
                        <Table>
                          <TableHeader>
                            <TableRow className="hover:bg-transparent">
                              <TableHead>Source</TableHead>
                              <TableHead className="text-right">Confidence</TableHead>
                              <TableHead className="text-right">Weight</TableHead>
                            </TableRow>
                          </TableHeader>
                          <TableBody>
                            {signalGroupDetail.events.map((event) => (
                              <TableRow key={event.event_id}>
                                <TableCell>{event.source}</TableCell>
                                <TableCell numeric>{formatConfidence(event.confidence)}</TableCell>
                                <TableCell numeric>{event.source_weight.toFixed(1)}</TableCell>
                              </TableRow>
                            ))}
                          </TableBody>
                        </Table>
                      </div>
                    </div>
                  ) : null}

                  {mitigation.correlation.explanation && (
                    <Field label="Why">
                      <span className="text-pretty">{mitigation.correlation.explanation}</span>
                    </Field>
                  )}
                </CardContent>
              </Card>
            ) : (
              <Card data-testid="no-correlation-card">
                <CardContent className="flex items-center gap-2 text-sm text-muted-foreground">
                  <Info className="size-4 shrink-0" aria-hidden="true" />
                  Single-source mitigation — no correlation data available.
                </CardContent>
              </Card>
            )}
          </div>

          <div className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle>Customer</CardTitle>
              </CardHeader>
              <CardContent>
                {customer ? (
                  <FieldList className="sm:grid-cols-1">
                    <Field label="Customer">
                      <span className="font-medium">{customer.name}</span>
                      <span className="block font-mono text-xs text-muted-foreground">{customer.customer_id}</span>
                    </Field>
                    {service && (
                      <Field label="Service affected">
                        <span className="font-medium">{service.name}</span>
                        <span className="block font-mono text-xs text-muted-foreground">{service.service_id}</span>
                      </Field>
                    )}
                    <Field label="Policy profile"><Tag>{customer.policy_profile}</Tag></Field>
                  </FieldList>
                ) : (
                  <p className="text-sm text-muted-foreground">No customer context found in inventory.</p>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Metadata</CardTitle>
              </CardHeader>
              <CardContent>
                <FieldList className="sm:grid-cols-1">
                  <Field label="Mitigation ID"><span className="break-all font-mono text-xs">{mitigation.mitigation_id}</span></Field>
                  <Field label="Scope hash"><span className="break-all font-mono text-xs">{mitigation.scope_hash}</span></Field>
                  <Field label="Triggering event">
                    <Link
                      href={`/events?id=${encodeURIComponent(String(mitigation.triggering_event_id))}`}
                      className="break-all rounded-sm font-mono text-xs hover:underline"
                    >
                      {mitigation.triggering_event_id}
                    </Link>
                  </Field>
                  {mitigation.last_event_id !== mitigation.triggering_event_id && (
                    <Field label="Last event (TTL extension)">
                      <Link
                        href={`/events?id=${encodeURIComponent(String(mitigation.last_event_id))}`}
                        className="break-all rounded-sm font-mono text-xs hover:underline"
                      >
                        {mitigation.last_event_id}
                      </Link>
                    </Field>
                  )}
                  {mitigation.reason && (
                    <Field label="Reason"><span className="text-pretty">{mitigation.reason}</span></Field>
                  )}
                </FieldList>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>

      {/* Withdraw Confirmation Dialog */}
      <AlertDialog open={showWithdrawDialog} onOpenChange={(open) => {
        if (!open && !withdrawInFlight.current) {
          setShowWithdrawDialog(false)
          setWithdrawReason("")
          setWithdrawError(null)
        }
      }}>
        <AlertDialogContent className="max-h-[calc(100dvh-2rem)] overflow-y-auto" onCloseAutoFocus={(event) => {
          event.preventDefault()
          const target = !withdrawCompleted.current && withdrawTrigger.current?.isConnected ? withdrawTrigger.current : victimLink.current
          target?.focus()
        }}>
          <AlertDialogHeader>
            <AlertDialogTitle>Withdraw Mitigation</AlertDialogTitle>
            <AlertDialogDescription>
              Request withdrawal for <span className="font-mono font-semibold">{mitigation?.victim_ip}</span>.
              Local completion is recorded in the audit log. Router convergence and traffic filtering are not verified here.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Label htmlFor="reason">Reason (optional)</Label>
            <Input
              id="reason"
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

      <IncidentReportDialog
        markdown={reportMarkdown}
        filename={`incident-${mitigation.victim_ip.replace(/[/:]/g, "-")}-${mitigation.mitigation_id.slice(0, 8)}.md`}
        open={showReportDialog}
        onOpenChange={setShowReportDialog}
        loading={reportLoading}
      />
    </>
  )
}
