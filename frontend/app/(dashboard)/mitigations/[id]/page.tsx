"use client"

import { use } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { useMitigation, useConfigInventory, useSignalGroupDetail } from "@/hooks/use-api"
import { StatusBadge } from "@/components/dashboard/status-badge"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Skeleton } from "@/components/ui/skeleton"
import { ArrowLeft, Check, Clock, Copy, FileText, ShieldAlert, Activity, GitBranch, RefreshCw, AlertTriangle, User, Terminal, Layers, CheckCircle2, Info } from "lucide-react"
import { FlowSpecPreview, formatFlowSpecRule } from "@/components/dashboard/flowspec-preview"
import { IncidentReportDialog } from "@/components/dashboard/incident-report-dialog"
import { withdrawMitigation, getIncidentReport } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { toast } from "sonner"
import { useState } from "react"
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
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { usePermissions } from "@/hooks/use-permissions"
import { cn } from "@/lib/utils"

function formatBps(bps: number | null): string {
  if (!bps) return "N/A"
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbps`
  if (bps >= 1_000) return `${(bps / 1_000).toFixed(1)} Kbps`
  return `${bps} bps`
}

function formatTimestamp(dateStr: string): string {
  return new Date(dateStr).toLocaleString("en-US", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  }) + " UTC"
}

function protocolName(proto: number | null): string {
  if (proto === null) return "any"
  switch (proto) {
    case 1: return "ICMP"
    case 6: return "TCP"
    case 17: return "UDP"
    default: return `${proto}`
  }
}

export default function MitigationDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params)
  const router = useRouter()
  const permissions = usePermissions()

  const { data: mitigation, isLoading, mutate } = useMitigation(id)
  const { data: inventory } = useConfigInventory()
  const { data: signalGroupDetail, isLoading: isSignalGroupLoading } = useSignalGroupDetail(
    mitigation?.correlation?.signal_group_id ?? null
  )

  const [copied, setCopied] = useState<string | null>(null)
  const [showWithdrawDialog, setShowWithdrawDialog] = useState(false)
  const [withdrawReason, setWithdrawReason] = useState("")
  const [isWithdrawing, setIsWithdrawing] = useState(false)
  const [withdrawError, setWithdrawError] = useState<string | null>(null)
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
    if (!mitigation) return
    setIsWithdrawing(true)
    setWithdrawError(null)
    try {
      await withdrawMitigation(mitigation.mitigation_id, withdrawReason || "Manual withdrawal", "dashboard")
      setShowWithdrawDialog(false)
      mutate()
    } catch (e) {
      setWithdrawError(e instanceof Error ? e.message : "Failed to withdraw")
    } finally {
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
      <DashboardLayout>
        <div className="flex h-[50vh] items-center justify-center">
          <RefreshCw className="h-8 w-8 animate-spin text-muted-foreground" />
        </div>
      </DashboardLayout>
    )
  }

  if (!mitigation) {
    return (
      <DashboardLayout>
        <div className="flex flex-col items-center justify-center h-[50vh] space-y-4">
          <ShieldAlert className="h-12 w-12 text-muted-foreground" />
          <h2 className="text-xl font-semibold">Mitigation Not Found</h2>
          <p className="text-muted-foreground">The requested mitigation ID does not exist or has expired entirely.</p>
          <Button variant="outline" onClick={() => router.push("/mitigations")}>
            <ArrowLeft className="mr-2 h-4 w-4" /> Back to Mitigations
          </Button>
        </div>
      </DashboardLayout>
    )
  }

  const canWithdraw = mitigation.status === "active" || mitigation.status === "escalated"

  // Find customer context
  const customer = inventory?.customers.find(c => c.customer_id === mitigation.customer_id)
  const service = customer?.services.find(s => s.service_id === mitigation.service_id)

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header Section */}
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div>
            <Button variant="ghost" size="sm" onClick={() => router.back()} className="-ml-3 mb-2 text-muted-foreground">
              <ArrowLeft className="mr-2 h-4 w-4" /> Back
            </Button>
            <div className="flex items-center gap-3 mt-1">
              <StatusBadge status={mitigation.status} />
              <Link
                href={`/ip-history?ip=${encodeURIComponent(mitigation.victim_ip)}`}
                className="text-2xl font-bold font-mono tracking-tight text-primary hover:underline"
              >
                {mitigation.victim_ip}
              </Link>
            </div>
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="outline" className="font-mono text-muted-foreground">
                {mitigation.vector.replace(/_/g, " ")}
              </Badge>
              <span className="text-muted-foreground text-sm">POP: {mitigation.pop}</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <div className="text-sm text-muted-foreground mb-1">Current Action</div>
              <ActionBadge actionType={mitigation.action_type} rateBps={mitigation.rate_bps} />
            </div>
            <Button variant="outline" size="sm" onClick={handleGenerateReport}>
              <FileText className="h-4 w-4 mr-2" />
              Report
            </Button>
            {permissions.canWithdraw && canWithdraw ? (
              <Button
                variant="destructive"
                onClick={() => setShowWithdrawDialog(true)}
                className="ml-2"
              >
                <AlertTriangle className="h-4 w-4 mr-2" />
                Withdraw
              </Button>
            ) : null}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main Info Column */}
          <div className="lg:col-span-2 space-y-6">

            {/* FlowSpec Rule Preview */}
            <Card className="border-border shadow-sm">
              <CardHeader className="bg-secondary/30 pb-4 border-b border-border">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <GitBranch className="h-5 w-5 text-muted-foreground" />
                    <CardTitle className="text-base font-semibold">FlowSpec Rule</CardTitle>
                  </div>
                  <div className="flex items-center gap-1">
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 px-2"
                      onClick={() => copyToClipboard(formatFlowSpecRule(mitigation), "flowspec")}
                    >
                      {copied === "flowspec" ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Terminal className="h-3.5 w-3.5" />}
                      <span className="ml-2 text-xs">Copy Rule</span>
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-8 px-2"
                      onClick={() => copyToClipboard(JSON.stringify(mitigation, null, 2), "rule")}
                    >
                      {copied === "rule" ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
                      <span className="ml-2 text-xs">Copy JSON</span>
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="p-0">
                <FlowSpecPreview
                  dst_prefix={mitigation.dst_prefix}
                  protocol={mitigation.protocol}
                  dst_ports={mitigation.dst_ports}
                  action_type={mitigation.action_type}
                  rate_bps={mitigation.rate_bps}
                />
                <div className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-border">
                  <div className="p-4">
                    <p className="text-xs text-muted-foreground mb-1">Destination Prefix</p>
                    <p className="font-mono text-sm">{mitigation.dst_prefix}</p>
                  </div>
                  <div className="p-4">
                    <p className="text-xs text-muted-foreground mb-1">Protocol</p>
                    <p className="font-mono text-sm">{protocolName(mitigation.protocol)}</p>
                  </div>
                  <div className="p-4">
                    <p className="text-xs text-muted-foreground mb-1">Destination Ports</p>
                    <p className="font-mono text-sm">{mitigation.dst_ports.length > 0 ? mitigation.dst_ports.join(", ") : "Any"}</p>
                  </div>
                  <div className="p-4 bg-secondary/10">
                    <p className="text-xs text-muted-foreground mb-1">Action Applied</p>
                    <p className="font-mono text-sm text-primary font-medium">
                      {mitigation.action_type === "discard" ? "discard" : `rate-limit ${formatBps(mitigation.rate_bps)}`}
                    </p>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Timeline */}
            <Card className="border-border shadow-sm">
              <CardHeader className="pb-4">
                <div className="flex items-center gap-2">
                  <Clock className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">Mitigation Timeline</CardTitle>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-6 pl-4 border-l-2 border-muted relative">

                  {/* Created */}
                  <div className="relative">
                    <div className="absolute -left-[21px] top-1 h-3 w-3 rounded-full bg-primary" />
                    <div>
                      <p className="text-sm font-medium">Mitigation Created</p>
                      <p className="text-xs text-muted-foreground font-mono mt-1">
                        {formatTimestamp(mitigation.created_at)}
                      </p>
                      <p className="text-xs text-muted-foreground mt-2">
                        Triggered by event{" "}
                        <Link
                          href={`/events?id=${encodeURIComponent(String(mitigation.triggering_event_id))}`}
                          className="font-mono text-primary hover:underline"
                        >
                          {mitigation.triggering_event_id.slice(0, 8)}
                        </Link>
                      </p>
                    </div>
                  </div>

                  {/* Updated/Escalated (if different from created) */}
                  {mitigation.updated_at !== mitigation.created_at && (
                    <div className="relative">
                      <div className="absolute -left-[21px] top-1 h-3 w-3 rounded-full bg-yellow-500" />
                      <div>
                        <p className="text-sm font-medium">Mitigation Escalated / Updated</p>
                        <p className="text-xs text-muted-foreground font-mono mt-1">
                          {formatTimestamp(mitigation.updated_at)}
                        </p>
                        <p className="text-xs text-muted-foreground mt-2">
                          Rule updated to {mitigation.action_type} {mitigation.rate_bps ? `(${formatBps(mitigation.rate_bps)})` : ""}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Withdrawn */}
                  {mitigation.withdrawn_at && (
                    <div className="relative">
                      <div className="absolute -left-[21px] top-1 h-3 w-3 rounded-full bg-muted-foreground" />
                      <div>
                        <p className="text-sm font-medium">Mitigation Withdrawn</p>
                        <p className="text-xs text-muted-foreground font-mono mt-1">
                          {formatTimestamp(mitigation.withdrawn_at)}
                        </p>
                      </div>
                    </div>
                  )}

                  {/* Expiry */}
                  {!mitigation.withdrawn_at && (
                    <div className="relative">
                      <div className={cn(
                        "absolute -left-[21px] top-1 h-3 w-3 rounded-full",
                        new Date(mitigation.expires_at) < new Date() ? "bg-muted-foreground" : "bg-border border-2 border-background"
                      )} />
                      <div>
                        <p className="text-sm font-medium">
                          {new Date(mitigation.expires_at) < new Date() ? "Expired" : "Expires"}
                        </p>
                        <p className="text-xs text-muted-foreground font-mono mt-1">
                          {formatTimestamp(mitigation.expires_at)}
                        </p>
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Correlation Section */}
            {mitigation.correlation ? (
              <Card className="border-border shadow-sm" data-testid="correlation-card">
                <CardHeader className="pb-4">
                  <div className="flex items-center gap-2">
                    <Layers className="h-5 w-5 text-muted-foreground" />
                    <CardTitle className="text-base font-semibold">Correlation</CardTitle>
                    {mitigation.correlation.corroboration_met ? (
                      <Badge variant="default" className="ml-auto bg-green-600 hover:bg-green-600 text-xs">
                        <CheckCircle2 className="h-3 w-3 mr-1" />
                        Corroborated
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="ml-auto text-amber-600 dark:text-amber-400 border-amber-400 text-xs">
                        <AlertTriangle className="h-3 w-3 mr-1" />
                        Pending
                      </Badge>
                    )}
                  </div>
                </CardHeader>
                <CardContent className="space-y-5">
                  {/* Signal Group Link */}
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Signal Group</p>
                    <Link
                      href={`/correlation/groups/${mitigation.correlation.signal_group_id}`}
                      className="text-sm font-mono text-primary hover:underline"
                    >
                      {mitigation.correlation.signal_group_id}
                    </Link>
                  </div>

                  {/* Derived Confidence with visual bar */}
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Derived Confidence</p>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                        <div
                          className="h-full rounded-full bg-primary transition-all"
                          style={{ width: `${Math.round(mitigation.correlation.derived_confidence * 100)}%` }}
                        />
                      </div>
                      <span className="text-sm font-mono font-medium tabular-nums w-10 text-right">
                        {Math.round(mitigation.correlation.derived_confidence * 100)}%
                      </span>
                    </div>
                  </div>

                  {/* Source Count with source names */}
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Sources</p>
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-mono">{mitigation.correlation.source_count} source{mitigation.correlation.source_count !== 1 ? "s" : ""}</span>
                      {mitigation.correlation.contributing_sources?.map((source) => (
                        <Badge key={source} variant="outline" className="text-[10px] font-mono">
                          {source}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Contributing Sources Table (from signal group detail) */}
                  {isSignalGroupLoading ? (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Contributing Sources</p>
                      <div className="space-y-2">
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-full" />
                        <Skeleton className="h-4 w-3/4" />
                      </div>
                    </div>
                  ) : signalGroupDetail?.events && signalGroupDetail.events.length > 0 ? (
                    <div>
                      <p className="text-xs text-muted-foreground mb-2">Contributing Sources</p>
                      <div className="overflow-x-auto">
                        <table className="w-full text-xs font-mono">
                          <thead>
                            <tr className="border-b border-border text-left text-muted-foreground">
                              <th className="pb-2 pr-3 font-medium">Source</th>
                              <th className="pb-2 pr-3 font-medium text-right">Confidence</th>
                              <th className="pb-2 font-medium text-right">Weight</th>
                            </tr>
                          </thead>
                          <tbody>
                            {signalGroupDetail.events.map((event) => (
                              <tr key={event.event_id} className="border-b border-border/50 last:border-0">
                                <td className="py-1.5 pr-3">{event.source}</td>
                                <td className="py-1.5 pr-3 text-right tabular-nums">
                                  {event.confidence != null ? `${Math.round(event.confidence * 100)}%` : "N/A"}
                                </td>
                                <td className="py-1.5 text-right tabular-nums">{event.source_weight.toFixed(1)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ) : null}

                  {/* Why Explanation */}
                  {mitigation.correlation.explanation && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Why</p>
                      <p className="text-sm text-foreground/80 leading-relaxed">
                        {mitigation.correlation.explanation}
                      </p>
                    </div>
                  )}
                </CardContent>
              </Card>
            ) : (
              <Card className="border-border shadow-sm bg-secondary/5" data-testid="no-correlation-card">
                <CardContent className="py-4">
                  <div className="flex items-center gap-2">
                    <Info className="h-4 w-4 text-muted-foreground" />
                    <p className="text-sm text-muted-foreground">
                      Single-source mitigation — no correlation data available.
                    </p>
                  </div>
                </CardContent>
              </Card>
            )}

          </div>

          {/* Sidebar Column */}
          <div className="space-y-6">
            {/* Customer Context */}
            <Card className="border-border shadow-sm">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <User className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">Customer Context</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {customer ? (
                  <>
                    <div>
                      <p className="text-xs text-muted-foreground">Customer</p>
                      <p className="text-sm font-medium mt-1">{customer.name}</p>
                      <p className="text-xs font-mono text-muted-foreground mt-1">{customer.customer_id}</p>
                    </div>
                    {service && (
                      <div>
                        <p className="text-xs text-muted-foreground">Service Affected</p>
                        <p className="text-sm font-medium mt-1">{service.name}</p>
                        <p className="text-xs font-mono text-muted-foreground mt-1">{service.service_id}</p>
                      </div>
                    )}
                    <div>
                      <p className="text-xs text-muted-foreground">Policy Profile</p>
                      <Badge variant="outline" className="mt-1 font-mono text-xs">{customer.policy_profile}</Badge>
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground italic">No customer context found in inventory.</p>
                )}
              </CardContent>
            </Card>

            {/* Metadata */}
            <Card className="border-border shadow-sm bg-secondary/10">
              <CardHeader className="pb-3">
                <div className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base font-semibold">Metadata</CardTitle>
                </div>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Mitigation ID</p>
                  <p className="text-xs font-mono break-all">{mitigation.mitigation_id}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Scope Hash</p>
                  <p className="text-xs font-mono break-all">{mitigation.scope_hash}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Triggering Event</p>
                  <Link
                    href={`/events?id=${encodeURIComponent(String(mitigation.triggering_event_id))}`}
                    className="text-xs font-mono text-primary hover:underline break-all"
                  >
                    {mitigation.triggering_event_id}
                  </Link>
                </div>
                {mitigation.last_event_id !== mitigation.triggering_event_id && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Last Event (TTL extend)</p>
                    <Link
                      href={`/events?id=${encodeURIComponent(String(mitigation.last_event_id))}`}
                      className="text-xs font-mono text-primary hover:underline break-all"
                    >
                      {mitigation.last_event_id}
                    </Link>
                  </div>
                )}
                {mitigation.reason && (
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Reason</p>
                    <p className="text-sm italic">{mitigation.reason}</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

      </div>

      {/* Withdraw Confirmation Dialog */}
      <AlertDialog open={showWithdrawDialog} onOpenChange={setShowWithdrawDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Withdraw Mitigation</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately withdraw the FlowSpec rule from all BGP peers. 
              Traffic to <span className="font-mono font-semibold">{mitigation?.victim_ip}</span> will 
              no longer be filtered.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <div className="py-4">
            <Label htmlFor="reason">Reason (optional)</Label>
            <Input
              id="reason"
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

      <IncidentReportDialog
        markdown={reportMarkdown}
        filename={`incident-${mitigation.victim_ip}-${mitigation.mitigation_id.slice(0, 8)}.md`}
        open={showReportDialog}
        onOpenChange={setShowReportDialog}
        loading={reportLoading}
      />
    </DashboardLayout>
  )
}
