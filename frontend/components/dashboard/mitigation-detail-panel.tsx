"use client"

import { useState } from "react"
import { motion } from "motion/react"
import { X, Copy, Check, AlertTriangle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { StatusBadge } from "./status-badge"
import { ActionBadge } from "./action-badge"
import type { Mitigation } from "@/lib/api"
import { withdrawMitigation } from "@/lib/api"
import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
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

interface MitigationDetailPanelProps {
  mitigation: Mitigation | null
  onClose: () => void
  onWithdraw?: () => void
}

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

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffSecs = Math.floor(Math.abs(diffMs) / 1000)
  const diffMins = Math.floor(diffSecs / 60)
  const diffHours = Math.floor(diffMins / 60)
  const diffDays = Math.floor(diffHours / 24)

  const suffix = diffMs > 0 ? "ago" : "from now"

  if (diffSecs < 60) return `${diffSecs}s ${suffix}`
  if (diffMins < 60) return `${diffMins}m ${suffix}`
  if (diffHours < 24) return `${diffHours}h ${suffix}`
  return `${diffDays}d ${suffix}`
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

export function MitigationDetailPanel({ mitigation, onClose, onWithdraw }: MitigationDetailPanelProps) {
  const [copied, setCopied] = useState<string | null>(null)
  const [showWithdrawDialog, setShowWithdrawDialog] = useState(false)
  const [withdrawReason, setWithdrawReason] = useState("")
  const [isWithdrawing, setIsWithdrawing] = useState(false)
  const [withdrawError, setWithdrawError] = useState<string | null>(null)
  const reducedMotion = useReducedMotion()

  if (!mitigation) return null

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopied(field)
    setTimeout(() => setCopied(null), 2000)
  }

  const handleWithdraw = async () => {
    setIsWithdrawing(true)
    setWithdrawError(null)
    try {
      await withdrawMitigation(mitigation.mitigation_id, withdrawReason || "Manual withdrawal", "dashboard")
      setShowWithdrawDialog(false)
      onWithdraw?.()
      onClose()
    } catch (e) {
      setWithdrawError(e instanceof Error ? e.message : "Failed to withdraw")
    } finally {
      setIsWithdrawing(false)
    }
  }

  const canWithdraw = mitigation.status === "active" || mitigation.status === "escalated"

  return (
    <>
      <motion.div
        initial={reducedMotion ? false : { x: "100%", opacity: 0.5 }}
        animate={{ x: 0, opacity: 1 }}
        exit={reducedMotion ? undefined : { x: "100%", opacity: 0.5 }}
        transition={{ duration: 0.15, ease: "easeOut" }}
        className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-background border-l border-border shadow-xl overflow-y-auto"
      >
        <div className="sticky top-0 bg-background border-b border-border px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-3">
            <StatusBadge status={mitigation.status} />
            <span className="font-mono text-lg font-semibold text-foreground">{mitigation.victim_ip}</span>
            <span className="rounded-md bg-secondary px-2 py-0.5 text-xs text-muted-foreground">
              {mitigation.vector.replace(/_/g, " ")}
            </span>
          </div>
          <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close panel">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <div className="p-6 space-y-6">
          {/* Info Grid */}
          <div className="grid grid-cols-2 gap-4">
            <InfoItem
              label="Mitigation ID"
              value={mitigation.mitigation_id}
              mono
              copyable
              copied={copied === "id"}
              onCopy={() => copyToClipboard(mitigation.mitigation_id, "id")}
            />
            <InfoItem
              label="Scope Hash"
              value={mitigation.scope_hash}
              mono
              copyable
              copied={copied === "hash"}
              onCopy={() => copyToClipboard(mitigation.scope_hash, "hash")}
            />
            <InfoItem label="Customer" value={mitigation.customer_id || "N/A"} />
            <InfoItem label="Service" value={mitigation.service_id || "N/A"} />
            <InfoItem label="POP" value={mitigation.pop} mono />
            <InfoItem
              label="Triggering Event"
              value={mitigation.triggering_event_id.slice(0, 8) + "..."}
              mono
              copyable
              copied={copied === "event"}
              onCopy={() => copyToClipboard(mitigation.triggering_event_id, "event")}
            />
          </div>

          {/* Reason */}
          {mitigation.reason && (
            <Card className="bg-secondary/50 border-border">
              <CardContent className="pt-4">
                <p className="text-sm text-muted-foreground">{mitigation.reason}</p>
              </CardContent>
            </Card>
          )}

          {/* Match Criteria */}
          <Card className="bg-secondary border-border">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Match Criteria</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Destination</span>
                <span className="font-mono text-sm text-foreground">{mitigation.dst_prefix}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Protocol</span>
                <span className="font-mono text-sm text-foreground">{protocolName(mitigation.protocol)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Ports</span>
                <span className="font-mono text-sm text-foreground">
                  {mitigation.dst_ports.length > 0 ? mitigation.dst_ports.join(", ") : "any"}
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Action */}
          <Card className="bg-secondary border-border">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Action</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between items-center">
                <span className="text-sm text-muted-foreground">Type</span>
                <ActionBadge actionType={mitigation.action_type} rateBps={mitigation.rate_bps} />
              </div>
              {mitigation.rate_bps && (
                <>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Rate Limit</span>
                    <span className="font-mono text-sm text-foreground">
                      {mitigation.rate_bps.toLocaleString()} bps
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Formatted</span>
                    <span className="font-mono text-sm text-primary">{formatBps(mitigation.rate_bps)}</span>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          {/* Timestamps */}
          <Card className="bg-secondary border-border">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Timeline</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Created</span>
                <span className="font-mono text-sm text-foreground">{formatTimestamp(mitigation.created_at)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Last Updated</span>
                <span className="font-mono text-sm text-foreground">{formatRelativeTime(mitigation.updated_at)}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-sm text-muted-foreground">Expires</span>
                <span className={cn(
                  "font-mono text-sm",
                  new Date(mitigation.expires_at) < new Date() ? "text-destructive" : "text-foreground"
                )}>
                  {formatRelativeTime(mitigation.expires_at)}
                </span>
              </div>
              {mitigation.withdrawn_at && (
                <div className="flex justify-between">
                  <span className="text-sm text-muted-foreground">Withdrawn</span>
                  <span className="font-mono text-sm text-muted-foreground">
                    {formatTimestamp(mitigation.withdrawn_at)}
                  </span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Action Buttons */}
          <div className="pt-4">
            <Button
              variant="destructive"
              className="w-full"
              disabled={!canWithdraw}
              onClick={() => setShowWithdrawDialog(true)}
            >
              <AlertTriangle className="h-4 w-4 mr-2" />
              Withdraw Mitigation
            </Button>
            {!canWithdraw && (
              <p className="text-xs text-muted-foreground text-center mt-2">
                Only active or escalated mitigations can be withdrawn
              </p>
            )}
          </div>
        </div>
      </motion.div>

      {/* Withdraw Confirmation Dialog */}
      <AlertDialog open={showWithdrawDialog} onOpenChange={setShowWithdrawDialog}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Withdraw Mitigation</AlertDialogTitle>
            <AlertDialogDescription>
              This will immediately withdraw the FlowSpec rule from all BGP peers. 
              Traffic to <span className="font-mono font-semibold">{mitigation.victim_ip}</span> will 
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
    </>
  )
}

function InfoItem({
  label,
  value,
  mono,
  copyable,
  copied,
  onCopy,
}: {
  label: string
  value: string
  mono?: boolean
  copyable?: boolean
  copied?: boolean
  onCopy?: () => void
}) {
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-1">{label}</p>
      <div className="flex items-center gap-1">
        <span className={cn("text-sm text-foreground truncate", mono && "font-mono")}>{value}</span>
        {copyable && onCopy && (
          <button
            onClick={onCopy}
            className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors shrink-0"
            aria-label={`Copy ${label}`}
          >
            {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
          </button>
        )}
      </div>
    </div>
  )
}
