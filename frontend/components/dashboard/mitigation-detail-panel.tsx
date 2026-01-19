"use client"

import { X, Copy, ExternalLink } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { StatusBadge } from "./status-badge"
import { ActionBadge } from "./action-badge"
import { type Mitigation, formatBps, formatTimestamp, formatRelativeTime } from "@/lib/mock-data"
import { cn } from "@/lib/utils"

interface MitigationDetailPanelProps {
  mitigation: Mitigation | null
  onClose: () => void
}

export function MitigationDetailPanel({ mitigation, onClose }: MitigationDetailPanelProps) {
  if (!mitigation) return null

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-background border-l border-border shadow-xl overflow-y-auto">
      <div className="sticky top-0 bg-background border-b border-border px-6 py-4 flex items-center justify-between z-10">
        <div className="flex items-center gap-3">
          <StatusBadge status={mitigation.status} />
          <span className="font-mono text-lg font-semibold text-foreground">{mitigation.victimIp}</span>
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
            value={mitigation.id}
            mono
            copyable
            onCopy={() => copyToClipboard(mitigation.id)}
          />
          <InfoItem
            label="Scope Hash"
            value={mitigation.scopeHash}
            mono
            copyable
            onCopy={() => copyToClipboard(mitigation.scopeHash)}
          />
          <InfoItem label="Customer" value={mitigation.customer} />
          <InfoItem label="Service" value={mitigation.service} />
          <InfoItem label="Created" value={formatTimestamp(mitigation.createdAt)} mono />
          <InfoItem label="Expires" value={formatTimestamp(mitigation.expiresAt)} mono />
          <InfoItem
            label="Triggering Event"
            value={mitigation.triggeringEventId}
            mono
            link
            href={`/events?id=${mitigation.triggeringEventId}`}
          />
        </div>

        {/* Match Criteria */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Match Criteria</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Destination</span>
              <span className="font-mono text-sm text-foreground">{mitigation.match.destination}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Protocol</span>
              <span className="font-mono text-sm text-foreground">{mitigation.match.protocol}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Ports</span>
              <span className="font-mono text-sm text-foreground">{mitigation.match.ports}</span>
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
              <ActionBadge type={mitigation.action.type} rate={mitigation.action.rate} />
            </div>
            {mitigation.action.rate && (
              <>
                <div className="flex justify-between">
                  <span className="text-sm text-muted-foreground">Rate</span>
                  <span className="font-mono text-sm text-foreground">
                    {mitigation.action.rate.toLocaleString()} bps
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-sm text-muted-foreground">Formatted</span>
                  <span className="font-mono text-sm text-primary">{formatBps(mitigation.action.rate)}</span>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Announcement Status */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Announcement Status</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border">
                    <th className="text-left py-2 font-medium text-muted-foreground">Peer</th>
                    <th className="text-left py-2 font-medium text-muted-foreground">Status</th>
                    <th className="text-left py-2 font-medium text-muted-foreground">Announced At</th>
                    <th className="text-right py-2 font-medium text-muted-foreground">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {mitigation.announcements.map((announcement) => (
                    <tr key={announcement.peer} className="border-b border-border/50">
                      <td className="py-2 font-mono text-foreground">{announcement.peer}</td>
                      <td className="py-2">
                        <StatusBadge status={announcement.status} size="sm" />
                      </td>
                      <td className="py-2 font-mono text-muted-foreground">
                        {formatTimestamp(announcement.announcedAt)}
                      </td>
                      <td className="py-2 text-right font-mono text-foreground">{announcement.latency}ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Timeline */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <TimelineStep label="Created" time={formatRelativeTime(mitigation.createdAt)} active />
              <TimelineConnector />
              <TimelineStep label="Announced" time={formatRelativeTime(mitigation.createdAt)} active />
              <TimelineConnector />
              <TimelineStep
                label={mitigation.status === "expired" ? "Expired" : "Active"}
                time={mitigation.status === "expired" ? formatRelativeTime(mitigation.expiresAt) : "now"}
                active={mitigation.status !== "expired"}
                current={mitigation.status !== "expired"}
              />
            </div>
          </CardContent>
        </Card>

        {/* Action Buttons */}
        <div className="pt-4">
          <Button variant="destructive" className="w-full" disabled={mitigation.status !== "active" && mitigation.status !== "escalated"}>
            Withdraw Mitigation
          </Button>
        </div>
      </div>
    </div>
  )
}

function InfoItem({
  label,
  value,
  mono,
  copyable,
  onCopy,
  link,
  href,
}: {
  label: string
  value: string
  mono?: boolean
  copyable?: boolean
  onCopy?: () => void
  link?: boolean
  href?: string
}) {
  return (
    <div>
      <p className="text-xs text-muted-foreground mb-1">{label}</p>
      <div className="flex items-center gap-1">
        {link && href ? (
          <a
            href={href}
            className={cn("text-sm text-primary hover:underline flex items-center gap-1", mono && "font-mono")}
          >
            {value}
            <ExternalLink className="h-3 w-3" />
          </a>
        ) : (
          <span className={cn("text-sm text-foreground", mono && "font-mono")}>{value}</span>
        )}
        {copyable && onCopy && (
          <button
            onClick={onCopy}
            className="p-1 rounded hover:bg-muted text-muted-foreground hover:text-foreground transition-colors"
          >
            <Copy className="h-3 w-3" />
          </button>
        )}
      </div>
    </div>
  )
}

function TimelineStep({
  label,
  time,
  active,
  current,
}: {
  label: string
  time: string
  active?: boolean
  current?: boolean
}) {
  return (
    <div className="flex flex-col items-center">
      <div
        className={cn(
          "h-3 w-3 rounded-full border-2",
          active ? "border-primary bg-primary" : "border-muted-foreground bg-transparent",
          current && "status-glow-cyan",
        )}
      />
      <span className={cn("text-xs mt-1", active ? "text-foreground" : "text-muted-foreground")}>{label}</span>
      <span className="text-xs text-muted-foreground">{time}</span>
    </div>
  )
}

function TimelineConnector() {
  return <div className="flex-1 h-0.5 bg-border" />
}
