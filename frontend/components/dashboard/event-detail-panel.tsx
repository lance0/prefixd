"use client"

import { useState } from "react"
import { motion } from "motion/react"
import { X, Copy, Check, ExternalLink } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { SourceBadge } from "./source-badge"
import { ConfidenceBar } from "./confidence-bar"
import type { Event } from "@/lib/api"
import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/use-reduced-motion"

interface EventDetailPanelProps {
  event: Event | null
  onClose: () => void
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

  if (diffSecs < 60) return `${diffSecs}s ago`
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  return `${diffDays}d ago`
}

function protocolName(proto: number | null): string {
  if (proto === null) return "N/A"
  switch (proto) {
    case 1: return "ICMP (1)"
    case 6: return "TCP (6)"
    case 17: return "UDP (17)"
    default: return `${proto}`
  }
}

function parsePorts(portsJson: string): number[] {
  try {
    return JSON.parse(portsJson) || []
  } catch {
    return []
  }
}

export function EventDetailPanel({ event, onClose }: EventDetailPanelProps) {
  const [copied, setCopied] = useState<string | null>(null)
  const reducedMotion = useReducedMotion()

  if (!event) return null

  const copyToClipboard = (text: string, field: string) => {
    navigator.clipboard.writeText(text)
    setCopied(field)
    setTimeout(() => setCopied(null), 2000)
  }

  const ports = parsePorts(event.top_dst_ports_json)

  return (
    <motion.div
      initial={reducedMotion ? false : { x: "100%", opacity: 0.5 }}
      animate={{ x: 0, opacity: 1 }}
      exit={reducedMotion ? undefined : { x: "100%", opacity: 0.5 }}
      transition={{ duration: 0.15, ease: "easeOut" }}
      className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-background border-l border-border shadow-xl overflow-y-auto"
    >
      <div className="sticky top-0 bg-background border-b border-border px-6 py-4 flex items-center justify-between z-10">
        <div className="flex items-center gap-3">
          <SourceBadge source={event.source} />
          <a
            href={`/ip-history?ip=${encodeURIComponent(event.victim_ip)}`}
            className="font-mono text-lg font-semibold text-primary hover:underline"
          >
            {event.victim_ip}
          </a>
          <span className="rounded-md bg-secondary px-2 py-0.5 text-xs text-muted-foreground">
            {event.vector.replace(/_/g, " ")}
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
            label="Event ID"
            value={event.event_id}
            mono
            copyable
            copied={copied === "id"}
            onCopy={() => copyToClipboard(event.event_id, "id")}
          />
          {event.external_event_id && (
            <InfoItem
              label="External ID"
              value={event.external_event_id}
              mono
              copyable
              copied={copied === "ext"}
              onCopy={() => copyToClipboard(event.external_event_id!, "ext")}
            />
          )}
          <InfoItem label="Source" value={event.source} />
          <InfoItem label="Vector" value={event.vector.replace(/_/g, " ")} />
        </div>

        {/* Traffic Stats */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Traffic Statistics</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-muted-foreground mb-1">Bandwidth</p>
                <p className="font-mono text-2xl font-semibold text-foreground">{formatBps(event.bps)}</p>
                {event.bps && (
                  <p className="text-xs text-muted-foreground">{event.bps.toLocaleString()} bps</p>
                )}
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-1">Packet Rate</p>
                <p className="font-mono text-2xl font-semibold text-foreground">{formatPps(event.pps)}</p>
                {event.pps && (
                  <p className="text-xs text-muted-foreground">{event.pps.toLocaleString()} pps</p>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Match Details */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Attack Details</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Protocol</span>
              <span className="font-mono text-sm text-foreground">{protocolName(event.protocol)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Top Destination Ports</span>
              <span className="font-mono text-sm text-foreground">
                {ports.length > 0 ? ports.join(", ") : "N/A"}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Confidence */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Confidence Score</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-4">
              <div className="flex-1">
                <ConfidenceBar value={event.confidence || 0} />
              </div>
              <span className="font-mono text-lg font-semibold text-foreground">
                {event.confidence ? `${Math.round(event.confidence * 100)}%` : "N/A"}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-2">
              {event.confidence && event.confidence >= 0.8
                ? "High confidence - automatic mitigation applied"
                : event.confidence && event.confidence >= 0.5
                  ? "Medium confidence - review recommended"
                  : "Low confidence - may be rejected by policy"}
            </p>
          </CardContent>
        </Card>

        {/* Timestamps */}
        <Card className="bg-secondary border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Timeline</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Event Time</span>
              <span className="font-mono text-sm text-foreground">{formatTimestamp(event.event_timestamp)}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-sm text-muted-foreground">Ingested</span>
              <span className="font-mono text-sm text-foreground">{formatRelativeTime(event.ingested_at)}</span>
            </div>
          </CardContent>
        </Card>

        {/* Link to mitigations */}
        <div className="pt-2">
          <Link href={`/mitigations?ip=${event.victim_ip}`}>
            <Button variant="outline" className="w-full">
              <ExternalLink className="h-4 w-4 mr-2" />
              View Mitigations for {event.victim_ip}
            </Button>
          </Link>
        </div>
      </div>
    </motion.div>
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
