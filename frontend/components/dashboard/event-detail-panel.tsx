"use client"

import { useState } from "react"
import { motion } from "motion/react"
import { X, Copy, Check, ExternalLink } from "lucide-react"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tag } from "./status-pill"
import { Field, FieldList } from "./field"
import { ConfidenceBar } from "./confidence-bar"
import type { Event } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/use-reduced-motion"
import { isConfidence } from "@/lib/confidence"
import { MISSING, formatBps, formatPps, formatRelative, formatUtc } from "@/lib/format"

interface EventDetailPanelProps {
  event: Event | null
  onClose: () => void
}

function protocolName(proto: number | null): string {
  if (proto === null) return MISSING
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

  const copyToClipboard = async (text: string, field: string) => {
    if (!(await copyText(text))) {
      toast.error("Copy failed — clipboard unavailable")
      return
    }
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
      className="fixed inset-y-0 right-0 z-50 w-full max-w-lg overflow-y-auto overscroll-contain border-l bg-popover shadow-md"
    >
      <div className="sticky top-0 z-10 flex items-center justify-between gap-3 border-b bg-popover px-4 py-3">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <Link
            href={`/ip-history?ip=${encodeURIComponent(event.victim_ip)}`}
            className="break-all rounded-sm font-mono text-base font-semibold hover:underline"
          >
            {event.victim_ip}
          </Link>
          <Tag>{event.vector.replace(/_/g, " ")}</Tag>
          <Tag>{event.source}</Tag>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} aria-label="Close panel">
          <X className="size-4" aria-hidden="true" />
        </Button>
      </div>

      <div className="space-y-4 p-4">
        <FieldList>
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
          <Field label="Source">{event.source}</Field>
          <Field label="Vector">{event.vector.replace(/_/g, " ")}</Field>
        </FieldList>

        <Card>
          <CardHeader>
            <CardTitle>Traffic</CardTitle>
          </CardHeader>
          <CardContent>
            <FieldList className="grid-cols-2">
              <Field label="Bandwidth">
                <span className="text-xl font-semibold tabular-nums">{formatBps(event.bps)}</span>
                {event.bps ? <span className="block text-xs text-muted-foreground tabular-nums">{event.bps.toLocaleString("en-US")}&nbsp;bps</span> : null}
              </Field>
              <Field label="Packet rate">
                <span className="text-xl font-semibold tabular-nums">{formatPps(event.pps)}</span>
                {event.pps ? <span className="block text-xs text-muted-foreground tabular-nums">{event.pps.toLocaleString("en-US")}&nbsp;pps</span> : null}
              </Field>
            </FieldList>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Attack details</CardTitle>
          </CardHeader>
          <CardContent>
            <FieldList className="grid-cols-2">
              <Field label="Protocol">{protocolName(event.protocol)}</Field>
              <Field label="Top destination ports">
                <span className="font-mono">{ports.length > 0 ? ports.join(", ") : MISSING}</span>
              </Field>
            </FieldList>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Confidence</CardTitle>
          </CardHeader>
          <CardContent>
            <ConfidenceBar value={event.confidence} />
            <p className="mt-2 text-xs text-muted-foreground text-pretty">
              {isConfidence(event.confidence)
                ? event.confidence >= 0.8
                  ? "High reported confidence."
                  : event.confidence >= 0.5
                    ? "Medium reported confidence."
                    : "Low reported confidence."
                : "No valid confidence reported."}{" "}
              Confidence alone does not confirm mitigation or router installation.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Timeline</CardTitle>
          </CardHeader>
          <CardContent>
            <FieldList className="grid-cols-2">
              <Field label="Event time"><span className="tabular-nums">{formatUtc(event.event_timestamp)}</span></Field>
              <Field label="Ingested">
                <time dateTime={event.ingested_at} title={formatUtc(event.ingested_at)} className="tabular-nums">{formatRelative(event.ingested_at)}</time>
              </Field>
            </FieldList>
          </CardContent>
        </Card>

        <Button variant="outline" className="w-full" asChild>
          <Link href={`/mitigations?ip=${encodeURIComponent(event.victim_ip)}`}>
            <ExternalLink className="size-4" aria-hidden="true" />
            View mitigations for {event.victim_ip}
          </Link>
        </Button>
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
    <Field label={label}>
      <span className="flex items-center gap-1">
        <span className={cn("truncate", mono && "font-mono")}>{value}</span>
        {copyable && onCopy && (
          <button
            type="button"
            onClick={onCopy}
            className="shrink-0 rounded-sm p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
            aria-label={`Copy ${label}`}
          >
            {copied ? <Check className="size-3 text-success" aria-hidden="true" /> : <Copy className="size-3" aria-hidden="true" />}
          </button>
        )}
      </span>
    </Field>
  )
}
