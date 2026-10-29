"use client"

import { AlertTriangle } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusPill, type StatusTone } from "@/components/dashboard/status-pill"
import { useTimeFormat } from "@/components/time-zone-provider"
import type { BlackholeExportEvidence, ExportDisposition } from "@/lib/api"

/** A labelled status pill. */
interface Pill {
  label: string
  tone: StatusTone
}

/** Committed is the speaker's Adj-RIB-Out for that peer, never router state. */
export const DISPOSITION_LABEL: Record<ExportDisposition, Pill> = {
  committed: { label: "Committed", tone: "success" },
  withheld: { label: "Withheld", tone: "danger" },
  pending: { label: "Pending", tone: "warning" },
}

function summary(evidence: BlackholeExportEvidence): Pill {
  if (evidence.historical) return { label: "Historical export evidence", tone: "neutral" }
  const listed = evidence.peers.length

  switch (evidence.status) {
    case "observed":
      return evidence.warning
        ? { label: "Exported to no peer", tone: "danger" }
        : { label: `Committed to ${evidence.counts.committed} of ${listed} Established peer${listed === 1 ? "" : "s"}`, tone: "success" }
    case "no_local_route":
      return { label: "No local route on the speaker", tone: "warning" }
    case "error":
      return { label: "Export unknown", tone: "danger" }
    case "unsupported":
      return { label: "Not reported by this speaker", tone: "neutral" }
    default:
      return { label: "Not observed yet", tone: "neutral" }
  }
}

/** Per-peer export from the last reconciliation pass; this never establishes router enforcement. */
export function ExportEvidenceCard({ evidence, now, kind = "blackhole" }: {
  evidence: BlackholeExportEvidence
  now?: number
  kind?: "blackhole" | "flowspec"
}) {
  const { formatTime } = useTimeFormat()
  const overall = summary(evidence)
  const notEstablished = evidence.not_established_peers
  const noun = kind === "flowspec" ? "FlowSpec rule" : "blackhole"
  const retained = evidence.historical || evidence.status === "error"

  return (
    <Card data-testid="export-evidence">
      <CardHeader className="flex flex-wrap items-center justify-between gap-2">
        <CardTitle>Export to peers</CardTitle>
        <StatusPill tone={overall.tone}>{overall.label}</StatusPill>
      </CardHeader>
      <CardContent className="space-y-4">
        {evidence.historical && (
          <p role="status" className="text-sm text-muted-foreground">
            Controller ownership was lost after this observation. Current export is unknown until a fresh complete read.
          </p>
        )}
        {evidence.warning && (
          <div role="alert" className={`flex items-start gap-2 rounded-md border p-3 text-sm ${evidence.historical ? "text-muted-foreground" : "border-destructive/30 bg-destructive/10 text-destructive"}`}>
            <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <span>
              {retained
                ? `At ${evidence.historical ? "the retained observation" : "the last complete read"}, no Established peer had this ${noun} in its Adj-RIB-Out.`
                : <>No Established peer has this {noun} in its Adj-RIB-Out, so no router is sent it. {evidence.warning.message}</>}{" "}
              <span className="font-mono">({evidence.warning.reason})</span>
            </span>
          </div>
        )}
        {evidence.status === "error" && (
          <p role="alert" className="text-sm text-destructive">
            The last export read failed{evidence.error ? `: ${evidence.error}` : ""}. Export is unknown, not empty.
          </p>
        )}
        {evidence.status === "no_local_route" && (
          <p className="text-sm text-muted-foreground">
            {evidence.historical
              ? `At the retained observation, the speaker held no local route for this ${noun}.`
              : `The speaker holds no local route for this ${noun}, so it is exported to no peer. Reconciliation re-adds it; check repair errors if this persists.`}
          </p>
        )}
        {evidence.status === "unsupported" && (
          <p className="text-sm text-muted-foreground">This speaker does not report per-peer export. rustbgpd does; GoBGP does not.</p>
        )}
        {evidence.status === "not_observed" && (
          <p className="text-sm text-muted-foreground">The next reconciliation pass reads per-peer export.</p>
        )}

        {evidence.peers.length > 0 && (
          <div className="overflow-x-auto rounded-md border">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead>Peer</TableHead>
                  <TableHead>{retained ? "Export at observation" : "Export"}</TableHead>
                  <TableHead>Reason</TableHead>
                  <TableHead>Explain code</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {evidence.peers.map((peer) => {
                  const disposition = DISPOSITION_LABEL[peer.disposition] ?? ({ label: peer.disposition, tone: "neutral" } satisfies Pill)

                  return (
                    <TableRow key={peer.peer_address}>
                      <TableCell className="font-mono">{peer.peer_address}</TableCell>
                      <TableCell><StatusPill tone={retained ? "neutral" : disposition.tone}>{disposition.label}</StatusPill></TableCell>
                      <TableCell>
                        <span className="font-mono">{peer.reason || "—"}</span>
                        {peer.detail && peer.disposition !== "committed" && <span className="block text-xs text-muted-foreground">{peer.detail}</span>}
                      </TableCell>
                      <TableCell className="font-mono">{peer.explain_code || "—"}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        )}

        {(evidence.historical || evidence.status === "observed" || evidence.status === "no_local_route") && (
          notEstablished === null ? (
            <p className="text-sm text-muted-foreground">Configured peers without a session were not observed.</p>
          ) : notEstablished.length > 0 ? (
            <p className="text-sm">
              <span className="text-muted-foreground">{evidence.historical && "At the retained observation: "}Configured, not Established (sent nothing): </span>
              {notEstablished.map((peer, index) => (
                <span key={peer.peer_address}>
                  {index > 0 && ", "}
                  <span className="font-mono">{peer.peer_address}</span> <span className="text-muted-foreground">({peer.state ?? "session state not observed"})</span>
                </span>
              ))}
            </p>
          ) : null
        )}

        <p className="text-xs text-muted-foreground">
          Committed means the speaker placed the route in that peer&apos;s Adj-RIB-Out. BGP reports no receipt, so router enforcement is not verified here.
          {evidence.observed_at && <> Observed <time dateTime={evidence.observed_at} className="tabular-nums">{formatTime(evidence.observed_at, now)}</time>.</>}
        </p>
      </CardContent>
    </Card>
  )
}
