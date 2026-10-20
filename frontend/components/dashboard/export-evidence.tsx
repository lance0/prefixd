import { AlertTriangle } from "lucide-react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusPill, type StatusTone } from "@/components/dashboard/status-pill"
import { formatUtc } from "@/lib/format"
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

/** Per-peer export of an active blackhole from the last reconciliation pass (rustbgpd). */
export function ExportEvidenceCard({ evidence, now }: { evidence: BlackholeExportEvidence; now?: number }) {
  const overall = summary(evidence)
  const notEstablished = evidence.not_established_peers

  return (
    <Card data-testid="export-evidence">
      <CardHeader className="flex flex-wrap items-center justify-between gap-2">
        <CardTitle>Export to peers</CardTitle>
        <StatusPill tone={overall.tone}>{overall.label}</StatusPill>
      </CardHeader>
      <CardContent className="space-y-4">
        {evidence.warning && (
          <div role="alert" className="flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive">
            <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden="true" />
            <span>
              No Established peer has this blackhole in its Adj-RIB-Out, so no router is sent it. {evidence.warning.message}{" "}
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
            The speaker holds no local route for this blackhole, so it is exported to no peer. Reconciliation re-adds it; check repair errors if this persists.
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
                  <TableHead>Export</TableHead>
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
                      <TableCell><StatusPill tone={disposition.tone}>{disposition.label}</StatusPill></TableCell>
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

        {(evidence.status === "observed" || evidence.status === "no_local_route") && (
          notEstablished === null ? (
            <p className="text-sm text-muted-foreground">Peer sessions were not observed, so configured peers without a session are not shown.</p>
          ) : notEstablished.length > 0 ? (
            <p className="text-sm">
              <span className="text-muted-foreground">Configured, not Established (sent nothing): </span>
              {notEstablished.map((peer, index) => (
                <span key={peer.peer_address}>
                  {index > 0 && ", "}
                  <span className="font-mono">{peer.peer_address}</span> <span className="text-muted-foreground">({peer.state})</span>
                </span>
              ))}
            </p>
          ) : null
        )}

        <p className="text-xs text-muted-foreground">
          Committed means the speaker placed the route in that peer&apos;s Adj-RIB-Out. BGP reports no receipt, so router enforcement is not verified here.
          {evidence.observed_at && <> Observed <time dateTime={evidence.observed_at} className="tabular-nums">{formatUtc(evidence.observed_at, now)}</time>.</>}
        </p>
      </CardContent>
    </Card>
  )
}
