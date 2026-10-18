"use client"

import Link from "next/link"
import { formatConfidence } from "@/lib/confidence"
import { formatRelative, formatUtc } from "@/lib/format"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { StatusPill, Tag, healthTone, signalGroupTone } from "@/components/dashboard/status-pill"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { useSignalSources, useSignalGroups } from "@/hooks/use-api"
import { cn } from "@/lib/utils"

function SourceStatusCards() {
  const { data: sources, error, isLoading, mutate } = useSignalSources()

  if (isLoading) {
    return (
      <div role="status" aria-label="Loading signal sources" className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {[1, 2, 3].map((i) => (
          <Card key={i}>
            <CardContent className="space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-3 w-32" />
              <Skeleton className="h-3 w-20" />
            </CardContent>
          </Card>
        ))}
      </div>
    )
  }

  if (error) {
    return (
      <div className="rounded-md border bg-card">
        <ErrorState
          title="Unable to load signal sources"
          detail="Source health could not be refreshed. Detectors may still be sending signals; retry, or check that the controller is reachable."
          onRetry={() => { void mutate() }}
        />
      </div>
    )
  }

  if (!sources || sources.length === 0) {
    return (
      <div className="rounded-md border bg-card">
        <EmptyState title="No signal sources configured" description="Add sources on the Configuration tab to start correlating signals." />
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {sources.map((source) => (
        <Card key={source.name}>
          <CardHeader className="flex items-center justify-between gap-2">
            <CardTitle className="truncate">{source.name}</CardTitle>
            <Tag>{source.type}</Tag>
          </CardHeader>
          <CardContent>
            <dl className="space-y-1 text-sm">
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Status</dt>
                <dd>
                  <StatusPill tone={source.healthy ? healthTone("healthy") : "neutral"}>
                    {source.healthy ? "healthy" : "idle"}
                  </StatusPill>
                </dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Last seen</dt>
                <dd className="tabular-nums">
                  {source.last_seen
                    ? <time dateTime={source.last_seen} title={formatUtc(source.last_seen)}>{formatRelative(source.last_seen)}</time>
                    : "Never"}
                </dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Events</dt>
                <dd className="tabular-nums">{source.event_count}</dd>
              </div>
              <div className="flex justify-between gap-2">
                <dt className="text-muted-foreground">Weight</dt>
                <dd className="tabular-nums">{source.weight.toFixed(1)}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      ))}
    </div>
  )
}

// Neutral chart ramp: weights are proportions, not status, so they carry no hue.
const WEIGHT_RAMP = ["bg-chart-2", "bg-chart-3", "bg-chart-4", "bg-chart-5"] as const

function SourceWeightVisualization() {
  const { data: sources } = useSignalSources()

  if (!sources || sources.length === 0) return null

  const totalWeight = sources.reduce((sum, s) => sum + s.weight, 0)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Source weights</CardTitle>
      </CardHeader>
      <CardContent>
        <div
          className="flex h-2 gap-1"
          role="img"
          aria-label={`Relative source weights: ${sources.map((s) => `${s.name} ${s.weight.toFixed(1)}`).join(", ")}`}
        >
          {sources.map((source, index) => {
            const pct = totalWeight > 0 ? (source.weight / totalWeight) * 100 : 0
            return (
              <div
                key={source.name}
                className={cn("rounded-sm", WEIGHT_RAMP[index % WEIGHT_RAMP.length])}
                style={{ width: `${pct}%`, minWidth: pct > 0 ? "8px" : "0" }}
                title={`${source.name}: ${source.weight.toFixed(1)} (${pct.toFixed(0)}%)`}
              />
            )
          })}
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
          {sources.map((source, index) => (
            <div key={source.name} className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <span aria-hidden="true" className={cn("size-2 rounded-sm", WEIGHT_RAMP[index % WEIGHT_RAMP.length])} />
              <span>{source.name}</span>
              <span className="text-foreground tabular-nums">{source.weight.toFixed(1)}</span>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

function RecentSignalsTable() {
  const { data: groupsResp, error, isLoading, mutate } = useSignalGroups({ limit: 20 })
  const groups = groupsResp?.groups ?? []

  return (
    <section aria-labelledby="recent-signal-groups" className="overflow-hidden rounded-md border bg-card">
      <div className="border-b px-4 py-3">
        <h2 id="recent-signal-groups" className="text-sm font-semibold">Recent signal groups</h2>
      </div>
      {isLoading ? (
        <LoadingRows label="Loading recent signal groups" rows={5} />
      ) : error ? (
        <ErrorState
          title="Unable to load recent signal groups"
          detail="Signal groups could not be refreshed. Correlation continues on the controller; retry to reload this list."
          onRetry={() => { void mutate() }}
        />
      ) : groups.length === 0 ? (
        <EmptyState title="No recent signals" description="Signal groups appear here when events are correlated." />
      ) : (
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead>Status</TableHead>
              <TableHead>Victim IP</TableHead>
              <TableHead>Vector</TableHead>
              <TableHead className="text-right">Confidence</TableHead>
              <TableHead className="text-right">Sources</TableHead>
              <TableHead className="text-right">Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {groups.map((group) => (
              <TableRow key={group.group_id}>
                <TableCell>
                  <SignalGroupStatusBadge status={group.status} corroborated={group.corroboration_met} />
                </TableCell>
                <TableCell>
                  <Link href={`/correlation/groups/${group.group_id}`} className="rounded-sm font-mono hover:underline">
                    {group.victim_ip}
                  </Link>
                </TableCell>
                <TableCell className="text-muted-foreground">{group.vector.replace(/_/g, " ")}</TableCell>
                <TableCell numeric>{formatConfidence(group.derived_confidence)}</TableCell>
                <TableCell numeric>{group.source_count}</TableCell>
                <TableCell numeric className="text-muted-foreground">
                  <time dateTime={group.created_at} title={formatUtc(group.created_at)}>{formatRelative(group.created_at)}</time>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </section>
  )
}

export function SignalGroupStatusBadge({ status, corroborated = false }: { status: string; corroborated?: boolean }) {
  const label = status === "resolved" ? "Resolved" : status === "expired" ? "Expired" : corroborated ? "Corroborated" : "Open"
  return <StatusPill tone={signalGroupTone(status, corroborated)}>{label}</StatusPill>
}

export function SignalsTab() {
  return (
    <div className="space-y-4">
      <SourceStatusCards />
      <SourceWeightVisualization />
      <RecentSignalsTable />
    </div>
  )
}
