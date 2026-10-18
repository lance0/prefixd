"use client"

import { use } from "react"
import Link from "next/link"
import { useSignalGroupDetail, useCorrelationConfig } from "@/hooks/use-api"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { ConfidenceBar } from "@/components/dashboard/confidence-bar"
import { PageHeader } from "@/components/dashboard/page-header"
import { StatusPill, Tag, signalGroupTone } from "@/components/dashboard/status-pill"
import { Field, FieldList } from "@/components/dashboard/field"
import { ErrorState, LoadingRows } from "@/components/dashboard/states"
import { isNotFound } from "@/lib/api"
import { Table, TableBody, TableCell, TableFooter, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { formatConfidence, isConfidence } from "@/lib/confidence"
import { formatUtc } from "@/lib/format"
import { AlertTriangle, CheckCircle2, Info } from "lucide-react"

function statusLabel(status: string, corroborated: boolean) {
  if (status === "resolved") return "Resolved"
  if (status === "expired") return "Expired"
  return corroborated ? "Corroborated" : "Open"
}

const back = { href: "/correlation", label: "Correlation" }

export default function SignalGroupDetailPage({
  params,
}: {
  params: Promise<{ id: string }>
}) {
  const { id } = use(params)

  const { data: group, isLoading, error, mutate } = useSignalGroupDetail(id)
  const { data: correlationConfig } = useCorrelationConfig()

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader back={back} title="Signal group" />
        <div className="rounded-md border bg-card"><LoadingRows label="Loading signal group" /></div>
      </div>
    )
  }

  if (!group && error && !isNotFound(error)) {
    return (
      <div className="space-y-6">
        <PageHeader back={back} title="Signal group" />
        <div className="rounded-md border bg-card">
          <ErrorState
            title="Unable to load this signal group"
            detail={`${error.message}. Correlation continues on the controller; retry, or check that it is reachable.`}
            onRetry={() => { void mutate() }}
          />
        </div>
      </div>
    )
  }

  if (!group) {
    return (
      <PageHeader
        back={back}
        title="Signal group not found"
        description="The requested signal group ID does not exist or has been removed."
      />
    )
  }

  // Sort events chronologically (earliest first), placing rows with a
  // missing ingest time at the end rather than sorting them as epoch 0.
  const ingestTs = (t: string | null | undefined) =>
    t ? new Date(t).getTime() : Number.POSITIVE_INFINITY
  const sortedEvents = [...group.events].sort(
    (a, b) => ingestTs(a.ingested_at) - ingestTs(b.ingested_at),
  )

  // Confidence breakdown calculations
  const totalWeight = sortedEvents.reduce((sum, e) => sum + e.source_weight, 0)
  const confidenceRows = sortedEvents.map((e) => {
    const rawConfidence = e.confidence
    const weightedContribution = rawConfidence == null
      ? rawConfidence
      : isConfidence(rawConfidence)
        ? totalWeight === 0 ? 0 : (rawConfidence * e.source_weight) / totalWeight
        : NaN
    return {
      source: e.source,
      event_id: e.event_id,
      rawConfidence,
      weight: e.source_weight,
      weightedContribution,
    }
  })

  // Distinct source count for corroboration
  const distinctSources = new Set(sortedEvents.map((e) => e.source)).size
  const minSources = correlationConfig?.min_sources ?? 1

  return (
    <div className="space-y-6">
      <PageHeader
        back={back}
        title={
          <Link
            href={`/ip-history?ip=${encodeURIComponent(group.victim_ip)}`}
            className="break-all rounded-sm font-mono hover:underline"
          >
            {group.victim_ip}
          </Link>
        }
        meta={
          <>
            <StatusPill tone={signalGroupTone(group.status, group.corroboration_met)}>
              {statusLabel(group.status, group.corroboration_met)}
            </StatusPill>
            <Tag>{group.vector.replace(/_/g, " ")}</Tag>
            <span className="text-muted-foreground tabular-nums">
              {group.source_count} source{group.source_count !== 1 ? "s" : ""}
            </span>
            <span className="text-muted-foreground tabular-nums">
              Created <time dateTime={group.created_at}>{formatUtc(group.created_at)}</time>
            </span>
            <span className="text-muted-foreground tabular-nums">
              Window {group.status === "open" ? "expires" : group.status === "expired" ? "expired" : "closed"}{" "}
              <time dateTime={group.window_expires_at}>{formatUtc(group.window_expires_at)}</time>
            </span>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          <Card>
            <CardHeader className="flex items-center justify-between gap-2">
              <CardTitle>Contributing events</CardTitle>
              <span className="text-xs text-muted-foreground tabular-nums">
                {sortedEvents.length} event{sortedEvents.length !== 1 ? "s" : ""}
              </span>
            </CardHeader>
            <CardContent>
              {sortedEvents.length === 0 ? (
                <p className="text-sm text-muted-foreground">No contributing events recorded.</p>
              ) : (
                <ol className="relative space-y-5 border-l pl-4">
                  {sortedEvents.map((event) => (
                    <li key={event.event_id} className="relative">
                      <span aria-hidden="true" className="absolute -left-[21px] top-1.5 size-2.5 rounded-full bg-muted-foreground" />
                      <div className="flex flex-wrap items-center gap-2">
                        <Tag className="text-foreground">{event.source}</Tag>
                        {event.is_corroborating && (
                          <Tag>
                            <span title="Corroborating signal — strengthened the group but cannot trigger mitigations alone">corroborating</span>
                          </Tag>
                        )}
                        <span className="text-xs text-muted-foreground tabular-nums">
                          Confidence: {formatConfidence(event.confidence)}
                        </span>
                      </div>
                      <p className="mt-1 text-xs text-muted-foreground tabular-nums">
                        {event.ingested_at ? formatUtc(event.ingested_at) : "Unknown ingest time"}
                      </p>
                      <p className="mt-1 text-xs text-muted-foreground">
                        Event{" "}
                        <Link
                          href={`/events?id=${encodeURIComponent(event.event_id)}`}
                          className="rounded-sm font-mono text-foreground hover:underline"
                        >
                          {event.event_id.slice(0, 8)}
                        </Link>
                        <span className="ml-2 tabular-nums">weight {event.source_weight.toFixed(1)}</span>
                      </p>
                    </li>
                  ))}
                </ol>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Confidence breakdown</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-hidden rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead>Source</TableHead>
                      <TableHead className="text-right">Raw confidence</TableHead>
                      <TableHead className="text-right">Weight</TableHead>
                      <TableHead className="text-right">Weighted contribution</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {confidenceRows.map((row) => (
                      <TableRow key={row.event_id}>
                        <TableCell>{row.source}</TableCell>
                        <TableCell numeric>{formatConfidence(row.rawConfidence)}</TableCell>
                        <TableCell numeric>{row.weight.toFixed(1)}</TableCell>
                        <TableCell numeric>{formatConfidence(row.weightedContribution)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                  <TableFooter>
                    <TableRow className="hover:bg-transparent">
                      <TableCell className="font-medium">Derived total</TableCell>
                      <TableCell />
                      <TableCell numeric className="font-medium">{totalWeight.toFixed(1)}</TableCell>
                      <TableCell numeric className="font-medium">{formatConfidence(group.derived_confidence)}</TableCell>
                    </TableRow>
                  </TableFooter>
                </Table>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Corroboration</CardTitle>
            </CardHeader>
            <CardContent>
              {group.corroboration_met ? (
                <div className="space-y-1">
                  <StatusPill tone="success" icon={<CheckCircle2 aria-hidden="true" />}>Corroborated</StatusPill>
                  <p className="text-xs text-muted-foreground tabular-nums">
                    {distinctSources} of {minSources} required source{minSources !== 1 ? "s" : ""} confirmed
                  </p>
                </div>
              ) : (
                <div className="space-y-1">
                  <StatusPill tone="warning" icon={<AlertTriangle aria-hidden="true" />}>
                    Pending corroboration {distinctSources}/{minSources}
                  </StatusPill>
                  <p className="text-xs text-muted-foreground tabular-nums">
                    {minSources - distinctSources} more distinct source{(minSources - distinctSources) !== 1 ? "s" : ""} needed
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Linked mitigation</CardTitle>
            </CardHeader>
            <CardContent>
              {group.mitigation_id ? (
                <Link
                  href={`/mitigations/${group.mitigation_id}`}
                  className="block rounded-md border p-3 hover:bg-muted/40"
                >
                  <span className="font-mono text-sm">{group.mitigation_id.slice(0, 8)}…</span>
                  <span className="mt-1 block text-xs text-muted-foreground">
                    Mitigation created from this signal group. Open it for current status.
                  </span>
                </Link>
              ) : (
                <div className="flex items-start gap-2">
                  <Info className="mt-0.5 size-4 shrink-0 text-muted-foreground" aria-hidden="true" />
                  <div>
                    <p className="text-sm">No mitigation created</p>
                    <p className="mt-1 text-xs text-muted-foreground text-pretty">
                      {group.status === "open"
                        ? "Corroboration threshold has not been met yet. A mitigation will be created when enough distinct sources confirm this attack."
                        : group.status === "expired"
                          ? "The correlation window expired before corroboration was achieved. No mitigation was triggered."
                          : "No linked mitigation is available for this signal group."}
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Summary</CardTitle>
            </CardHeader>
            <CardContent>
              <FieldList className="sm:grid-cols-1">
                <Field
                  label={
                    <>
                      Derived confidence
                      {correlationConfig?.confidence_decay_half_life_seconds && correlationConfig.confidence_decay_half_life_seconds > 0 ? (
                        <span className="ml-1">(decayed, half-life {correlationConfig.confidence_decay_half_life_seconds}s)</span>
                      ) : null}
                    </>
                  }
                >
                  <ConfidenceBar value={group.derived_confidence} />
                </Field>
                <Field label="Distinct sources"><span className="tabular-nums">{distinctSources}</span></Field>
                <Field label="Confidence threshold"><span className="tabular-nums">{formatConfidence(correlationConfig?.confidence_threshold)}</span></Field>
                <Field label="Min sources required"><span className="tabular-nums">{minSources}</span></Field>
                <Field label="Group ID"><span className="break-all font-mono text-xs">{group.group_id}</span></Field>
              </FieldList>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
