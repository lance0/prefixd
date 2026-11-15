"use client"

import Link from "next/link"
import type { ReactNode } from "react"
import { ActorBadge } from "@/components/dashboard/actor-badge"
import { ErrorState } from "@/components/dashboard/states"
import { useTimeFormat } from "@/components/time-zone-provider"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { useAuditLog } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import type { AuditEntry, Mitigation } from "@/lib/api"

const ACTION_LABELS = new Map([
  ["create", "Created"],
  ["extend", "Lifetime extended"],
  ["withdraw", "Withdrawn"],
  ["expire", "Expired"],
  ["announce", "Announced"],
  ["escalate", "Escalated"],
])

const AUDIT_LIMIT = 100

function actionLabel(action: string) {
  return ACTION_LABELS.get(action) ?? action.replace(/_/g, " ")
}

function Step({ label, time, now, hollow = false, children }: {
  label: string
  time: string
  now: number
  hollow?: boolean
  children?: ReactNode
}) {
  const { formatTime } = useTimeFormat()

  return (
    <li className="relative">
      <span
        aria-hidden="true"
        className={hollow
          ? "absolute -left-[21px] top-1.5 size-2.5 rounded-full border-2 border-muted-foreground bg-card"
          : "absolute -left-[21px] top-1.5 size-2.5 rounded-full bg-muted-foreground"}
      />
      <p className="text-sm font-medium">{label}</p>
      <p className="mt-0.5 text-xs text-muted-foreground tabular-nums">
        <time dateTime={time}>{formatTime(time, now)}</time>
      </p>
      {children}
    </li>
  )
}

function TriggeringEvent({ mitigation }: { mitigation: Mitigation }) {
  return (
    <p className="mt-1 text-xs text-muted-foreground">
      Triggered by event{" "}
      <Link
        href={`/events?id=${encodeURIComponent(String(mitigation.triggering_event_id))}`}
        className="rounded-sm font-mono text-foreground hover:underline"
      >
        {mitigation.triggering_event_id.slice(0, 8)}
      </Link>
    </p>
  )
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <>
      <dt className="text-muted-foreground">{label}</dt>
      <dd className="min-w-0 break-words">{children}</dd>
    </>
  )
}

/** Who did what and why, from one audit entry; absent fields are left out rather than guessed. */
function EntryDetails({ entry, now }: { entry: AuditEntry; now: number }) {
  const { formatTime } = useTimeFormat()
  const { reason, operation_id: operationId, previous_expires_at: previous } = entry.details
  const next = entry.details.expires_at ?? entry.details.ended_at
  const time = (value: string) => <time dateTime={value} className="tabular-nums">{formatTime(value, now)}</time>

  return (
    <dl className="mt-1 grid grid-cols-[auto_minmax(0,1fr)] gap-x-3 gap-y-0.5 text-xs">
      <Detail label="Actor">
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <ActorBadge type={entry.actor_type} name={entry.actor_id || "system"} />
          <span className="text-muted-foreground">({entry.actor_type})</span>
        </span>
      </Detail>
      <Detail label="Action"><span className="font-mono">{entry.action}</span></Detail>
      {reason ? <Detail label="Reason"><span className="text-pretty">{reason}</span></Detail> : null}
      {operationId ? <Detail label="Operation"><span className="break-all font-mono">{operationId}</span></Detail> : null}
      {previous || next ? (
        <Detail label="Expiry">
          {previous ? <>{time(previous)} <span aria-hidden="true">→</span><span className="sr-only">to</span> </> : null}
          {next ? time(next) : null}
        </Detail>
      ) : null}
    </dl>
  )
}

/** Mitigation history: audit entries when the operator can read them, else the record's own timestamps. */
export function MitigationTimeline({ mitigation, now }: { mitigation: Mitigation; now: number }) {
  const { formatTime } = useTimeFormat()
  const permissions = usePermissions()
  const canReadAudit = permissions.settled && permissions.isOperator

  const { data, error, isLoading, mutate } = useAuditLog(
    canReadAudit ? { target_type: "mitigation", target_id: mitigation.mitigation_id, limit: AUDIT_LIMIT } : null,
  )

  const entries = [...(data?.entries ?? [])].sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp) || a.audit_id.localeCompare(b.audit_id))
  const expired = Date.parse(mitigation.expires_at) <= now
  const ended = mitigation.status === "expired" ? "Expired" : "Withdrawn"

  // The record's own steps fill in whatever the audit does not cover, including entries older than the page.
  const hasCreate = entries.some((entry) => entry.action === "create")
  const hasEnd = entries.some((entry) => entry.action === "withdraw" || entry.action === "expire")

  return (
    <Card data-testid="mitigation-timeline">
      <CardHeader>
        <CardTitle>Timeline</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {error && !data ? (
          <div className="rounded-md border">
            <ErrorState
              title="Unable to load audit entries"
              detail={`${error.message}. The timestamps below come from the mitigation record; retry, or open the audit log.`}
              onRetry={() => { void mutate() }}
            />
          </div>
        ) : null}
        {canReadAudit && isLoading ? <p role="status" className="text-xs text-muted-foreground">Loading audit entries…</p> : null}
        {permissions.settled && !permissions.isOperator ? (
          <p className="text-xs text-muted-foreground">Actors and reasons are in the audit log, which needs the operator role.</p>
        ) : null}

        <ol className="relative space-y-5 border-l pl-4">
          {!hasCreate && (
            <Step label="Created" time={mitigation.created_at} now={now}>
              <TriggeringEvent mitigation={mitigation} />
            </Step>
          )}

          {entries.map((entry) => (
            <Step key={entry.audit_id} label={actionLabel(entry.action)} time={entry.timestamp} now={now}>
              <EntryDetails entry={entry} now={now} />
              {entry.action === "create" ? <TriggeringEvent mitigation={mitigation} /> : null}
            </Step>
          ))}

          {mitigation.withdrawn_at
            ? !hasEnd && <Step label={ended} time={mitigation.withdrawn_at} now={now} />
            : <Step label={expired ? "Expired" : "Expires"} time={mitigation.expires_at} now={now} hollow={!expired} />}
        </ol>

        {data?.has_more ? (
          <p className="text-xs text-muted-foreground">
            Showing the latest {AUDIT_LIMIT} entries. Older entries are in the{" "}
            <Link href="/audit-log" className="rounded-sm text-foreground hover:underline">audit log</Link>.
          </p>
        ) : null}
        {mitigation.updated_at !== mitigation.created_at ? (
          <p className="text-xs text-muted-foreground">
            Record last updated <time dateTime={mitigation.updated_at} className="tabular-nums">{formatTime(mitigation.updated_at, now)}</time>
          </p>
        ) : null}
      </CardContent>
    </Card>
  )
}
