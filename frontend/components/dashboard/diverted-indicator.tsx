"use client"

import Link from "next/link"
import { Split } from "lucide-react"
import { StatusPill, type StatusTone } from "@/components/dashboard/status-pill"
import { useDiversions } from "@/hooks/use-api"
import type { ScrubberDiversion, VpnScopeIdentity } from "@/lib/api"
import { parseDestination } from "@/lib/destination"

// Withdrawal keeps traffic diverted until the controller confirms local absence.
const DIVERTING: Partial<Record<ScrubberDiversion["status"], { label: string; tone: StatusTone }>> = {
  active: { label: "Diverted", tone: "info" },
  pending: { label: "Diversion pending", tone: "warning" },
  withdrawing: { label: "Diversion withdrawing", tone: "warning" },
}

/**
 * The outstanding diversion of one host, if any. `scope` null means global routing only;
 * undefined means any scope. `pop`, when given, must own the diversion: a mitigation in
 * another POP is not diverted by this controller. Simulations divert nothing.
 */
export function findDiversion(rows: ScrubberDiversion[], host: string, scope?: VpnScopeIdentity | null, pop?: string) {
  const target = parseDestination(host)

  if (!target || target.prefixLength !== target.maxLength) return undefined

  return rows.find(row => DIVERTING[row.status]
    && (pop === undefined || row.pop === pop)
    && parseDestination(row.rule.nlri.dst_prefix)?.prefix === target.prefix
    && (scope === undefined || ((row.rule.nlri.scope?.family ?? null) === (scope?.family ?? null)
      && (row.rule.nlri.scope?.rd ?? null) === (scope?.rd ?? null))))
}

/**
 * Links a diverted victim to its diversion on the Scrubbers page. A failed read is unknown,
 * never "not diverted"; `showUnknown` says so where there is room.
 */
export function DivertedIndicator({ host, scope, pop, showUnknown = false }: { host: string; scope?: VpnScopeIdentity | null; pop?: string; showUnknown?: boolean }) {
  const { data, error } = useDiversions()

  if (error) return showUnknown ? <StatusPill tone="neutral">Diversion state unknown</StatusPill> : null

  const row = data && findDiversion(data, host, scope, pop)
  const state = row && DIVERTING[row.status]

  if (!row || !state) return null

  return (
    <Link
      href={`/scrubbers#diversion-${row.id}`}
      onClick={event => event.stopPropagation()}
      aria-label={`${state.label} through scrubber profile ${row.profile.id}: open Scrubbers`}
      className="rounded-sm hover:underline"
    >
      <StatusPill tone={state.tone} icon={<Split aria-hidden="true" />}>{state.label}</StatusPill>
    </Link>
  )
}
