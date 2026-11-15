"use client"

import { useEffect, useState } from "react"
import { AlertTriangle, Info, PauseCircle } from "lucide-react"
import { cn } from "@/lib/utils"
import { useHealthDetail } from "@/hooks/use-api"
import type { HealthResponse, LeaseHealth } from "@/lib/api"

export type BannerTone = "critical" | "warning" | "info"

export interface HealthBannerState {
  tone: BannerTone
  title: string
  detail: string
  /** True while the lease countdown needs a one-second tick. */
  countdown: boolean
}

export interface HealthBannerInput {
  data: HealthResponse | undefined
  error: unknown
  isLoading?: boolean
  /** True when the snapshot is older than the freshness window. */
  isStale?: boolean
  now?: number
}

/**
 * Seconds until the speaker drops the leased mitigations, from the fields the
 * controller exposes. Renewal may run up to one lease after the last renewal
 * attempt; `renew_until` is the hard bound once the TTL stop engaged.
 * `null` when no field dates the lease, so the banner omits the countdown.
 */
export function leaseSecondsLeft(lease: LeaseHealth, now: number): number | null {
  const anchor = lease.renewal_stopped === "ttl_bound"
    ? lease.renew_until ?? lease.last_renewal_at
    : lease.last_renewal_at ?? lease.renew_until
  if (!anchor) return null
  const expiry = Date.parse(anchor) + lease.lease_seconds * 1000
  if (!Number.isFinite(expiry)) return null

  return Math.max(0, Math.ceil((expiry - now) / 1000))
}

function leaseBanner(lease: LeaseHealth, now: number): HealthBannerState | null {
  if (lease.state !== "renewal_failing" && lease.state !== "expired") return null
  const secondsLeft = leaseSecondsLeft(lease, now)

  if (lease.state === "expired") {
    return {
      tone: "critical",
      title: "Injection lease expired",
      detail: "The speaker no longer holds the leased mitigations and has removed them. Check the controller-to-speaker connection and the lease capability.",
      countdown: false,
    }
  }

  return {
    tone: "critical",
    title: "Injection lease renewal failing",
    detail: secondsLeft === null
      ? "The speaker has refused or missed the last renewal. Every leased mitigation is removed within one lease unless renewal recovers."
      : `The speaker has refused or missed the last renewal. Every leased mitigation is removed in ${secondsLeft}s unless renewal recovers.`,
    countdown: secondsLeft !== null,
  }
}

/**
 * Pick the single most important banner from health detail, or `null` for no
 * banner. A missing, loading, failed or stale read never renders as healthy;
 * only a current read may assert standby or dry-run. A failing lease stays
 * visible from cached data because it is the reason health may be unavailable.
 */
export function selectHealthBanner({ data, error, isStale, now = Date.now() }: HealthBannerInput): HealthBannerState | null {
  if (error || !data) return null
  const lease = data.speaker?.lease
  if (lease) {
    const failing = leaseBanner(lease, now)
    if (failing) return failing
  }
  if (isStale) return null
  if (data.status === "standby") {
    return {
      tone: "warning",
      title: "Standby",
      detail: "Another controller holds this POP's fence. This instance applies no changes and reports the state it last observed.",
      countdown: false,
    }
  }
  if (data.mode === "dry-run") {
    return {
      tone: "info",
      title: "Dry run",
      detail: "Changes are simulated only; no speaker mutations are sent.",
      countdown: false,
    }
  }

  return null
}

const TONE: Record<BannerTone, { icon: typeof Info; className: string }> = {
  critical: { icon: AlertTriangle, className: "border-destructive/60 bg-destructive/10" },
  warning: { icon: PauseCircle, className: "border-warning/60 bg-warning/10" },
  info: { icon: Info, className: "border-border bg-muted/40" },
}

/** One top-bar banner for the most important operator-facing state. */
export function HealthBanner() {
  const { data, error, isLoading, isStale } = useHealthDetail()
  const [now, setNow] = useState(() => Date.now())
  const banner = selectHealthBanner({ data, error, isLoading, isStale, now })

  useEffect(() => {
    if (!banner?.countdown) return
    const timer = setInterval(() => setNow(Date.now()), 1000)

    return () => clearInterval(timer)
  }, [banner?.countdown])

  if (!banner) return null
  const { icon: Icon, className } = TONE[banner.tone]

  return (
    <div role="status" className={cn("flex flex-wrap items-baseline gap-x-2 gap-y-1 border-b px-4 py-2 text-sm sm:px-6", className)}>
      <span className="inline-flex items-center gap-2 font-medium">
        <Icon className="size-4 shrink-0" aria-hidden="true" />
        {banner.title}
      </span>
      <span className="text-muted-foreground">{banner.detail}</span>
    </div>
  )
}
