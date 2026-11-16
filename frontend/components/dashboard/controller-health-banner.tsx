"use client"

import type { HealthResponse } from "@/lib/api"

interface ControllerHealthBannerProps {
  health: HealthResponse | undefined
  error: unknown
  isStale: boolean
  receiptAge: number | null
}

function warning({ health, error, isStale, receiptAge }: ControllerHealthBannerProps): string | null {
  if (error) return "Controller health unavailable. Retrying automatically."

  if (!health) return "Checking controller health…"

  if (isStale || receiptAge === null) return "Controller health is stale. Retrying automatically."

  if (health.status === "standby") return "Controller standby. This controller cannot change mitigations."

  if (health.mode === "dry-run") return "Dry-run mode. This controller sends no routing changes."

  if (health.mode !== "enforced") return "Controller operation mode is unknown. Refresh health before acting."

  const lease = health.speaker?.lease

  if (!lease || lease.has_leased_intent === false) return null

  if (lease.state === "renewal_failing" || (lease.state === "live" && lease.renewal_overdue === true)) {
    const remaining = lease.remaining_seconds
    const label = lease.state === "renewal_failing" ? "Lease renewal failing" : "Lease renewal overdue"

    if (remaining === null || !Number.isFinite(remaining) || remaining < 0) {
      return `${label}. Time remaining is unavailable.`
    }

    return `${label} (about ${Math.max(0, Math.floor(remaining - receiptAge / 1000))} s left). Leased mitigations may lapse.`
  }

  switch (lease.state) {
    case "none":
    case "live":
      return null

    case "expired":
      return "Injection lease expired. Leased mitigations may no longer be active."

    case "standby":
      return "Lease state unknown in standby. Another controller may be renewing it."

    case "not_renewing":
      return "Injection lease is not renewing. Leased mitigations may lapse."

    default:
      return "Injection lease state is unknown. Refresh health before acting."
  }
}

export function ControllerHealthBanner(props: ControllerHealthBannerProps) {
  const message = warning(props)

  return message ? <div role="status" aria-label="Controller warning" className="border-t border-warning/60 bg-warning/10 px-4 py-2 text-sm text-pretty tabular-nums sm:px-6">{message}</div> : null
}
