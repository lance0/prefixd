import type { ReactNode } from "react"
import { cn } from "@/lib/utils"
import type { Mitigation, SignalGroup } from "@/lib/api"

/**
 * Status colour is reserved for state. Every pill pairs a dot (or icon) and a
 * text label with the hue, so it still reads in grayscale. Unknown values map
 * to neutral: an unrecognised state must never look healthy.
 */
export type StatusTone = "success" | "warning" | "danger" | "info" | "neutral"

const TONE_CLASSES: Record<StatusTone, string> = {
  success: "border-success/30 bg-success/10 text-success",
  warning: "border-warning/30 bg-warning/10 text-warning",
  danger: "border-destructive/30 bg-destructive/10 text-destructive",
  info: "border-info/30 bg-info/10 text-info",
  neutral: "border-border bg-muted/50 text-muted-foreground",
}

export function mitigationTone(status: Mitigation["status"] | string): StatusTone {
  switch (status) {
    case "active":
      return "success"
    case "pending":
      return "warning"
    case "escalated":
    case "rejected":
      return "danger"
    default:
      return "neutral"
  }
}

/** Service, connection and BGP session states. */
export function healthTone(state: string): StatusTone {
  switch (state.toLowerCase()) {
    case "ok":
    case "healthy":
    case "connected":
    case "established":
    case "observed":
      return "success"
    case "degraded":
    case "connecting":
    case "stale":
      return "warning"
    case "error":
    case "failed":
    case "down":
    case "disconnected":
    // BGP FSM states short of established: the session is not carrying routes.
    case "idle":
    case "connect":
    case "active":
    case "opensent":
    case "openconfirm":
      return "danger"
    default:
      return "neutral"
  }
}

export function signalGroupTone(status: SignalGroup["status"] | string, corroborated = false): StatusTone {
  if (status !== "open") return "neutral"
  return corroborated ? "success" : "info"
}

interface StatusPillProps {
  tone: StatusTone
  children: ReactNode
  /** Replaces the dot, e.g. a lucide icon with aria-hidden. */
  icon?: ReactNode
  className?: string
}

export function StatusPill({ tone, children, icon, className }: StatusPillProps) {
  return (
    <span
      data-tone={tone}
      className={cn(
        "inline-flex w-fit shrink-0 items-center gap-1.5 whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs font-medium [&>svg]:size-3",
        TONE_CLASSES[tone],
        className,
      )}
    >
      {icon ?? <span aria-hidden="true" className="size-1.5 rounded-full bg-current" />}
      {children}
    </span>
  )
}

/** Neutral metadata label (vector, source, profile, role): never coloured. */
export function Tag({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex w-fit shrink-0 items-center whitespace-nowrap rounded-sm border px-1.5 py-0.5 text-xs text-muted-foreground",
        className,
      )}
    >
      {children}
    </span>
  )
}
