"use client"

import { useHealthDetail } from "@/hooks/use-api"
import { cn } from "@/lib/utils"
import { Skeleton } from "@/components/ui/skeleton"
import { StatusPill, healthTone } from "@/components/dashboard/status-pill"
import { formatUtc } from "@/lib/format"

export function formatControllerUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "unavailable"
  const minutes = Math.floor(seconds / 60)

  if (minutes === 0) return `${Math.floor(seconds)}s`

  if (minutes < 60) return `${minutes}m`
  const hours = Math.floor(minutes / 60)

  if (hours < 24) return `${hours}h ${minutes % 60}m`

  return `${Math.floor(hours / 24)}d ${hours % 24}h`
}

export function BgpSessionStatus() {
  const { data: health, error, isStale: stale, receiptAge: age } = useHealthDetail()
  const daemon = error ? undefined : health?.speaker?.daemon
  const daemonAvailable = daemon?.status === "observed" && !stale

  const status = error ? "error"
    : stale ? "stale"
    : !health ? "loading"
    : health.speaker?.capabilities.peer_observer === false || health.gobgp.status === "unsupported" ? "unsupported"
    : health.gobgp.status !== "connected" ? "error"
    : Object.keys(health.bgp_sessions).length === 0 ? "no peers"
    : health.bgp_session_up ? "up" : "down"

  const observed = error || stale ? undefined : health
  const peers = observed ? Object.values(observed.bgp_sessions) : []
  const established = peers.filter(state => state === "established").length

  return (
    <section aria-label="Speaker and controller health" className="flex flex-wrap items-center gap-x-6 gap-y-3 rounded-md border bg-card px-4 py-3 text-sm">
      <div className="flex items-center gap-2">
        <span className="text-muted-foreground">Backend</span>
        <span className="font-medium">{observed ? observed.speaker?.backend ?? "Unknown backend" : "Unavailable"}</span>
        <span className="flex items-center gap-2 text-muted-foreground">Peers <StatusPill tone={healthTone(status)}>{status}</StatusPill></span>
      </div>
      {error ? (
        <span role="status" className="text-destructive">Health unavailable. Retrying automatically.</span>
      ) : !health ? (
        <div role="status" className="flex items-center gap-2 text-muted-foreground"><Skeleton className="h-4 w-24" />Loading health…</div>
      ) : stale ? (
        <>
          <span role="status" className="text-destructive">Health observation is stale. Retrying automatically.</span>
          <span className="text-muted-foreground">Daemon {daemon?.status === "unsupported" ? "unsupported" : daemon?.status === "observed" ? "stale" : "unavailable"}</span>
        </>
      ) : (
        <>
          <span className="text-muted-foreground">
            Sessions <span className="text-foreground tabular-nums">{status === "unsupported" || status === "error" || status === "stale" ? "unavailable" : `${established}/${peers.length} established`}</span>
          </span>
          <span className="text-muted-foreground">
            Daemon <span className={cn(daemonAvailable && "font-mono", daemonAvailable && daemon?.ready === false ? "text-destructive" : "text-foreground")}>{daemonAvailable ? daemon.version ?? "version unavailable" : daemon?.status === "unsupported" ? "unsupported" : "unavailable"}</span>
            {daemonAvailable && <>{" · up "}<span className="text-foreground tabular-nums">{daemon.uptime_seconds === null ? "unavailable" : formatControllerUptime(daemon.uptime_seconds)}</span>{" · "}<span className={daemon.ready === false ? "font-medium text-destructive" : undefined}>{daemon.ready === true ? "ready" : daemon.ready === false ? "not ready" : "readiness unavailable"}</span>{daemon.observed_at && <>{" · observed "}<time dateTime={daemon.observed_at} className="tabular-nums">{formatUtc(daemon.observed_at)}</time></>}</>}
          </span>
          {!stale && age !== null && <span className="text-muted-foreground">Received {Math.floor(age / 1000)}s ago</span>}
          <span className="text-muted-foreground">Database <span className={cn(health.database === "connected" ? "text-foreground" : "text-destructive")}>{health.database === "connected" ? "connected" : "unavailable"}</span></span>
          <span className="text-muted-foreground sm:ml-auto">Controller <span className="font-mono text-foreground">v{health.version}</span> · up <span className="tabular-nums">{formatControllerUptime(health.uptime_seconds)}</span></span>
        </>
      )}
    </section>
  )
}
