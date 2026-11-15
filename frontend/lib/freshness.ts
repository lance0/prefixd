import type { ConnectionState } from "@/hooks/use-websocket-types"

/** Data older than this, by browser receipt time, is shown as stale. */
export const STALE_AFTER_MS = 15_000

/** Browser receipt of API data, recorded by every GET so a frozen screen never reads as live. */
export interface ApiReceipt {
  /** performance.now() at the last successful GET response, or null before the first. */
  lastSuccessAt: number | null
  /** True when the latest GET to settle failed. */
  failing: boolean
}

const initialReceipt: ApiReceipt = { lastSuccessAt: null, failing: false }
let receipt = initialReceipt
const listeners = new Set<() => void>()

function publish(next: ApiReceipt) {
  receipt = next
  listeners.forEach((listener) => listener())
}

export function recordApiResponse(ok: boolean) {
  publish(ok ? { lastSuccessAt: performance.now(), failing: false } : { ...receipt, failing: true })
}

/** Clears the module-wide receipt between tests. */
export function resetApiReceipt() {
  publish(initialReceipt)
}

export function subscribeApiReceipt(listener: () => void): () => void {
  listeners.add(listener)

  return () => { listeners.delete(listener) }
}

export function getApiReceipt(): ApiReceipt {
  return receipt
}

export type FreshnessState = "connecting" | "live" | "polling" | "stale" | "offline"

export interface DataFreshness {
  state: FreshnessState
  /** Milliseconds since the last successful API response, or null before the first. */
  ageMs: number | null
}

/**
 * Combines the realtime feed with API receipt. Only a recent successful response
 * is fresh: a connected feed with failing or hung requests is stale, never live.
 * A failure after a recent success stays fresh until that success is
 * STALE_AFTER_MS old, so one failed poll does not flip the status.
 */
export function dataFreshness(connection: ConnectionState, api: ApiReceipt, now: number, startedAt: number): DataFreshness {
  const ageMs = api.lastSuccessAt === null ? null : Math.max(0, now - api.lastSuccessAt)
  const waited = now - (api.lastSuccessAt ?? startedAt)

  if (waited > STALE_AFTER_MS) return { state: api.failing ? "offline" : "stale", ageMs }

  if (api.lastSuccessAt === null) return { state: api.failing ? "offline" : "connecting", ageMs }

  return { state: connection === "connected" ? "live" : "polling", ageMs }
}
