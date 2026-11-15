import { describe, expect, it } from "vitest"
import { leaseSecondsLeft, selectHealthBanner } from "@/components/dashboard/health-banner"
import type { HealthResponse, LeaseHealth } from "@/lib/api"

const NOW = Date.parse("2026-11-15T12:00:00Z")

function health(overrides: Partial<HealthResponse> = {}): HealthResponse {
  return {
    status: "healthy",
    version: "test",
    mode: "enforced",
    pop: "test",
    uptime_seconds: 10,
    bgp_sessions: {},
    active_mitigations: 0,
    database: "connected",
    gobgp: { status: "connected" },
    auth_mode: "none",
    bgp_session_up: true,
    ...overrides,
  }
}

function lease(overrides: Partial<LeaseHealth> = {}): LeaseHealth {
  return {
    owner: "prefixd.test.0123456789abcdef",
    lease_seconds: 60,
    state: "live",
    generation: { incarnation: 1, sequence: 3 },
    last_renewal_at: "2026-11-15T11:59:50Z",
    last_renewal_result: "success",
    renew_until: null,
    ...overrides,
  }
}

const speaker = (value: LeaseHealth) => ({
  backend: "rustbgpd",
  capabilities: { rule_reader: true, peer_observer: true },
  lease: value,
})

const withLease = (value: LeaseHealth, status = "healthy") => health({ status, speaker: speaker(value) })

describe("leaseSecondsLeft", () => {
  it("counts down from the last renewal plus one lease", () => {
    expect(leaseSecondsLeft(lease(), NOW)).toBe(50)
  })

  it("uses the TTL bound when renewal stopped there", () => {
    const stopped = lease({ renewal_stopped: "ttl_bound", state: "live", renew_until: "2026-11-15T11:59:58Z" })

    expect(leaseSecondsLeft(stopped, NOW)).toBe(58)
  })

  it("never reports negative time and never invents a countdown without a date", () => {
    expect(leaseSecondsLeft(lease({ last_renewal_at: "2026-11-15T11:58:00Z" }), NOW)).toBe(0)
    expect(leaseSecondsLeft(lease({ last_renewal_at: null, renew_until: null }), NOW)).toBeNull()
  })
})

describe("selectHealthBanner", () => {
  it("renders nothing while loading, without data, or after an error", () => {
    expect(selectHealthBanner({ data: undefined, error: undefined, isLoading: true })).toBeNull()
    expect(selectHealthBanner({ data: undefined, error: new Error("offline"), isLoading: false })).toBeNull()
    expect(selectHealthBanner({ data: health(), error: new Error("API error 503: offline") })).toBeNull()
  })

  it("renders nothing for a healthy enforced read with a live lease", () => {
    expect(selectHealthBanner({ data: withLease(lease()), error: undefined, now: NOW })).toBeNull()
  })

  it("surfaces a failing lease with the seconds it has left", () => {
    const banner = selectHealthBanner({
      data: withLease(lease({ state: "renewal_failing", last_renewal_result: "error" }), "degraded"),
      error: undefined,
      now: NOW,
    })

    expect(banner?.tone).toBe("critical")
    expect(banner?.title).toContain("renewal failing")
    expect(banner?.detail).toContain("50s")
    expect(banner?.countdown).toBe(true)
  })

  it("surfaces an expired lease without a countdown", () => {
    const banner = selectHealthBanner({
      data: withLease(lease({ state: "expired" }), "degraded"),
      error: undefined,
      now: NOW,
    })

    expect(banner?.tone).toBe("critical")
    expect(banner?.title).toContain("expired")
    expect(banner?.countdown).toBe(false)
  })

  it("ranks a failing lease above standby because it is the louder problem", () => {
    const banner = selectHealthBanner({
      data: withLease(lease({ state: "renewal_failing" }), "standby"),
      error: undefined,
      now: NOW,
    })

    expect(banner?.title).toContain("renewal failing")
  })

  it("shows standby when the fence is held elsewhere and the lease is not failing", () => {
    const banner = selectHealthBanner({ data: withLease(lease(), "standby"), error: undefined, now: NOW })

    expect(banner?.tone).toBe("warning")
    expect(banner?.title).toBe("Standby")
  })

  it("shows dry-run when the controller sends no speaker mutations", () => {
    const banner = selectHealthBanner({
      data: health({ mode: "dry-run", speaker: speaker(lease({ state: "not_renewing" })) }),
      error: undefined,
      now: NOW,
    })

    expect(banner?.tone).toBe("info")
    expect(banner?.title).toBe("Dry run")
  })

  it("does not assert standby or dry-run from a stale read", () => {
    expect(selectHealthBanner({ data: health({ status: "standby" }), error: undefined, isStale: true, now: NOW })).toBeNull()
    expect(selectHealthBanner({ data: health({ mode: "dry-run" }), error: undefined, isStale: true, now: NOW })).toBeNull()
  })

  it("keeps a failing lease visible on a stale read", () => {
    const banner = selectHealthBanner({
      data: withLease(lease({ state: "expired" }), "degraded"),
      error: undefined,
      isStale: true,
      now: NOW,
    })

    expect(banner?.tone).toBe("critical")
  })
})
