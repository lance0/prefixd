import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, act } from "@testing-library/react"
import { ActiveMitigationsMini, formatSourceCount, formatTimeRemaining } from "@/components/dashboard/active-mitigations-mini"
import { formatControllerUptime } from "@/components/dashboard/bgp-session-status"
import type { Mitigation } from "@/lib/api"

const now = Date.parse("2026-10-18T12:00:00Z")

const mitigation: Mitigation = {
  mitigation_id: "rule-1", scope_hash: "scope-1", status: "active",
  customer_id: null, service_id: null, pop: "iad1", victim_ip: "203.0.113.10",
  vector: "udp_flood", action_type: "discard", rate_bps: null,
  dst_prefix: "203.0.113.10/32", protocol: 17, dst_ports: [53],
  created_at: "2026-10-18T11:59:00Z", updated_at: "2026-10-18T11:59:00Z",
  expires_at: "2026-10-18T12:00:45Z", withdrawn_at: null,
  triggering_event_id: "event-1", last_event_id: "event-1", reason: "DNS flood detected",
  acknowledged_at: null, acknowledged_by: null,
}

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(now) })

afterEach(() => { cleanup(); vi.useRealTimers() })

describe("operator evidence formatting", () => {
  it.each([
    [undefined, "Sources unavailable"], [NaN, "Sources unavailable"],
    [-1, "Sources unavailable"], [1.5, "Sources unavailable"],
    [0, "0 sources"], [1, "1 source"], [2, "2 sources"],
  ])("preserves observed source counts for %s", (value, label) => {
    expect(formatSourceCount(value)).toBe(label)
  })

  it.each([
    [-1, "Expiry due"], [0, "Expiry due"], [1, "<1m"], [59_999, "<1m"],
    [60_000, "1m"], [3_599_999, "59m"], [3_600_000, "1h 0m"],
    [86_400_000, "1d 0h"],
  ])("shows the expiry boundary at %sms without implying withdrawal", (remaining, label) => {
    expect(formatTimeRemaining(new Date(now + remaining).toISOString(), now)).toBe(label)
  })

  it("keeps an invalid deadline explicit", () => {
    expect(formatTimeRemaining("not-a-date", now)).toBe("Unavailable")
  })

  it.each([[0, "0s"], [59, "59s"], [60, "1m"], [3600, "1h 0m"], [86400, "1d 0h"], [-1, "unavailable"], [NaN, "unavailable"]])("formats controller uptime %s", (value, label) => {
    expect(formatControllerUptime(value)).toBe(label)
  })
})

describe("active mitigation worklist", () => {
  it("shows actual reason, correlation, target, action and deadline with unobserved installation", () => {
    render(<ActiveMitigationsMini mitigations={[{
      ...mitigation,
      correlation: { signal_group_id: "signal-1", source_count: 2, derived_confidence: 0.88, corroboration_met: true },
    }]} />)
    expect(screen.getByRole("link", { name: "203.0.113.10/32" })).toHaveAttribute("href", "/mitigations/rule-1")
    expect(screen.getByText("DNS flood detected")).toBeInTheDocument()
    expect(screen.getByText(/2 sources · Confidence: 88%/)).toBeInTheDocument()
    expect(screen.getByText("discard")).toBeInTheDocument()
    expect(screen.getByText("Unobserved")).toBeInTheDocument()
    expect(screen.getByText("<1m")).toBeInTheDocument()
    expect(screen.getByText(/18 Oct,? 12:00:45 UTC/)).toBeInTheDocument()
    expect(screen.queryByText(/installed|enforced/i)).not.toBeInTheDocument()
  })

  it("does not infer confidence or one source from a mitigation without correlation", () => {
    render(<ActiveMitigationsMini mitigations={[mitigation]} />)
    expect(screen.getByText(/Sources unavailable · Confidence: Unavailable/)).toBeInTheDocument()
    expect(screen.queryByText(/Confidence: 100%|1 source/)).not.toBeInTheDocument()
  })

  it("updates an overdue deadline without claiming the rule has been withdrawn", () => {
    render(<ActiveMitigationsMini mitigations={[mitigation]} />)
    act(() => { vi.advanceTimersByTime(46_000) })
    expect(screen.getByText("Expiry due")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "203.0.113.10/32" })).toBeInTheDocument()
    expect(screen.getByText("Unobserved")).toBeInTheDocument()
  })

  it("distinguishes loading from empty data", () => {
    const { rerender } = render(<ActiveMitigationsMini mitigations={[]} loading />)
    expect(screen.getByRole("status", { name: "Loading active mitigations" })).toBeInTheDocument()
    expect(screen.queryByText("No active mitigations")).not.toBeInTheDocument()
    rerender(<ActiveMitigationsMini mitigations={[]} />)
    expect(screen.getByText("No active mitigations")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Review incoming events" })).toHaveAttribute("href", "/events")
  })

  it("shows a refresh failure over stale data and retries the owning request", () => {
    const retry = vi.fn()
    render(<ActiveMitigationsMini mitigations={[mitigation]} error onRetry={retry} />)
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load mitigations")
    expect(screen.queryByText("No active mitigations")).not.toBeInTheDocument()
    expect(screen.queryByRole("link", { name: "203.0.113.10/32" })).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Retry mitigations" }))
    expect(retry).toHaveBeenCalledOnce()
  })

  it("scopes the displayed count to loaded active rows", () => {
    render(<ActiveMitigationsMini limit={1} hasMore mitigations={[
      mitigation,
      { ...mitigation, mitigation_id: "rule-2", dst_prefix: "203.0.113.11/32" },
      { ...mitigation, mitigation_id: "rule-3", status: "withdrawn" },
    ]} />)
    expect(screen.getByText("Showing 1 of 2 loaded · more available")).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: "203.0.113.11/32" })).not.toBeInTheDocument()
  })
})
