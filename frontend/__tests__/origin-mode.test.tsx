import { afterEach, describe, expect, it } from "vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { OriginTag } from "@/components/dashboard/status-pill"
import { ActiveMitigationsMini } from "@/components/dashboard/active-mitigations-mini"
import type { Mitigation } from "@/lib/api"

const row = (id: string, origin_mode: Mitigation["origin_mode"]): Mitigation => ({
  mitigation_id: id, scope_hash: id, status: "active",
  customer_id: null, service_id: null, pop: "iad1", victim_ip: `203.0.113.${id}`,
  vector: "udp_flood", action_type: "discard", rate_bps: null,
  dst_prefix: `203.0.113.${id}/32`, protocol: 17, dst_ports: [53],
  created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
  expires_at: new Date(Date.now() + 600_000).toISOString(), withdrawn_at: null,
  triggering_event_id: "event-1", last_event_id: "event-1", reason: "DNS flood",
  acknowledged_at: null, acknowledged_by: null, origin_mode,
})

afterEach(cleanup)

describe("origin mode tag", () => {
  it.each<[string | null | undefined, boolean, string]>([
    ["dry-run", false, "Simulation"],
    ["dry-run", true, "Simulation"],
    ["enforced", false, ""],
    ["enforced", true, ""],
    [null, false, ""],
    [undefined, false, ""],
    [null, true, "Origin unknown"],
    [undefined, true, "Origin unknown"],
    // An unrecognised mode is unknown, never treated as enforced.
    ["something-new", true, "Origin unknown"],
  ])("renders %s (showUnknown=%s) as %j", (origin, showUnknown, label) => {
    const { container } = render(<OriginTag origin={origin} showUnknown={showUnknown} />)

    expect(container.textContent).toBe(label)
    // Neutral metadata only: never a status pill or status colour.
    expect(container.querySelector("[data-tone]")).toBeNull()
    expect(container.innerHTML).not.toMatch(/success|warning|destructive|info/)
  })

  it("marks only dry-run rows on the Overview worklist", () => {
    render(<ActiveMitigationsMini mitigations={[row("1", "dry-run"), row("2", "enforced"), row("3", null)]} />)

    expect(screen.getAllByText("Simulation")).toHaveLength(1)
    expect(screen.getByRole("link", { name: "203.0.113.1/32" }).closest("td")).toHaveTextContent("Simulation")
    expect(screen.queryByText("Origin unknown")).not.toBeInTheDocument()
  })
})
