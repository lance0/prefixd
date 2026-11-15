import { act, screen, waitFor } from "@testing-library/react"
import { Suspense } from "react"
import { describe, expect, it } from "vitest"
import { findDiversion } from "@/components/dashboard/diverted-indicator"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import type { Mitigation, ScrubberDiversion } from "@/lib/api"
import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import IpHistoryPage from "@/app/(dashboard)/ip-history/page"
import { failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

function diversion(overrides: Partial<ScrubberDiversion> = {}, dst = "203.0.113.20/32"): ScrubberDiversion {
  return {
    id: "operation-1", profile: { id: "scrubber-a", revision: "v1" },
    rule: { nlri: { dst_prefix: dst, protocol: 6, dst_ports: [443] }, target: "192.0.2.99", owner: "owner", revision: 1 },
    expires_at: "2030-01-01T00:00:00Z", status: "active", dry_run: false, withdrawal_reason: null, last_error: null,
    ...overrides,
  }
}

const mitigation: Mitigation = {
  mitigation_id: "mit-1", scope_hash: "scope-1", status: "withdrawn", customer_id: "acme", service_id: null, pop: "iad1",
  victim_ip: "203.0.113.20", vector: "syn_flood", action_type: "discard", rate_bps: null,
  dst_prefix: "203.0.113.20/32", protocol: 6, dst_ports: [443],
  created_at: "2026-11-14T10:00:00Z", updated_at: "2026-11-14T10:00:00Z", expires_at: "2026-11-14T11:00:00Z",
  withdrawn_at: "2026-11-14T10:30:00Z", triggering_event_id: "event-1", last_event_id: "event-1", reason: "flood",
  acknowledged_at: null, acknowledged_by: null,
}

describe("findDiversion", () => {
  const vpn = { family: "ipv4" as const, rd: "44407:40" }

  it.each([
    ["a bare address", "203.0.113.20", [diversion()], "operation-1"],
    ["a host CIDR", "203.0.113.20/32", [diversion()], "operation-1"],
    ["another host", "203.0.113.21", [diversion()], undefined],
    ["a covering prefix", "203.0.113.0/24", [diversion()], undefined],
    ["an equivalent IPv6 spelling", "2001:DB8:0::20", [diversion({}, "2001:db8::20/128")], "operation-1"],
    ["a withdrawn diversion", "203.0.113.20", [diversion({ status: "withdrawn" })], undefined],
    ["a simulation", "203.0.113.20", [diversion({ status: "simulated", dry_run: true })], undefined],
    ["a pending diversion", "203.0.113.20", [diversion({ status: "pending" })], "operation-1"],
    ["a withdrawing diversion", "203.0.113.20", [diversion({ status: "withdrawing" })], "operation-1"],
  ])("matches %s", (_case, host, rows, id) => {
    expect(findDiversion(rows, host, null)?.id).toBe(id)
  })

  it("keeps global and VPN routing apart unless any scope is asked for", () => {
    const scoped = diversion()

    scoped.rule.nlri.scope = vpn
    expect(findDiversion([scoped], "203.0.113.20", null)).toBeUndefined()
    expect(findDiversion([scoped], "203.0.113.20", vpn)?.id).toBe("operation-1")
    expect(findDiversion([scoped], "203.0.113.20", { ...vpn, rd: "44407:41" })).toBeUndefined()
    expect(findDiversion([scoped], "203.0.113.20")?.id).toBe("operation-1")
    expect(findDiversion([diversion()], "203.0.113.20", vpn)).toBeUndefined()
  })
})

function serveDiversions(response: () => Response) {
  controller.route("GET", "/v1/diversions", response)
}

describe("Diverted indicator", () => {
  it.each(["viewer", "operator"] as const)("links a diverted Mitigations row to Scrubbers for a %s", async role => {
    signIn(controller, "credentials", operatorResponse(role))
    controller.route("GET", "/v1/config/inventory", () => json({ customers: [] }))
    controller.route("GET", "/v1/pops", () => json([]))
    controller.route("GET", "/v1/mitigations", () => json({ mitigations: [mitigation, { ...mitigation, mitigation_id: "mit-2", victim_ip: "203.0.113.21", dst_prefix: "203.0.113.21/32" }], count: 2, next_cursor: null, has_more: false }))
    serveDiversions(() => json([diversion()]))
    renderApp(<MitigationsContentLive />, { url: "/mitigations" })
    const links = await screen.findAllByRole("link", { name: "Diverted through scrubber profile scrubber-a: open Scrubbers" })

    expect(links).toHaveLength(1)
    expect(links[0]).toHaveAttribute("href", "/scrubbers#diversion-operation-1")
  })

  async function renderDetail(response: () => Response) {
    signIn(controller, "none", null)
    controller.route("GET", "/v1/config/inventory", () => json({ customers: [] }))
    controller.route("GET", "/v1/mitigations/mit-1", () => json(mitigation))
    serveDiversions(response)
    await act(async () => { renderApp(<Suspense fallback={null}><MitigationDetailPage params={Promise.resolve({ id: "mit-1" })} /></Suspense>, { url: "/mitigations/mit-1" }) })
  }

  it("shows the diversion in the mitigation detail header", async () => {
    await renderDetail(() => json([diversion({ status: "withdrawing" })]))
    const link = await screen.findByRole("link", { name: "Diversion withdrawing through scrubber profile scrubber-a: open Scrubbers" })

    expect(link.closest("header")).not.toBeNull()
    expect(link).toHaveAttribute("href", "/scrubbers#diversion-operation-1")
  })

  it("shows unknown diversion state on mitigation detail when the read fails", async () => {
    await renderDetail(() => failure(500))
    expect(await screen.findByText("Diversion state unknown")).toBeInTheDocument()
    expect(screen.queryByRole("link", { name: /open Scrubbers/ })).not.toBeInTheDocument()
  })

  async function renderHistory(rows: ScrubberDiversion[]) {
    signIn(controller, "credentials", operatorResponse("viewer"))
    controller.route("GET", "/v1/ip/203.0.113.20/history", () => json({ ip: "203.0.113.20", events: [], mitigations: [mitigation], customer: null, service: null }))
    serveDiversions(() => json(rows))
    renderApp(<IpHistoryPage />, { url: "/ip-history?ip=203.0.113.20" })
    await screen.findByRole("link", { name: "Mitigation" })
    await waitFor(() => expect(controller.calls("GET", "/v1/diversions")).toHaveLength(1))
    await settle()
  }

  it("shows the diversion on IP history", async () => {
    await renderHistory([diversion()])
    expect(screen.getByRole("link", { name: "Diverted through scrubber profile scrubber-a: open Scrubbers" }).closest("header")).not.toBeNull()
  })

  it("shows nothing on IP history for an address that is not diverted", async () => {
    await renderHistory([diversion({}, "203.0.113.99/32")])
    expect(screen.queryByRole("link", { name: /open Scrubbers/ })).not.toBeInTheDocument()
  })
})
