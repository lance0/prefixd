import { describe, it, expect } from "vitest"
import { screen, act, within, waitFor, fireEvent } from "@testing-library/react"
import { Suspense } from "react"
import type { Mitigation, SignalGroupDetailResponse } from "@/lib/api"
import { failure, json, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"

const controller = useFakeController()

// ─── Sample Data ────────────────────────────────────────

const baseMitigation: Mitigation = {
  mitigation_id: "mit-001-aaaa-bbbb-cccc",
  scope_hash: "abc123",
  status: "active",
  customer_id: "cust_acme",
  service_id: "svc_dns",
  pop: "iad1",
  victim_ip: "203.0.113.10",
  vector: "udp_flood",
  action_type: "police",
  rate_bps: 5000000,
  dst_prefix: "203.0.113.10/32",
  protocol: 17,
  dst_ports: [53],
  created_at: new Date(Date.now() - 120000).toISOString(),
  updated_at: new Date(Date.now() - 120000).toISOString(),
  expires_at: new Date(Date.now() + 180000).toISOString(),
  withdrawn_at: null,
  triggering_event_id: "evt-001",
  last_event_id: "evt-001",
  reason: "UDP flood detected",
  acknowledged_at: null,
  acknowledged_by: null,
}

const correlation = {
    signal_group_id: "sg-001-aaaa-bbbb-cccc-dddd",
    derived_confidence: 0.88,
    source_count: 2,
    corroboration_met: true,
    contributing_sources: ["fastnetmon", "alertmanager"],
    explanation:
      'Corroboration achieved: 2 of 2 required sources confirmed UDP flood on 203.0.113.10. Derived confidence 88% (threshold 50%). Sources: fastnetmon (95% × 1.0), alertmanager (80% × 0.8).',
}

const correlatedMitigation: Mitigation = { ...baseMitigation, correlation }

const nonCorrelatedMitigation: Mitigation = {
  ...baseMitigation,
  correlation: null,
}

const signalGroupDetailData: SignalGroupDetailResponse = {
  group_id: "sg-001-aaaa-bbbb-cccc-dddd",
  victim_ip: "203.0.113.10",
  vector: "udp_flood",
  created_at: new Date(Date.now() - 300000).toISOString(),
  window_expires_at: new Date(Date.now() + 300000).toISOString(),
  derived_confidence: 0.88,
  source_count: 2,
  status: "resolved",
  corroboration_met: true,
  mitigation_id: "mit-001-aaaa-bbbb-cccc",
  events: [
    {
      group_id: "sg-001-aaaa-bbbb-cccc-dddd",
      event_id: "evt-001",
      source: "fastnetmon",
      confidence: 0.95,
      source_weight: 1.0,
      ingested_at: new Date(Date.now() - 300000).toISOString(),
      victim_ip: "203.0.113.10",
      vector: "udp_flood",
    },
    {
      group_id: "sg-001-aaaa-bbbb-cccc-dddd",
      event_id: "evt-002",
      source: "alertmanager",
      confidence: 0.8,
      source_weight: 0.8,
      ingested_at: new Date(Date.now() - 240000).toISOString(),
      victim_ip: "203.0.113.10",
      vector: "udp_flood",
    },
  ],
}

// ─── Helper ─────────────────────────────────────────────

const mitigationPath = "/v1/mitigations/mit-001-aaaa-bbbb-cccc"

/** Serves the mitigation and, when given, its signal group; auth is disabled so every action is permitted. */
function serve(mitigation: Mitigation | Response, group?: SignalGroupDetailResponse) {
  signIn(controller, "none", null)
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: new Date().toISOString() }))
  controller.route("GET", mitigationPath, () => mitigation instanceof Response ? mitigation : json(mitigation))

  if (group) controller.route("GET", `/v1/signal-groups/${group.group_id}`, () => json(group))
}

async function renderPage() {
  let result!: ReturnType<typeof renderApp>
  await act(async () => {
    result = renderApp(
      <Suspense fallback={<div>Loading suspense...</div>}>
        <MitigationDetailPage params={Promise.resolve({ id: "mit-001-aaaa-bbbb-cccc" })} />
      </Suspense>,
      { url: "/mitigations/mit-001" },
    )
  })
  await waitFor(() => expect(controller.calls("GET", mitigationPath)).toHaveLength(1))
  await settle()
  await settle()

  return result
}

// ─── Tests ──────────────────────────────────────────────

describe("Mitigation Detail – Correlation Section", () => {
  it("shows Correlation card with all fields for a correlated mitigation", async () => {
    serve(correlatedMitigation, signalGroupDetailData)

    await renderPage()

    expect(screen.getByTestId("correlation-card")).toBeTruthy()

    // Signal group link
    const groupLink = screen.getByText("sg-001-aaaa-bbbb-cccc-dddd")
    expect(groupLink.closest("a")).toBeTruthy()
    expect(groupLink.closest("a")?.getAttribute("href")).toBe(
      "/correlation/groups/sg-001-aaaa-bbbb-cccc-dddd"
    )

    // Derived confidence percentage
    expect(screen.getByText("88%")).toBeTruthy()

    // Source count
    expect(screen.getByText(/2 sources/)).toBeTruthy()

    // Contributing source names (badge + table)
    expect(screen.getAllByText("fastnetmon").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("alertmanager").length).toBeGreaterThanOrEqual(1)

    // Corroboration badge
    expect(screen.getByText("Corroborated")).toBeTruthy()

    // Why explanation text
    expect(screen.getByText(/Corroboration achieved/)).toBeTruthy()
  })

  // JSON cannot carry NaN, so the API's invalid confidence is an out-of-range fraction.
  it.each([
    [0, "0%"], [null, "Unavailable"], [1.5, "Invalid"],
  ])("preserves source confidence %s in mitigation reasons", async (confidence, label) => {
    serve(
      { ...correlatedMitigation, correlation: { ...correlation, derived_confidence: 0 } },
      { ...signalGroupDetailData, events: [{ ...signalGroupDetailData.events[0], confidence }] },
    )
    await renderPage()
    const row = within(screen.getByRole("table")).getByText("fastnetmon").closest("tr")!
    expect(within(row).getAllByRole("cell")[1]).toHaveTextContent(label)
    expect(screen.getByRole("meter", { name: "Confidence" })).toHaveAttribute("aria-valuenow", "0")
  })

  it("shows contributing sources table with confidence and weight from signal group detail", async () => {
    serve(correlatedMitigation, signalGroupDetailData)

    await renderPage()

    // Table headers
    expect(screen.getByText("Contributing sources")).toBeTruthy()
    expect(screen.getByText("Confidence")).toBeTruthy()
    expect(screen.getByText("Weight")).toBeTruthy()

    // fastnetmon: 95% confidence, 1.0 weight
    expect(screen.getByText("95%")).toBeTruthy()
    expect(screen.getByText("1.0")).toBeTruthy()

    // alertmanager: 80% confidence, 0.8 weight
    expect(screen.getByText("80%")).toBeTruthy()
    expect(screen.getByText("0.8")).toBeTruthy()
  })

  it("shows signal group link that navigates to /correlation/groups/{id}", async () => {
    serve(correlatedMitigation, signalGroupDetailData)

    await renderPage()

    const link = screen.getByText("sg-001-aaaa-bbbb-cccc-dddd")
    const anchor = link.closest("a")
    expect(anchor?.getAttribute("href")).toBe(
      "/correlation/groups/sg-001-aaaa-bbbb-cccc-dddd"
    )
  })

  it("shows muted message for non-correlated mitigation", async () => {
    serve(nonCorrelatedMitigation)

    await renderPage()

    expect(screen.getByTestId("no-correlation-card")).toBeTruthy()
    expect(screen.getByText(/Single-source mitigation/)).toBeTruthy()
    expect(screen.queryByTestId("correlation-card")).toBeNull()
  })

  it("hides correlation section when mitigation has no correlation field", async () => {
    // No correlation field at all
    serve({ ...baseMitigation })

    await renderPage()

    expect(screen.getByTestId("no-correlation-card")).toBeTruthy()
    expect(screen.getByText(/Single-source mitigation/)).toBeTruthy()
  })

  it("renders pending corroboration badge when not met", async () => {
    serve({
      ...baseMitigation,
      correlation: {
        signal_group_id: "sg-002",
        derived_confidence: 0.45,
        source_count: 1,
        corroboration_met: false,
        contributing_sources: ["fastnetmon"],
        explanation: "Awaiting additional sources for corroboration.",
      },
    })

    await renderPage()

    expect(screen.getByTestId("correlation-card")).toBeTruthy()
    expect(screen.getByText("Pending")).toBeTruthy()
    expect(screen.queryByText("Corroborated")).toBeNull()
  })

  it("requests the signal group named by the mitigation's correlation", async () => {
    serve(correlatedMitigation, signalGroupDetailData)

    await renderPage()

    expect(controller.calls("GET", "/v1/signal-groups/sg-001-aaaa-bbbb-cccc-dddd")).toHaveLength(1)
  })

  it("requests no signal group when the mitigation has no correlation", async () => {
    serve(nonCorrelatedMitigation)

    await renderPage()

    expect(controller.requests.filter((request) => request.path.startsWith("/v1/signal-groups"))).toEqual([])
  })
})

describe("Mitigation Detail – load failures", () => {
  it("shows a retryable error rather than not-found when the request fails", async () => {
    serve(failure(500, "database unavailable"))

    await renderPage()

    expect(screen.getByRole("alert").textContent).toContain("Unable to load this mitigation")
    expect(screen.queryByText("Mitigation not found")).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Retry" }))
    await waitFor(() => expect(controller.calls("GET", mitigationPath)).toHaveLength(2))
  })

  it("keeps not-found for a 404", async () => {
    serve(failure(404, "not found"))

    await renderPage()

    expect(screen.getByText("Mitigation not found")).toBeTruthy()
    expect(screen.queryByRole("alert")).toBeNull()
  })
})
