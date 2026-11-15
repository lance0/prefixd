import { describe, it, expect } from "vitest"
import { screen, act, within, waitFor, fireEvent } from "@testing-library/react"
import { Suspense } from "react"
import type { AuditEntry, Mitigation } from "@/lib/api"
import { failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"

const controller = useFakeController()

const id = "mit-001-aaaa-bbbb-cccc"
const created = new Date(Date.now() - 600_000).toISOString()
const firstExpiry = new Date(Date.now() - 480_000).toISOString()
const extendedAt = new Date(Date.now() - 300_000).toISOString()
const expiry = new Date(Date.now() + 900_000).toISOString()

// Extended once: updated_at differs from created_at, which the old timeline described as "Rule set to police".
const mitigation: Mitigation = {
  mitigation_id: id,
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
  created_at: created,
  updated_at: extendedAt,
  expires_at: expiry,
  withdrawn_at: null,
  triggering_event_id: "evt-001",
  last_event_id: "evt-001",
  reason: "UDP flood detected",
  acknowledged_at: null,
  acknowledged_by: null,
  correlation: null,
}

function entry(action: string, timestamp: string, actor: Pick<AuditEntry, "actor_type" | "actor_id">, details: AuditEntry["details"]): AuditEntry {
  return { audit_id: `${action}-id`, timestamp, schema_version: 1, ...actor, action, target_type: "mitigation", target_id: id, details }
}

// Newest first, as the API returns them.
const entries: AuditEntry[] = [
  entry("extend", extendedAt, { actor_type: "operator", actor_id: "alice" }, {
    reason: "attack still ongoing",
    previous_expires_at: firstExpiry,
    expires_at: expiry,
    ttl_seconds: 1200,
  }),
  entry("create", created, { actor_type: "detector", actor_id: "fastnetmon" }, {
    reason: "UDP flood detected",
    expires_at: firstExpiry,
    event_id: "evt-001",
  }),
]

const mitigationPath = `/v1/mitigations/${id}`

function serve(audit: () => Response, auth: "none" | "viewer" = "none") {
  if (auth === "none") signIn(controller, "none", null)
  else signIn(controller, "credentials", operatorResponse("viewer"))
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: new Date().toISOString() }))
  controller.route("GET", mitigationPath, () => json(mitigation))
  controller.route("GET", "/v1/audit", audit)
}

async function renderPage() {
  await act(async () => {
    renderApp(
      <Suspense fallback={<div>Loading suspense...</div>}>
        <MitigationDetailPage params={Promise.resolve({ id })} />
      </Suspense>,
      { url: `/mitigations/${id}` },
    )
  })
  await waitFor(() => expect(controller.calls("GET", mitigationPath)).toHaveLength(1))
  await settle()
  await settle()

  return screen.getByTestId("mitigation-timeline")
}

describe("Mitigation timeline", () => {
  it("lists this mitigation's audit entries with actor, reason and old and new expiry", async () => {
    serve(() => json({ entries, count: entries.length, next_cursor: null, has_more: false }))
    const timeline = await renderPage()

    await waitFor(() => expect(within(timeline).getByText("Lifetime extended")).toBeInTheDocument())
    const [request] = controller.calls("GET", "/v1/audit")
    expect(request.query.get("target_type")).toBe("mitigation")
    expect(request.query.get("target_id")).toBe(id)

    const steps = within(timeline).getAllByRole("listitem")
    // Oldest first; the create entry stands in for the record's own Created step.
    expect(steps.map((step) => step.querySelector("p")?.textContent)).toEqual(["Created", "Lifetime extended", "Expires"])

    const extension = within(steps[1])
    expect(extension.getByText("alice")).toBeInTheDocument()
    expect(extension.getByText("(operator)")).toBeInTheDocument()
    expect(extension.getByText("extend")).toBeInTheDocument()
    expect(extension.getByText("attack still ongoing")).toBeInTheDocument()
    const times = steps[1].querySelectorAll("dd time")
    expect([...times].map((time) => time.getAttribute("dateTime"))).toEqual([firstExpiry, expiry])

    const creation = within(steps[0])
    expect(creation.getByText("fastnetmon")).toBeInTheDocument()
    expect(creation.getByRole("link", { name: "evt-001" })).toHaveAttribute("href", "/events?id=evt-001")

    // The extension is no longer described as a rule change.
    expect(within(timeline).queryByText(/Rule set to/)).not.toBeInTheDocument()
    expect(within(timeline).getByText(/Record last updated/)).toBeInTheDocument()
  })

  it("shows the operation ID and ended lifetime of a withdrawal", async () => {
    const withdrawnAt = new Date(Date.now() - 60_000).toISOString()
    const withdrawal = entry("withdraw", withdrawnAt, { actor_type: "system", actor_id: "safelist" }, {
      reason: "safelisted after admission",
      operation_id: "op-1234-5678",
      previous_expires_at: expiry,
      ended_at: withdrawnAt,
    })
    signIn(controller, "none", null)
    controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: new Date().toISOString() }))
    controller.route("GET", mitigationPath, () => json({ ...mitigation, status: "withdrawn", withdrawn_at: withdrawnAt }))
    controller.route("GET", "/v1/audit", () => json({ entries: [withdrawal, ...entries], count: 3, next_cursor: null, has_more: false }))
    const timeline = await renderPage()

    await waitFor(() => expect(within(timeline).getByText("op-1234-5678")).toBeInTheDocument())
    const steps = within(timeline).getAllByRole("listitem")
    // The audit entry replaces the record's Withdrawn step rather than repeating it.
    expect(steps.map((step) => step.querySelector("p")?.textContent)).toEqual(["Created", "Lifetime extended", "Withdrawn"])
    expect(within(steps[2]).getByText("safelisted after admission")).toBeInTheDocument()
    expect([...steps[2].querySelectorAll("dd time")].map((time) => time.getAttribute("dateTime"))).toEqual([expiry, withdrawnAt])
  })

  it("keeps the record's timeline and shows the error when the audit fails to load", async () => {
    let fail = true
    serve(() => fail ? failure(500, "audit unavailable") : json({ entries, count: entries.length, next_cursor: null, has_more: false }))
    const timeline = await renderPage()

    const alert = await within(timeline).findByRole("alert")
    expect(alert).toHaveTextContent("Unable to load audit entries")
    // The timeline is still there, from the mitigation record.
    const steps = within(timeline).getAllByRole("listitem")
    expect(steps.map((step) => step.querySelector("p")?.textContent)).toEqual(["Created", "Expires"])
    expect(within(timeline).queryByText(/Rule set to/)).not.toBeInTheDocument()

    fail = false
    await act(async () => { fireEvent.click(within(alert).getByRole("button", { name: "Retry" })) })
    await waitFor(() => expect(within(timeline).getByText("Lifetime extended")).toBeInTheDocument())
    expect(within(timeline).queryByRole("alert")).not.toBeInTheDocument()
  })

  it("does not request the audit for a viewer and keeps the record's timeline", async () => {
    serve(() => json({ entries, count: entries.length, next_cursor: null, has_more: false }), "viewer")
    const timeline = await renderPage()

    await waitFor(() => expect(within(timeline).getByText(/needs the operator role/)).toBeInTheDocument())
    expect(controller.calls("GET", "/v1/audit")).toHaveLength(0)
    expect(within(timeline).queryByRole("alert")).not.toBeInTheDocument()
    expect(within(timeline).getAllByRole("listitem").map((step) => step.querySelector("p")?.textContent)).toEqual(["Created", "Expires"])
  })
})
