import { act, screen, waitFor, within } from "@testing-library/react"
import { Suspense } from "react"
import { describe, expect, it } from "vitest"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import type { Mitigation } from "@/lib/api"
import { json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const retrying: Mitigation = {
  mitigation_id: "mit-1", scope_hash: "scope-1", status: "active", customer_id: "acme", service_id: null, pop: "iad1",
  victim_ip: "203.0.113.20", vector: "syn_flood", action_type: "discard", rate_bps: null,
  dst_prefix: "203.0.113.20/32", protocol: 6, dst_ports: [443],
  created_at: "2026-11-14T10:00:00Z", updated_at: "2026-11-14T10:00:00Z", expires_at: "2026-11-14T10:05:00Z",
  withdrawn_at: null, triggering_event_id: "event-1", last_event_id: "event-1", reason: "flood",
  acknowledged_at: null, acknowledged_by: null,
  withdrawal_pending: {
    requested_at: "2026-11-14T10:02:00Z",
    operation_id: "1f8c3d0e-2b4a-4c6d-8e0f-1a2b3c4d5e6f",
    actor: "alice",
    reason: "false positive",
  },
}

const completed: Mitigation = { ...retrying, status: "expired", withdrawal_pending: null }

async function renderList(rows: Mitigation[]) {
  signIn(controller, "credentials", operatorResponse("viewer"))
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [] }))
  controller.route("GET", "/v1/pops", () => json([]))
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: rows, count: rows.length, next_cursor: null, has_more: false }))
  renderApp(<MitigationsContentLive />, { url: "/mitigations" })
  await screen.findByText(rows[0].victim_ip)
}

async function renderDetail(row: Mitigation) {
  signIn(controller, "none", null)
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [] }))
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: [row], count: 1, next_cursor: null, has_more: false }))
  controller.route("GET", "/v1/mitigations/mit-1", () => json(row))
  await act(async () => {
    renderApp(<Suspense fallback={null}><MitigationDetailPage params={Promise.resolve({ id: "mit-1" })} /></Suspense>, { url: "/mitigations/mit-1" })
  })
  await settle()
}

describe("pending withdrawal state", () => {
  it("shows the retry time on an expired-looking list row", async () => {
    await renderList([retrying])

    expect(await screen.findByText(/Withdrawal retrying since/)).toBeInTheDocument()
  })

  it("filters the list by withdrawing", async () => {
    await renderList([retrying])

    await act(async () => screen.getByRole("button", { name: "withdrawing" }).click())
    await waitFor(() => {
      const status = controller.calls("GET", "/v1/mitigations").at(-1)?.query.get("status")
      expect(status?.split(",")).toContain("withdrawing")
    })
  })

  it("shows the recorded request on the detail page", async () => {
    await renderDetail(retrying)

    const card = await screen.findByTestId("withdrawal-pending-card")
    expect(within(card).getByText(/Withdrawal retrying since/)).toBeInTheDocument()
    expect(within(card).getByText("alice")).toBeInTheDocument()
    expect(within(card).getByText("false positive")).toBeInTheDocument()
    expect(within(card).getByText(retrying.withdrawal_pending!.operation_id)).toBeInTheDocument()
  })

  it("shows no retry state on a completed list row", async () => {
    await renderList([completed])

    expect(screen.queryByText(/Withdrawal retrying since/)).not.toBeInTheDocument()
  })

  it("shows no retry state on a completed detail page", async () => {
    await renderDetail(completed)

    expect(await screen.findByRole("heading", { level: 1, name: completed.victim_ip })).toBeInTheDocument()
    expect(screen.queryByTestId("withdrawal-pending-card")).not.toBeInTheDocument()
    expect(screen.queryByText(/Withdrawal retrying since/)).not.toBeInTheDocument()
  })
})
