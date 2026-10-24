import { fireEvent, screen, waitFor } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import { ExtendLifetimeDialog } from "@/components/dashboard/extend-lifetime-dialog"
import type { Mitigation } from "@/lib/api"
import { deferred, failure, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
const now = Date.now()

const mitigation: Mitigation = {
  mitigation_id: "rule-1", scope_hash: "scope", status: "active", customer_id: "owner", service_id: null,
  pop: "test-pop", victim_ip: "2001:db8:1234::/48", vector: "udp_flood", action_type: "police", rate_bps: 1048576,
  dst_prefix: "2001:db8:1234::/48", protocol: 17, dst_ports: [53], src_ports: [123],
  created_at: new Date(now - 60000).toISOString(), updated_at: new Date(now - 60000).toISOString(),
  expires_at: new Date(now + 120000).toISOString(), withdrawn_at: null,
  triggering_event_id: "event-1", last_event_id: "event-1", reason: "detector reason", acknowledged_at: null,
  acknowledged_by: null, origin_mode: "enforced",
}

function setup(role: "viewer" | "operator" = "operator", fields: Partial<Mitigation> = {}, mode = "enforced", minimum = 30) {
  signIn(controller, "credentials", operatorResponse(role))
  controller.route("GET", "/v1/config/settings", () => json({ settings: {
    pop: "test-pop", mode, guardrails: { min_ttl_seconds: minimum, max_ttl_seconds: 1800 },
  }, loaded_at: new Date(now).toISOString() }))
  const onUpdated = vi.fn(async () => {})
  const view = renderApp(<ExtendLifetimeDialog mitigation={{ ...mitigation, ...fields }} now={now} onUpdated={onUpdated} />)

  return { ...view, onUpdated }
}

async function open() {
  fireEvent.click(await screen.findByRole("button", { name: "Extend lifetime" }))
  await screen.findByRole("dialog")
}

describe("operator lifetime extension", () => {
  it("previews exact target and expiry, requires a reason and confirms the bounded remaining lifetime", async () => {
    const response = deferred<Response>()
    controller.route("POST", "/v1/mitigations/rule-1/extend", () => response.promise)
    const { onUpdated: refresh } = setup()
    await open()
    expect(screen.getByText(/2001:db8:1234::\/48.*source-port 123.*rate-limit/)).toBeVisible()
    expect(screen.getByText("1048576 bps")).toBeVisible()
    expect(screen.getByText("Current expiry")).toBeVisible()
    expect(screen.getByText("Estimated new expiry")).toBeVisible()
    const confirm = screen.getByRole("button", { name: "Confirm extension" })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "attack continues" } })
    fireEvent.change(screen.getByLabelText("Remaining lifetime (seconds)"), { target: { value: "1801" } })
    expect(confirm).toBeDisabled()
    fireEvent.change(screen.getByLabelText("Remaining lifetime (seconds)"), { target: { value: "600" } })
    fireEvent.click(confirm)
    fireEvent.click(confirm)
    await waitFor(() => expect(controller.calls("POST", "/v1/mitigations/rule-1/extend")).toHaveLength(1))
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations/rule-1/extend")[0].body!)).toEqual({ ttl_seconds: 600, reason: "attack continues" })
    response.resolve(json({ extended: true, previous_expires_at: mitigation.expires_at, mitigation: { ...mitigation, expires_at: new Date(now + 600000).toISOString() } }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(refresh).toHaveBeenCalledOnce()
  })

  it("shows an explicit unchanged horizon and no-op confirmation", async () => {
    controller.route("POST", "/v1/mitigations/rule-1/extend", () => json({ extended: false, previous_expires_at: mitigation.expires_at, mitigation }))
    setup()
    await open()
    fireEvent.change(screen.getByLabelText("Remaining lifetime (seconds)"), { target: { value: "30" } })
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "check horizon" } })
    expect(screen.getByText("Estimated expiry (unchanged)")).toBeVisible()
    fireEvent.click(screen.getByRole("button", { name: "Confirm lifetime check" }))
    expect(await screen.findByText("Existing expiry already meets the requested lifetime; no change recorded")).toBeVisible()
  })

  it("treats an unavailable result as ambiguous and refreshes before retry", async () => {
    controller.route("POST", "/v1/mitigations/rule-1/extend", () => failure(503))
    const { onUpdated: refresh } = setup()
    await open()
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "ongoing" } })
    fireEvent.click(screen.getByRole("button", { name: "Confirm extension" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("the update may have been saved")
    expect(refresh).toHaveBeenCalledOnce()
    expect(screen.getByRole("dialog")).toBeVisible()
  })

  it("retains a precise safety refusal without suggesting a committed update", async () => {
    controller.route("POST", "/v1/mitigations/rule-1/extend", () => failure(422, "source prefix matching is disabled"))
    setup()
    await open()
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "ongoing" } })
    fireEvent.click(screen.getByRole("button", { name: "Confirm extension" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("source prefix matching is disabled")
    expect(screen.getByRole("alert")).not.toHaveTextContent("may have been saved")
  })

  it("retains an open dialog and refusal when the mitigation expires during a request", async () => {
    const response = deferred<Response>()
    controller.route("POST", "/v1/mitigations/rule-1/extend", () => response.promise)
    const view = setup()

    await open()
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "ongoing" } })
    fireEvent.click(screen.getByRole("button", { name: "Confirm extension" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/mitigations/rule-1/extend")).toHaveLength(1))
    view.rerender(<ExtendLifetimeDialog mitigation={mitigation} now={Date.parse(mitigation.expires_at) + 1} onUpdated={view.onUpdated} />)
    expect(screen.getByRole("dialog")).toBeVisible()
    expect(screen.getByRole("status")).toHaveTextContent("no longer eligible")
    expect(screen.queryByRole("button", { name: "Extend lifetime" })).not.toBeInTheDocument()
    response.resolve(failure(409, "mitigation has expired"))
    expect(await screen.findByRole("alert")).toHaveTextContent("mitigation has expired")
    expect(screen.getByRole("dialog")).toBeVisible()
    const confirm = screen.getByRole("button", { name: "Confirm extension" })
    expect(confirm).toBeDisabled()
    fireEvent.click(confirm)
    fireEvent.submit(screen.getByLabelText("Reason for extending").closest("form")!)
    expect(controller.calls("POST", "/v1/mitigations/rule-1/extend")).toHaveLength(1)
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(screen.queryByRole("button", { name: "Extend lifetime" })).not.toBeInTheDocument()
  })

  it("retains an uncertain update warning when error refresh discovers withdrawal", async () => {
    const response = deferred<Response>()
    controller.route("POST", "/v1/mitigations/rule-1/extend", () => response.promise)
    const view = setup()
    view.onUpdated.mockImplementation(async () => {
      view.rerender(<ExtendLifetimeDialog mitigation={{ ...mitigation, status: "withdrawn", withdrawn_at: new Date(now).toISOString() }} now={now} onUpdated={view.onUpdated} />)
    })

    await open()
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "ongoing" } })
    fireEvent.click(screen.getByRole("button", { name: "Confirm extension" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/mitigations/rule-1/extend")).toHaveLength(1))
    response.resolve(failure(503))
    expect(await screen.findByRole("alert")).toHaveTextContent("the update may have been saved")
    expect(view.onUpdated).toHaveBeenCalledOnce()
    expect(screen.getByRole("dialog")).toBeVisible()
    expect(screen.getByRole("status")).toHaveTextContent("current status and audit")
    expect(screen.queryByRole("button", { name: "Extend lifetime" })).not.toBeInTheDocument()
    const confirm = screen.getByRole("button", { name: "Confirm extension" })
    expect(confirm).toBeDisabled()
    fireEvent.click(confirm)
    fireEvent.submit(screen.getByLabelText("Reason for extending").closest("form")!)
    expect(controller.calls("POST", "/v1/mitigations/rule-1/extend")).toHaveLength(1)
    expect(screen.getByRole("alert")).toHaveTextContent("the update may have been saved")
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(screen.queryByRole("button", { name: "Extend lifetime" })).not.toBeInTheDocument()
  })

  it("offers positive remaining lifetime when the general policy minimum is zero", async () => {
    setup("operator", {}, "enforced", 0)
    await open()
    const ttl = screen.getByLabelText("Remaining lifetime (seconds)")
    expect(ttl).toHaveAttribute("min", "1")
    fireEvent.change(ttl, { target: { value: "1" } })
    fireEvent.change(screen.getByLabelText("Reason for extending"), { target: { value: "check" } })
    expect(screen.getByRole("button", { name: "Confirm lifetime check" })).toBeEnabled()
    fireEvent.change(ttl, { target: { value: "0" } })
    expect(screen.getByRole("button", { name: "Confirm lifetime check" })).toBeDisabled()
    fireEvent.change(ttl, { target: { value: "" } })
    expect(ttl).toHaveValue(null)
    expect(screen.getByRole("button", { name: "Confirm lifetime check" })).toBeDisabled()
  })

  it.each([
    ["viewer", {}, "enforced"], ["operator", { action_type: "blackhole" }, "enforced"],
    ["operator", { status: "pending" }, "enforced"], ["operator", { origin_mode: null }, "enforced"],
    ["operator", { expires_at: new Date(now - 1).toISOString() }, "enforced"],
    ["operator", {}, "dry-run"],
  ] as const)("hides ineligible extension %s %j %s", async (role, fields, mode) => {
    setup(role, fields, mode)
    await waitFor(() => expect(controller.calls("GET", "/v1/config/settings")).toHaveLength(1))
    expect(screen.queryByRole("button", { name: "Extend lifetime" })).not.toBeInTheDocument()
  })
})
