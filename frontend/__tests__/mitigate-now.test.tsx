import { act, fireEvent, renderHook, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { playbookPrefill } from "@/components/dashboard/flowspec-rule-dialog"
import { useKeyboardShortcuts } from "@/hooks/use-keyboard-shortcuts"
import type { ConfigPlaybook, Mitigation } from "@/lib/api"
import { appWrapper, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
const now = new Date().toISOString()

const playbooks: ConfigPlaybook[] = [
  { name: "udp_prefix", match: { vector: "udp_flood", scope: "prefix" }, steps: [{ action: "discard", ttl_seconds: 30 }] },
  { name: "udp_ported", match: { vector: "udp_flood", require_top_ports: true }, steps: [{ action: "discard", ttl_seconds: 45 }] },
  { name: "udp_flood_police_first", match: { vector: "udp_flood" }, steps: [{ action: "police", rate_bps: 5_000_000, ttl_seconds: 120 }] },
  { name: "icmp_flood_discard", match: { vector: "icmp_flood" }, steps: [{ action: "discard", ttl_seconds: 300 }] },
  { name: "syn_blackhole", match: { vector: "syn_flood" }, steps: [{ action: "blackhole", ttl_seconds: 600 }] },
]

const created: Mitigation = {
  mitigation_id: "00000000-0000-4000-8000-000000000077",
  scope_hash: "scope-now", status: "active", customer_id: null, service_id: null, pop: "test-pop",
  victim_ip: "203.0.113.10", vector: "udp_flood", action_type: "police", rate_bps: 5_000_000,
  dst_prefix: "203.0.113.10/32", protocol: 17, dst_ports: [53], created_at: now, updated_at: now,
  expires_at: now, withdrawn_at: null, triggering_event_id: "manual", last_event_id: "manual", reason: "x",
  acknowledged_at: null, acknowledged_by: null, origin_mode: "enforced",
}

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} })
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: now }))
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: [], count: 0, next_cursor: null, has_more: false }))
  controller.route("GET", "/v1/config/playbooks", () => json({ playbooks, total_playbooks: playbooks.length, loaded_at: now }))
  controller.route("GET", "/v1/config/settings", () => json({ settings: { guardrails: { max_ports: 8 } }, loaded_at: now }))
  controller.route("POST", "/v1/mitigations", () => json(created, 201))
  controller.route("POST", "/v1/events", () => json({ event_id: "event", mitigation_id: "from-event", status: "accepted" }))
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }

  vi.unstubAllGlobals()
})

async function openAs(role: "admin" | "operator" | "viewer", url = "/mitigations") {
  signIn(controller, "credentials", operatorResponse(role))
  let handles!: ReturnType<typeof renderApp>
  await act(async () => {
    handles = renderApp(<MitigationsContentLive initialMitigateOpen={url.includes("mitigate=true")} />, { url })
  })
  await waitFor(() => expect(controller.calls("GET", "/v1/auth/me").length).toBeGreaterThan(0))
  await settle()

  return handles
}

describe("mitigate now", { timeout: 10_000 }, () => {
  it("opens the manual FlowSpec dialog prefilled from the vector's playbook and posts /v1/mitigations", async () => {
    const { router } = await openAs("operator")
    fireEvent.click(screen.getByRole("button", { name: "Mitigate now" }))
    const dialog = within(await screen.findByRole("dialog", { name: "Mitigate now" }))
    expect(dialog.getByText(/audited under your account/)).toBeInTheDocument()

    fireEvent.change(dialog.getByLabelText(/^Destination IP or CIDR/), { target: { value: "203.0.113.10" } })
    const vector = dialog.getByRole("combobox", { name: "Attack vector" })
    await waitFor(() => expect(vector).toBeEnabled())
    fireEvent.keyDown(vector, { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "UDP flood" }))

    // With no ports entered, the first host playbook without require_top_ports applies.
    expect(dialog.getByText(/from playbook udp_flood_police_first/)).toBeInTheDocument()
    expect(dialog.getByRole("combobox", { name: "Protocol" })).toHaveTextContent("udp")
    expect(dialog.getByRole("combobox", { name: "Action" })).toHaveTextContent("police")
    expect(dialog.getByLabelText(/^Rate/)).toHaveValue("5000000")
    expect(dialog.getByLabelText(/^TTL/)).toHaveValue("120")
    expect(dialog.getByLabelText(/^Reason/)).toHaveValue("Mitigate now: udp_flood (playbook udp_flood_police_first)")

    fireEvent.click(dialog.getByRole("button", { name: "Create rule" }))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith(`/mitigations/${created.mitigation_id}`))
    expect(controller.calls("POST", "/v1/events")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(1)
    const body = JSON.parse(controller.calls("POST", "/v1/mitigations")[0].body ?? "")
    expect(body).toEqual({
      victim_ip: "203.0.113.10", protocol: "udp", action: "police", rate_bps: 5_000_000,
      ttl_seconds: 120, reason: "Mitigate now: udp_flood (playbook udp_flood_police_first)",
    })
    // No detector claim: the controller attributes the rule to the signed-in operator.
    expect(body).not.toHaveProperty("source")
    expect(body).not.toHaveProperty("operator_id")
  })

  it("follows the destination and ports entered below the picker, keeping the operator's own edits", async () => {
    const { router } = await openAs("operator", "/mitigations?mitigate=true")
    const dialog = within(await screen.findByRole("dialog", { name: "Mitigate now" }))
    const vector = dialog.getByRole("combobox", { name: "Attack vector" })
    await waitFor(() => expect(vector).toBeEnabled())

    const pick = async (name: string) => {
      fireEvent.keyDown(vector, { key: "Enter" })
      fireEvent.click(await screen.findByRole("option", { name }))
    }

    const fill = (label: RegExp, value: string) => fireEvent.change(dialog.getByLabelText(label), { target: { value } })

    // Top down: the vector first, then an IPv6 destination moves ICMP to ICMPv6.
    await pick("ICMP flood")
    expect(dialog.getByRole("combobox", { name: "Protocol" })).toHaveTextContent("icmp")
    fill(/^Destination IP or CIDR/, "2001:db8::10")
    expect(dialog.getByRole("combobox", { name: "Protocol" })).toHaveTextContent("icmpv6")

    // Ports entered after the vector select the playbook that requires them.
    await pick("UDP flood")
    expect(dialog.getByRole("combobox", { name: "Action" })).toHaveTextContent("police")
    fill(/^Destination ports/, "53")
    expect(dialog.getByRole("combobox", { name: "Action" })).toHaveTextContent("discard")
    expect(dialog.getByLabelText(/^TTL/)).toHaveValue("45")
    expect(dialog.getByLabelText(/^Reason/)).toHaveValue("Mitigate now: udp_flood (playbook udp_ported)")

    // The operator's TTL survives a later recompute; the fields the picker wrote follow it.
    fill(/^TTL/, "90")
    fill(/^Destination ports/, "")
    expect(dialog.getByRole("combobox", { name: "Action" })).toHaveTextContent("police")
    expect(dialog.getByLabelText(/^Rate/)).toHaveValue("5000000")
    expect(dialog.getByLabelText(/^TTL/)).toHaveValue("90")
    expect(dialog.getByLabelText(/^Reason/)).toHaveValue("Mitigate now: udp_flood (playbook udp_flood_police_first)")

    fireEvent.click(dialog.getByRole("button", { name: "Create rule" }))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith(`/mitigations/${created.mitigation_id}`))
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations")[0].body ?? "")).toMatchObject({ victim_ip: "2001:db8::10", protocol: "udp", action: "police", rate_bps: 5_000_000, ttl_seconds: 90 })
  })

  it("keeps an operator's own reason when the vector changes", async () => {
    await openAs("operator", "/mitigations?mitigate=true")
    const dialog = within(await screen.findByRole("dialog", { name: "Mitigate now" }))
    fireEvent.change(dialog.getByLabelText(/^Reason/), { target: { value: "NOC ticket 4411" } })
    const vector = dialog.getByRole("combobox", { name: "Attack vector" })
    await waitFor(() => expect(vector).toBeEnabled())
    fireEvent.keyDown(vector, { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "ICMP flood" }))
    expect(dialog.getByLabelText(/^Reason/)).toHaveValue("NOC ticket 4411")
  })

  it("keeps an edited reason that still starts like the picker's across vector changes", async () => {
    await openAs("operator", "/mitigations?mitigate=true")
    const dialog = within(await screen.findByRole("dialog", { name: "Mitigate now" }))
    const vector = dialog.getByRole("combobox", { name: "Attack vector" })
    await waitFor(() => expect(vector).toBeEnabled())
    fireEvent.keyDown(vector, { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "UDP flood" }))
    const reason = "Mitigate now: udp_flood (playbook udp_flood_police_first) INC-4411"
    fireEvent.change(dialog.getByLabelText(/^Reason/), { target: { value: reason } })

    fireEvent.keyDown(vector, { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "ICMP flood" }))
    expect(dialog.getByRole("combobox", { name: "Action" })).toHaveTextContent("discard")
    expect(dialog.getByLabelText(/^Reason/)).toHaveValue(reason)
  })

  it("is not offered to a viewer, even from the mitigate link", async () => {
    await openAs("viewer", "/mitigations?mitigate=true")
    expect(screen.queryByRole("button", { name: "Mitigate now" })).not.toBeInTheDocument()
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    expect(controller.calls("GET", "/v1/config/playbooks")).toHaveLength(0)
  })
})

describe("mitigate now shortcut", () => {
  it.each([[false, 0], [true, 1]] as const)("opens from n only for a role that can mitigate (%s)", (canMitigate, pushes) => {
    const app = appWrapper({ withoutAuth: true })
    renderHook(() => useKeyboardShortcuts({ canMitigate }), { wrapper: app.wrapper })
    fireEvent.keyDown(window, { key: "n" })
    expect(app.handles.router.push.mock.calls.filter(([url]) => url === "/mitigations?mitigate=true")).toHaveLength(pushes)
  })
})

describe("playbook prefill", () => {
  const blank = { victimIp: "", dstPorts: "" }

  it("matches the controller's first host playbook for the vector", () => {
    expect(playbookPrefill("udp_flood", playbooks, blank)).toEqual({
      playbook: "udp_flood_police_first",
      fields: { protocol: "udp", action: "police", rateBps: "5000000", ttl: "120" },
    })
    expect(playbookPrefill("udp_flood", playbooks, { victimIp: "", dstPorts: "53" }).playbook).toBe("udp_ported")
  })

  it("uses ICMPv6 for an IPv6 destination", () => {
    expect(playbookPrefill("icmp_flood", playbooks, { victimIp: "2001:db8::1", dstPorts: "" }).fields.protocol).toBe("icmpv6")
    expect(playbookPrefill("icmp_flood", playbooks, { victimIp: "192.0.2.1", dstPorts: "" }).fields.protocol).toBe("icmp")
  })

  it("leaves the action to the operator when the playbook has none a FlowSpec rule can carry", () => {
    const blackhole = playbookPrefill("syn_flood", playbooks, blank)
    expect(blackhole.fields).toEqual({ protocol: "tcp", ttl: "600" })
    expect(blackhole.note).toMatch(/syn_blackhole has no single police or discard action/)
    const none = playbookPrefill("ack_flood", playbooks, blank)
    expect(none).toEqual({ playbook: null, fields: { protocol: "tcp" }, note: "No playbook matches this vector. Choose the action." })
    expect(playbookPrefill("unknown", [], blank).fields.protocol).toBe("any")
  })
})
