import { act, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { ScrubbersContent } from "@/components/dashboard/scrubbers-content"
import { createDiversion, previewDiversion, type DiversionPreview, type DiversionRequest, type ScrubberDiversion, type ScrubberProfiles } from "@/lib/api"
import type { OperatorRole } from "@/lib/auth"
import { deferred, failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map(name => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

function result(dryRun = false): DiversionPreview {
  return {
    candidate: {
      id: "operation-1", profile: { id: "a", revision: "v1" },
      rule: { nlri: { dst_prefix: "203.0.113.20/32", src_prefix: "198.51.100.0/24", protocol: 6, dst_ports: [443] }, target: "192.0.2.99", owner: "profile-owner", revision: 1 },
      expires_at: "2030-01-01T00:00:00Z", status: dryRun ? "simulated" : "pending", dry_run: dryRun, withdrawal_reason: null, last_error: null,
    },
    confirmation: "exact-full-match-and-target-v1", readiness: { armed: !dryRun, ready: !dryRun, observed_at: null, latch_reason: null },
    evidence: "Preview only; no reservation or speaker mutation. Withdrawal returns traffic to ordinary routing.",
  }
}

const active = { ...result().candidate, status: "active" as const }

function profiles(armed: boolean, ready: boolean): ScrubberProfiles {
  return { enabled: true, profiles: { a: { armed, ready, readiness: ready ? "ready" : "unknown", observed_at: null, latch_reason: null } }, configuration: [{ id: "a", revision: "v1", ipv4_target: "192.0.2.99", ipv6_target: null }] }
}

interface View { armed?: boolean; ready?: boolean; rows?: ScrubberDiversion[]; role?: OperatorRole; scrubbers?: () => Response }

async function render({ armed = true, ready = true, rows = [active], role = "admin", scrubbers = () => json(profiles(armed, ready)) }: View = {}) {
  signIn(controller, "credentials", operatorResponse(role))
  controller.route("GET", "/v1/scrubbers", scrubbers)
  controller.route("GET", "/v1/diversions", () => json(rows))
  renderApp(<ScrubbersContent />, { url: "/scrubbers" })
  await settle()
}

function mutations() {
  return controller.requests.filter(request => request.method !== "GET")
}

async function openWithdraw() {
  fireEvent.click(await screen.findByRole("button", { name: "Withdraw 203.0.113.20/32" }))

  return screen.findByRole("alertdialog", { name: "Withdraw diversion" })
}

async function setup(dryRun = false, routingScope?: string) {
  signIn(controller, "credentials", operatorResponse("admin"))
  controller.route("GET", "/v1/scrubbers", () => {
    const configured = profiles(!dryRun, !dryRun)

    if (routingScope) configured.configuration[0].scope = routingScope

    return json(configured)
  })
  controller.route("GET", "/v1/diversions", () => json([]))
  controller.route("POST", "/v1/diversions/preview", () => json(result(dryRun)))
  controller.route("POST", "/v1/diversions", () => json({ ...result(dryRun).candidate, status: dryRun ? "simulated" : "active" }, 202))
  renderApp(<ScrubbersContent />, { url: "/scrubbers" })
  await screen.findByText("New diversion")
  fireEvent.keyDown(screen.getByRole("combobox", { name: "Profile" }), { key: "Enter" })
  fireEvent.click(await screen.findByRole("option", { name: "a" }))
  fireEvent.change(screen.getByLabelText("Victim host CIDR"), { target: { value: "203.0.113.20/32" } })
  fireEvent.change(screen.getByLabelText("Source prefix (optional)"), { target: { value: "198.51.100.0/24" } })
  fireEvent.change(screen.getByLabelText("Destination ports (optional)"), { target: { value: "443" } })
  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Investigated attack" } })
}

// Real Radix form interactions on throttled runners; see CONTRIBUTING.md.
describe("manual scrubber workflow", { timeout: 10_000 }, () => {
  it("requires explicit match/target confirmation and preserves the source selector", async () => {
    await setup()
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    const confirm = await screen.findByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })

    expect(screen.getByRole("button", { name: "Create diversion" })).toBeDisabled()
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
    fireEvent.click(confirm)
    fireEvent.click(screen.getByRole("button", { name: "Create diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions")).toHaveLength(1))
    const sent = JSON.parse(controller.calls("POST", "/v1/diversions")[0].body ?? "{}")

    expect(sent).toMatchObject({ profile: "a", scope: { dst_prefix: "203.0.113.20/32", src_prefix: "198.51.100.0/24", protocol: 6, dst_ports: [443] }, confirmation: result().confirmation })
    expect(sent).not.toHaveProperty("target")
    expect(sent).not.toHaveProperty("owner")
  })

  it("discards a preview that completes after the form changes", async () => {
    await setup()
    const pending = deferred<Response>()

    controller.route("POST", "/v1/diversions/preview", () => pending.promise)
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions/preview")).toHaveLength(1))
    fireEvent.change(screen.getByLabelText("Victim host CIDR"), { target: { value: "203.0.113.21/32" } })
    await act(async () => { pending.resolve(json(result())) })
    await settle()
    expect(screen.queryByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
  })

  it("records a dry-run without requiring an armed or ready profile", async () => {
    await setup(true)
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    fireEvent.click(await screen.findByRole("checkbox", { name: "I confirm this traffic match and scrubber target." }))
    expect(screen.getByRole("button", { name: "Record simulation" })).toBeEnabled()
    fireEvent.click(screen.getByRole("button", { name: "Record simulation" }))
    await screen.findByText("Simulation recorded; no speaker mutation sent.")
    expect(controller.calls("POST", "/v1/scrubbers/a/arm")).toHaveLength(0)
  })

  it("previews the protocol chosen from the select and treats Any as no protocol", async () => {
    await setup()
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Protocol" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "Any" }))
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions/preview")).toHaveLength(1))
    expect(JSON.parse(controller.calls("POST", "/v1/diversions/preview")[0].body ?? "{}").scope.protocol).toBeNull()
  })

  it("discards a shown preview when the protocol changes", async () => {
    await setup()
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    await screen.findByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Protocol" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "UDP" }))
    await waitFor(() => expect(screen.queryByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })).not.toBeInTheDocument())
  })
})

describe("diversion withdrawal", () => {
  it("opens a confirmation that sends nothing until confirmed, and Cancel sends nothing", async () => {
    await render()
    const dialog = await openWithdraw()

    expect(dialog).toHaveTextContent("dst 203.0.113.20/32 · src 198.51.100.0/24 · protocol 6 · dst ports 443")
    expect(dialog).toHaveTextContent("192.0.2.99")
    expect(dialog).toHaveTextContent("a@v1")
    expect(dialog).toHaveTextContent("may expose the victim to the attack again")
    expect(dialog).toHaveTextContent("No automatic discard, blackhole or fallback")
    expect(mutations()).toHaveLength(0)
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    await settle()
    expect(mutations()).toHaveLength(0)
  })

  it("sends the typed reason once on confirm", async () => {
    await render()
    controller.route("POST", "/v1/diversions/operation-1/withdraw", () => json({ ...active, status: "withdrawing" }, 202))
    const dialog = await openWithdraw()

    fireEvent.change(within(dialog).getByLabelText("Withdrawal reason (optional)"), { target: { value: "  Attack subsided  " } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await screen.findByText("Withdrawal requested. Victim exclusion remains until local absence is confirmed.")
    expect(mutations()).toHaveLength(1)
    expect(controller.calls("POST", "/v1/diversions/operation-1/withdraw")).toHaveLength(1)
    expect(JSON.parse(controller.calls("POST", "/v1/diversions/operation-1/withdraw")[0].body ?? "")).toEqual({ reason: "Attack subsided" })
  })

  it("sends an empty body when no reason is given", async () => {
    await render()
    controller.route("POST", "/v1/diversions/operation-1/withdraw", () => json({ ...active, status: "withdrawing" }, 202))
    const dialog = await openWithdraw()

    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions/operation-1/withdraw")).toHaveLength(1))
    expect(JSON.parse(controller.calls("POST", "/v1/diversions/operation-1/withdraw")[0].body ?? "")).toEqual({})
  })

  it("closes after an accepted withdrawal while the diversions refresh is still pending", async () => {
    await render()
    controller.route("POST", "/v1/diversions/operation-1/withdraw", () => json({ ...active, status: "withdrawing" }, 202))
    const dialog = await openWithdraw()
    const refresh = deferred<Response>()

    controller.route("GET", "/v1/diversions", () => refresh.promise)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await screen.findByText("Withdrawal requested. Victim exclusion remains until local absence is confirmed.")
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    refresh.resolve(json([{ ...active, status: "withdrawing" }]))
    await settle()
  })

  it.each([409, 500])("shows a failed withdrawal (%i) and keeps the diversion row", async status => {
    await render()
    controller.route("POST", "/v1/diversions/operation-1/withdraw", () => json({ error: "withdrawal not accepted" }, status))
    const dialog = await openWithdraw()

    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("withdrawal not accepted")
    expect(screen.getByText("203.0.113.20/32 → 192.0.2.99 · a@v1")).toBeInTheDocument()
    expect(screen.queryByText("Withdrawal requested. Victim exclusion remains until local absence is confirmed.")).not.toBeInTheDocument()
  })
})

describe("scrubber re-arm and access", () => {
  it("re-arms a ready, unarmed profile with its configured revision", async () => {
    await render({ armed: false, rows: [] })
    controller.route("POST", "/v1/scrubbers/a/arm", () => json(null))
    const rearm = await screen.findByRole("button", { name: "Re-arm a" })

    await waitFor(() => expect(rearm).toBeEnabled())
    fireEvent.click(rearm)
    await screen.findByText("Profile a re-armed. New intent requires a separate confirmation.")
    expect(controller.calls("POST", "/v1/scrubbers/a/arm")).toHaveLength(1)
    expect(JSON.parse(controller.calls("POST", "/v1/scrubbers/a/arm")[0].body ?? "")).toEqual({ revision: "v1" })
  })

  it.each([{ armed: true, ready: true }, { armed: false, ready: false }])("disables re-arm when armed=$armed and ready=$ready", async ({ armed, ready }) => {
    await render({ armed, ready, rows: [] })
    const rearm = await screen.findByRole("button", { name: "Re-arm a" })

    await settle()
    expect(rearm).toBeDisabled()
    fireEvent.click(rearm)
    await settle()
    expect(mutations()).toHaveLength(0)
  })

  it("shows non-administrators the requirement and sends no mutations", async () => {
    await render({ role: "operator" })
    await settle()
    expect(screen.getByText("Scrubber diversion requires an administrator.")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Withdraw|Re-arm|Preview/ })).not.toBeInTheDocument()
    expect(mutations()).toHaveLength(0)
  })

  it("reports unknown state when scrubber observations cannot be refreshed", async () => {
    await render({ scrubbers: () => failure(500) })
    expect(await screen.findByRole("alert")).toHaveTextContent("Scrubber observations could not be refreshed. Current state is unknown.")
  })

  it("labels export evidence from a failed read as historical", async () => {
    const peers = [{ peer_address: "192.0.2.2", disposition: "committed", reason: "" }]

    await render({ rows: [{ ...active, export_observation: { observed_at: "2030-01-01T00:00:00Z", peers, error: "scrubber export observation timed out" } }] })
    expect(await screen.findByText(/Historical peer export observation from 2030-01-01T00:00:00Z; current export unknown/)).toBeInTheDocument()
  })

  it("shows both legs, the return leg as destination any, and separate export evidence", async () => {
    const inbound = [{ peer_address: "192.0.2.2", disposition: "committed", reason: "" }]
    const returned = [{ peer_address: "192.0.2.3", disposition: "committed", reason: "" }]
    const row = pairResult().candidate

    await render({ rows: [{ ...row, status: "active", export_observation: { observed_at: "2030-01-01T00:00:00Z", peers: inbound }, return_export_observation: { observed_at: "2030-01-01T00:00:05Z", peers: returned, error: "scrubber export observation timed out" } }] })
    expect(await screen.findByText("Return leg: destination any · src 203.0.113.20/32 · protocol 6 · src ports 443 · flags SYN+ACK → 192.0.2.99 · community 64496:100")).toBeInTheDocument()
    expect(screen.getByText("Both legs observed locally · Expires 2030-01-01T00:00:00Z")).toBeInTheDocument()
    expect(screen.getByText("Inbound leg peer export observed since 2030-01-01T00:00:00Z")).toBeInTheDocument()
    expect(screen.getByText(/Historical return leg peer export observation from 2030-01-01T00:00:05Z; current export unknown/)).toBeInTheDocument()
    const dialog = await openWithdraw()

    expect(dialog).toHaveTextContent("and its return leg destination any · src 203.0.113.20/32")
    expect(dialog).toHaveTextContent("may expose the victim to the attack again")
  })

  it("previews and confirms both legs of a pair with the exact confirmation", async () => {
    await setup()
    controller.route("POST", "/v1/diversions/preview", () => json(pairResult()))
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    const confirm = await screen.findByRole("checkbox", { name: "I confirm both legs' traffic matches and the scrubber target." })

    expect(screen.getByText("Return leg: destination any · src 203.0.113.20/32 · protocol 6 · src ports 443 · flags SYN+ACK → 192.0.2.99 · community 64496:100 · peers 192.0.2.3")).toBeInTheDocument()
    fireEvent.click(confirm)
    fireEvent.click(screen.getByRole("button", { name: "Create diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions")).toHaveLength(1))
    const sent = JSON.parse(controller.calls("POST", "/v1/diversions")[0].body ?? "{}")

    expect(sent.confirmation).toBe(pairResult().confirmation)
    expect(sent).not.toHaveProperty("return_rule")
    expect(sent.scope).not.toHaveProperty("tcp_flags")
  })

  it("shows a profile's return leg and keeps inbound-only profiles unchanged", async () => {
    const configured = profiles(true, true)

    configured.configuration.push({ id: "b", revision: "v2", ipv4_target: "192.0.2.99", ipv6_target: null, return_leg: { router_peers: ["192.0.2.3"], policy_binding: "client-side-v1", export_community: "64496:100", tcp_flags: "syn_ack" } })
    await render({ rows: [], scrubbers: () => json(configured) })
    expect(await screen.findByText("Return leg for TCP: peers 192.0.2.3 · community 64496:100 · SYN+ACK only")).toBeInTheDocument()
    expect(screen.getByText("Inbound direction only")).toBeInTheDocument()
  })
})

function pairResult(): DiversionPreview {
  const preview = result()
  const returnLeg = { router_peers: ["192.0.2.3"], policy_binding: "client-side-v1", export_community: "64496:100", tcp_flags: "syn_ack" as const }

  preview.candidate.profile.return_leg = returnLeg
  delete preview.candidate.rule.nlri.src_prefix
  preview.candidate.return_rule = {
    nlri: { dst_prefix: "", src_prefix: "203.0.113.20/32", protocol: 6, dst_ports: [], src_ports: [443], tcp_flags: { set: ["syn", "ack"] } },
    target: "192.0.2.99", owner: "profile-owner", revision: 1, export_community: "64496:100",
  }
  preview.confirmation = "exact-inbound-match; return leg destination any exact-return-match"

  return preview
}

function vpnResult(family: "ipv4" | "ipv6", routingScope = "TRANSIT"): DiversionPreview {
  const preview = result()
  preview.candidate.profile.scope = routingScope
  preview.candidate.rule.nlri.scope = { family, rd: "44407:40" }
  preview.candidate.rule.route_targets = ["44407:777"]

  if (family === "ipv6") {
    preview.candidate.rule.nlri.dst_prefix = "2001:db8::20/128"
    preview.candidate.rule.nlri.src_prefix = "2001:db8:bad::/64"
    preview.candidate.rule.target = "2001:db8::99"
  }

  return preview
}

function vpnRequest(family: "ipv4" | "ipv6"): DiversionRequest {
  const preview = vpnResult(family)

  return { profile: "a", scope: preview.candidate.rule.nlri, ttl_seconds: 60, reason: "Investigated attack", confirmation: preview.confirmation }
}

describe("VPN diversion boundary", { timeout: 10_000 }, () => {
  it.each(["ipv4", "ipv6"] as const)("uses only scope-aware endpoints for %s and rechecks before creation", async family => {
    const preview = vpnResult(family)
    const request = vpnRequest(family)
    controller.route("POST", "/v1/vpn/diversions/preview", () => json(preview))
    controller.route("POST", "/v1/vpn/diversions", () => json(preview.candidate))
    await expect(previewDiversion(request, "TRANSIT")).resolves.toMatchObject({ candidate: { profile: { scope: "TRANSIT" } } })
    await createDiversion(request, "TRANSIT")
    expect(controller.calls("POST", "/v1/vpn/diversions/preview")).toHaveLength(2)
    expect(JSON.parse(controller.calls("POST", "/v1/vpn/diversions")[0].body ?? "{}")).toEqual({ scope: "TRANSIT", diversion: request })
    expect(controller.calls("POST", "/v1/diversions/preview")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
  })

  it("refuses an older controller without global fallback", async () => {
    controller.route("POST", "/v1/vpn/diversions/preview", () => json({ error: "not found" }, 404))
    await expect(createDiversion(vpnRequest("ipv4"), "TRANSIT")).rejects.toThrow("404")
    expect(controller.calls("POST", "/v1/vpn/diversions")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/diversions/preview")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
  })

  it.each(["scope", "identity", "targets"])("refuses a missing or mismatched %s acknowledgement before creation", async field => {
    const preview = vpnResult("ipv4")

    if (field === "scope") preview.candidate.profile.scope = "OTHER"

    if (field === "identity") delete preview.candidate.rule.nlri.scope

    if (field === "targets") preview.candidate.rule.route_targets = []

    controller.route("POST", "/v1/vpn/diversions/preview", () => json(preview))
    await expect(createDiversion(vpnRequest("ipv4"), "TRANSIT")).rejects.toThrow("did not acknowledge")
    expect(controller.calls("POST", "/v1/vpn/diversions")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
  })

  it("requires a new confirmation when fresh scoped preview changes", async () => {
    const preview = vpnResult("ipv4")
    preview.confirmation = "new-scope-or-target"
    controller.route("POST", "/v1/vpn/diversions/preview", () => json(preview))
    await expect(createDiversion(vpnRequest("ipv4"), "TRANSIT")).rejects.toThrow("changed after confirmation")
    expect(controller.calls("POST", "/v1/vpn/diversions")).toHaveLength(0)
  })

  it("keeps the acknowledged scope through operator confirmation", async () => {
    await setup(false, "TRANSIT")
    const preview = vpnResult("ipv4")
    controller.route("POST", "/v1/vpn/diversions/preview", () => json(preview))
    controller.route("POST", "/v1/vpn/diversions", () => json({ ...preview.candidate, status: "active" }, 202))
    expect(screen.getByText("Requested routing scope: TRANSIT")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    const confirm = await screen.findByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })

    expect(screen.getByText("Confirmed routing scope: TRANSIT")).toBeInTheDocument()
    fireEvent.click(confirm)
    fireEvent.click(screen.getByRole("button", { name: "Create diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/vpn/diversions")).toHaveLength(1))
    expect(JSON.parse(controller.calls("POST", "/v1/vpn/diversions")[0].body ?? "{}").scope).toBe("TRANSIT")
    expect(controller.calls("POST", "/v1/diversions/preview")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
  })
})


describe("configured VRF redirect target", { timeout: 10_000 }, () => {
  it("shows the action RT separately from scope RTs in preview and withdrawal", async () => {
    const preview = vpnResult("ipv4")
    delete preview.candidate.rule.target
    preview.candidate.rule.redirect_route_target = "44407:888"
    const configured = profiles(true, true)
    configured.configuration[0] = { ...configured.configuration[0], scope: "TRANSIT", ipv4_target: null, redirect_route_target: "44407:888" }
    await render({ rows: [{ ...preview.candidate, status: "active" }], scrubbers: () => json(configured) })
    expect(screen.getByText("Redirect to VRF RT 44407:888")).toBeInTheDocument()
    expect(screen.getByText(/203.0.113.20\/32 → VRF RT 44407:888/)).toHaveTextContent("RT 44407:777")
    const dialog = await openWithdraw()
    expect(within(dialog).getByText("VRF RT 44407:888")).toBeInTheDocument()
  })

  it.each(["ipv4", "ipv6"] as const)("keeps the configured VRF action in fresh %s confirmation", async family => {
    const preview = vpnResult(family)
    delete preview.candidate.rule.target
    preview.candidate.rule.redirect_route_target = "44407:888"
    preview.confirmation = "VPN-scoped-match -> VRF RT 44407:888"
    const request = { ...vpnRequest(family), confirmation: preview.confirmation }
    controller.route("POST", "/v1/vpn/diversions/preview", () => json(preview))
    controller.route("POST", "/v1/vpn/diversions", () => json(preview.candidate))
    await expect(createDiversion(request, "TRANSIT")).resolves.toMatchObject({ rule: { redirect_route_target: "44407:888" } })
    const sent = JSON.parse(controller.calls("POST", "/v1/vpn/diversions")[0].body ?? "{}")
    expect(sent.diversion).not.toHaveProperty("target")
    expect(sent.diversion).not.toHaveProperty("redirect_route_target")
  })

  it.each(["missing", "mixed"])("refuses a %s action target in scoped read-back", async targetCase => {
    const preview = vpnResult("ipv4")

    if (targetCase === "missing") delete preview.candidate.rule.target
    else preview.candidate.rule.redirect_route_target = "44407:888"
    controller.route("POST", "/v1/vpn/diversions/preview", () => json(preview))
    await expect(createDiversion(vpnRequest("ipv4"), "TRANSIT")).rejects.toThrow("did not acknowledge")
    expect(controller.calls("POST", "/v1/vpn/diversions")).toHaveLength(0)
  })
})
