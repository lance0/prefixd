import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { fireEvent, screen, waitFor, within } from "@testing-library/react"
import { FlowSpecRuleDialog, validateRule, toRequest, type RuleForm } from "@/components/dashboard/flowspec-rule-dialog"
import { createSourceOnlyVpn, createVpnFlowSpec, parseFlowSpecAdmissionPreview, readAutomaticScope, type JsonValue, type VpnScopeSnapshot } from "@/lib/api"
import { formatFlowSpecRule } from "@/components/dashboard/flowspec-preview"
import { json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))
const scope: VpnScopeSnapshot = { name: "TRANSIT", identity: { family: "ipv4", rd: "44407:40" }, route_targets: ["44407:777"] }
const rule = { victim_ip: "203.0.113.10", protocol: "udp", action: "discard" as const, ttl_seconds: 30, reason: "pilot attack" }
const policy = { family: "ipv4" as const, rd: "44407:40", route_targets: ["44407:777"], allow_source_only: true, min_source_prefix_length: 24, max_source_only_ttl_seconds: 60, max_source_only_active: 10 }

function preview(vpnScope = scope, sourceOnly = false): JsonValue {
  const ipv6 = vpnScope.identity.family === "ipv6"

  const result = {
    outcome: "admissible", checked_at: "2026-11-08T12:00:00Z", mode: "enforced", speaker_state: "unobserved",
    candidate: {
      victim_ip: sourceOnly ? "any" : ipv6 ? "2001:db8::1" : rule.victim_ip,
      vpn_scope: { ...vpnScope, identity: { ...vpnScope.identity } },
      customer_id: sourceOnly ? null : "customer", service_id: null, pop: "test",
      scope: { dst_prefix: sourceOnly ? "" : ipv6 ? "2001:db8::1/128" : "203.0.113.10/32", src_prefix: ipv6 ? "2001:db8:bad::/64" : "198.51.100.0/24", protocol: 17, dst_ports: [], scope: { ...vpnScope.identity } },
      action: { action_type: "discard" }, ttl_seconds: 30, expires_at_cap: null,
    }, failed_check: null, reason: null,
  }

  if (sourceOnly) return { ...result, candidate: { ...result.candidate, destination: "any" } }

  return result
}

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} })

  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

describe("VPN admission boundary", () => {
  it("reports both configured automatic families without treating a scope map as global", () => {
    expect(readAutomaticScope({ bgp: { default_scope: { ipv4: "TRANSIT", ipv6: "TRANSIT6" } } })).toBe("IPv4: TRANSIT · IPv6: TRANSIT6")
    expect(readAutomaticScope({ bgp: { default_scope: "TRANSIT" } })).toBe("TRANSIT")
    expect(readAutomaticScope({ bgp: { default_scope: { ipv4: 13 } } })).toBeNull()
  })

  it.each(["ipv4", "ipv6"] as const)("keeps %s source-only identity distinct from explicit /0", family => {
    const selected = { ...scope, identity: { ...scope.identity, family } }
    const result = parseFlowSpecAdmissionPreview(preview(selected, true), 200)
    expect(result?.candidate).toMatchObject({ destination: "any", vpn_scope: selected, scope: { dst_prefix: "", scope: selected.identity } })
    const fields = { dst_prefix: "", vpn_scope: selected, src_prefix: family === "ipv6" ? "2001:db8:bad::/64" : "198.51.100.0/24", protocol: 17, dst_ports: [], action_type: "discard", rate_bps: null }
    expect(formatFlowSpecRule(fields)).toContain("match destination any")
    expect(formatFlowSpecRule(fields)).not.toEqual(formatFlowSpecRule({ ...fields, dst_prefix: family === "ipv6" ? "::/0" : "0.0.0.0/0" }))
  })

  it("refuses missing or mismatched scope identity and destination-any without VPN acknowledgement", () => {
    const value = preview()

    if (!(value instanceof Object) || Array.isArray(value)) throw new Error("fixture")
    const candidate = value.candidate

    if (!(candidate instanceof Object) || Array.isArray(candidate)) throw new Error("fixture")
    expect(parseFlowSpecAdmissionPreview({ ...value, candidate: { ...candidate, vpn_scope: null } }, 200)).toBeNull()
    expect(parseFlowSpecAdmissionPreview({ ...value, candidate: { ...candidate, destination: "any" } }, 200)).toBeNull()
  })

  it("never sends a global request when an older controller lacks scoped admission", async () => {
    controller.route("POST", "/v1/vpn/mitigations/preview", () => json({ error: "not found" }, 404))
    await expect(createVpnFlowSpec("TRANSIT", rule)).rejects.toThrow("no global request was sent")
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/vpn/mitigations")).toHaveLength(0)
  })

  it("requires a matching scope acknowledgement before creating", async () => {
    controller.route("POST", "/v1/vpn/mitigations/preview", () => json(preview({ ...scope, name: "OTHER" })))
    await expect(createVpnFlowSpec("TRANSIT", rule)).rejects.toThrow("did not acknowledge")
    expect(controller.calls("POST", "/v1/vpn/mitigations")).toHaveLength(0)
    controller.route("POST", "/v1/vpn/mitigations/preview", () => json(preview()))
    controller.route("POST", "/v1/vpn/mitigations", () => json({ mitigation_id: "vpn" }))
    await createVpnFlowSpec("TRANSIT", rule)
    expect(JSON.parse(controller.calls("POST", "/v1/vpn/mitigations")[0].body ?? "")).toEqual({ scope: "TRANSIT", rule })
  })

  it("requires explicit destination-any confirmation and preserves source-only shape", async () => {
    const request = { scope: "TRANSIT", src_prefix: "198.51.100.0/24", protocol: "udp", action: "discard" as const, ttl_seconds: 30, reason: "pilot attack" }
    await expect(createSourceOnlyVpn(request)).rejects.toThrow("Confirm")
    controller.route("POST", "/v1/vpn/source-rules/preview", () => json(preview(scope, true)))
    controller.route("POST", "/v1/vpn/source-rules", () => json({ mitigation_id: "source-only" }))
    await createSourceOnlyVpn({ ...request, confirm_destination_any: true })
    const body = JSON.parse(controller.calls("POST", "/v1/vpn/source-rules")[0].body ?? "")
    expect(body).toEqual({ ...request, confirm_destination_any: true })
    expect(body).not.toHaveProperty("victim_ip")
  })
})

describe("source-only operator form", { timeout: 10_000 }, () => {
  it("shows destination-any risk and requires confirmation before creation", async () => {
    controller.route("GET", "/v1/config/settings", () => json({ settings: { bgp: { default_scope: "TRANSIT", vpn_scopes: { TRANSIT: policy } }, guardrails: { allow_src_prefix_match: true } }, loaded_at: "2026-11-08T12:00:00Z" }))
    controller.route("POST", "/v1/vpn/source-rules/preview", () => json(preview(scope, true)))
    controller.route("POST", "/v1/vpn/source-rules", () => json({ mitigation_id: "source-only" }))
    const { router } = renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    await settle()
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Routing scope" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "TRANSIT (VPNv4)" }))
    fireEvent.click(screen.getByRole("checkbox", { name: /Source-only rule/ }))
    expect(screen.getByText(/including safelisted destinations/)).toBeInTheDocument()
    expect(screen.queryByLabelText("Destination IP or CIDR")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Create rule" })).toBeDisabled()
    fireEvent.change(screen.getByLabelText("Source prefix (required)"), { target: { value: "198.51.100.0/24" } })
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "pilot attack" } })
    fireEvent.click(screen.getByRole("checkbox", { name: /I confirm/ }))
    fireEvent.click(screen.getByRole("button", { name: "Create rule" }))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/mitigations/source-only"))
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
  })

  it("hides source-only creation from non-admin operators", async () => {
    controller.route("GET", "/v1/config/settings", () => json({ settings: { bgp: { default_scope: "TRANSIT", vpn_scopes: { TRANSIT: policy } }, guardrails: { allow_src_prefix_match: true } }, loaded_at: "2026-11-08T12:00:00Z" }))
    renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} canSourceOnly={false} />, { withoutAuth: true })
    await settle()
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Routing scope" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "TRANSIT (VPNv4)" }))
    expect(screen.queryByRole("checkbox", { name: /Source-only rule/ })).not.toBeInTheDocument()
    expect(screen.getByText("Source-only rules require an administrator.")).toBeInTheDocument()
  })

  it("checks family, source floor and short TTL without inventing a destination", () => {
    const form: RuleForm = { routingScope: "TRANSIT", sourceOnly: true, victimIp: "", srcPrefix: "198.51.100.0/24", protocol: "udp", action: "discard", rateBps: "", dstPorts: "", srcPorts: "", nonFirstFragments: false, lengthMin: "", lengthMax: "", ttl: "30", reason: "pilot attack" }
    expect(validateRule(form, { maxPorts: 5, allowSrcPrefixMatch: true, vpnScope: policy })).toEqual({})
    expect(validateRule({ ...form, srcPrefix: "198.51.0.0/16", ttl: "300" }, { maxPorts: 5, vpnScope: policy })).toMatchObject({ srcPrefix: expect.any(String), ttl: expect.any(String) })
    const ipv6 = { ...policy, family: "ipv6" as const, min_source_prefix_length: 64 }
    expect(validateRule({ ...form, srcPrefix: "2001:db8:bad::/64" }, { maxPorts: 5, allowSrcPrefixMatch: true, vpnScope: ipv6 })).toEqual({})
    expect(validateRule(form, { maxPorts: 5, vpnScope: ipv6 })).toHaveProperty("srcPrefix")
  })
})


describe("VPN marking", () => {
  function markedPreview(dscp: number): JsonValue {
    const value = preview()

    if (!(value instanceof Object) || Array.isArray(value)) throw new Error("fixture")
    const candidate = value.candidate

    if (!(candidate instanceof Object) || Array.isArray(candidate)) throw new Error("fixture")

    return { ...value, candidate: { ...candidate, action: { action_type: "mark", dscp } } }
  }

  it.each([0, 63])("preserves exact DSCP %i in validation, request and preview", dscp => {
    const form: RuleForm = { routingScope: "TRANSIT", victimIp: "203.0.113.10", srcPrefix: "", protocol: "udp", action: "mark", dscp: String(dscp), rateBps: "", dstPorts: "", srcPorts: "", nonFirstFragments: false, lengthMin: "", lengthMax: "", ttl: "30", reason: "pilot mark" }
    expect(validateRule(form, { maxPorts: 5, vpnScope: policy })).toEqual({})
    expect(toRequest(form)).toMatchObject({ action: "mark", dscp })
    expect(toRequest(form)).not.toHaveProperty("rate_bps")
    expect(parseFlowSpecAdmissionPreview(markedPreview(dscp), 200)?.candidate?.action).toMatchObject({ action_type: "mark", dscp })
    expect(formatFlowSpecRule({ dst_prefix: "203.0.113.10/32", protocol: 17, dst_ports: [], action_type: "mark", dscp, rate_bps: null, vpn_scope: scope })).toContain(`then mark DSCP ${dscp}`)
    expect(validateRule({ ...form, routingScope: "global" }, { maxPorts: 5 })).toHaveProperty("action")
    expect(validateRule({ ...form, sourceOnly: true }, { maxPorts: 5, vpnScope: policy })).toHaveProperty("action")
    expect(validateRule({ ...form, dscp: "64" }, { maxPorts: 5, vpnScope: policy })).toHaveProperty("dscp")
  })

  it("renders the exact acknowledged DSCP in controller admission", { timeout: 10_000 }, async () => {
    controller.route("GET", "/v1/config/settings", () => json({ settings: { bgp: { vpn_scopes: { TRANSIT: policy } }, guardrails: { allow_src_prefix_match: true } }, loaded_at: "2026-11-08T12:00:00Z" }))
    controller.route("POST", "/v1/vpn/mitigations/preview", () => json(markedPreview(0)))
    renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    await settle()
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Routing scope" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "TRANSIT (VPNv4)" }))
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Action" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "mark DSCP" }))
    fireEvent.change(screen.getByLabelText("Destination IP or CIDR"), { target: { value: "203.0.113.10" } })
    fireEvent.change(screen.getByLabelText("DSCP (0–63)"), { target: { value: "0" } })
    fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "pilot mark" } })
    fireEvent.click(screen.getByRole("button", { name: "Check admission" }))
    const region = screen.getByRole("region", { name: "Controller admission" })
    await waitFor(() => expect(within(region).getByText(/then mark DSCP 0/)).toBeInTheDocument())
    expect(within(region).queryByText(/mark DSCP unavailable/)).not.toBeInTheDocument()
  })

  it("refuses a malformed or mismatched marking acknowledgement without sending creation", async () => {
    expect(parseFlowSpecAdmissionPreview(markedPreview(64), 200)).toBeNull()
    controller.route("POST", "/v1/vpn/mitigations/preview", () => json(markedPreview(1)))
    await expect(createVpnFlowSpec("TRANSIT", { ...rule, action: "mark", dscp: 0 })).rejects.toThrow("did not acknowledge")
    expect(controller.calls("POST", "/v1/vpn/mitigations")).toHaveLength(0)
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
    controller.route("POST", "/v1/vpn/mitigations/preview", () => json(markedPreview(0)))
    controller.route("POST", "/v1/vpn/mitigations", () => json({ mitigation_id: "mark" }))
    await createVpnFlowSpec("TRANSIT", { ...rule, action: "mark", dscp: 0 })
    expect(JSON.parse(controller.calls("POST", "/v1/vpn/mitigations")[0].body ?? "").rule).toMatchObject({ action: "mark", dscp: 0 })
  })
})
