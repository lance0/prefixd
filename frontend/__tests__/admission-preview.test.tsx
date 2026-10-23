import { act, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { FlowSpecRuleDialog } from "@/components/dashboard/flowspec-rule-dialog"
import { parseFlowSpecAdmissionPreview, previewFlowSpecAdmission } from "@/lib/api"
import { json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const request = { victim_ip: "203.0.112.0/22", protocol: "udp", dst_ports: [443], action: "discard" as const, ttl_seconds: 300, reason: "attack across allocation" }

const result = {
  outcome: "admissible", checked_at: "2026-10-23T09:50:00Z", mode: "enforced", speaker_state: "unobserved",
  candidate: {
    victim_ip: "203.0.112.0/22", customer_id: "allocation", service_id: null, pop: "test-pop",
    scope: { dst_prefix: "203.0.112.0/22", protocol: 17, dst_ports: [443] },
    action: { action_type: "discard" }, ttl_seconds: 300, expires_at_cap: null,
  }, failed_check: null, reason: null,
}

beforeEach(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} })
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
})

function fill(label: RegExp, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } })
}

async function openForm() {
  controller.route("GET", "/v1/config/settings", () => json({ settings: { guardrails: { dst_prefix_minlen: 22, dst_prefix_maxlen: 32 } }, loaded_at: result.checked_at }))
  renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
  await settle()
  fill(/^Destination IP or CIDR/, request.victim_ip)
  fill(/^Destination ports/, "443")
  fill(/^Reason/, request.reason)
}

describe("admission response boundary", () => {
  it("accepts a complete canonical result and refuses contradictory HTTP outcomes", () => {
    expect(parseFlowSpecAdmissionPreview(result, 200)).toMatchObject({ outcome: "admissible", candidate: result.candidate })
    expect(parseFlowSpecAdmissionPreview(result, 503)).toBeNull()
    expect(parseFlowSpecAdmissionPreview({ ...result, outcome: "unavailable", failed_check: "safelist", reason: "Cannot read safelist" }, 200)).toBeNull()
  })

  it.each([
    { checked_at: "not-a-date" }, { checked_at: null }, { mode: "unknown" }, { speaker_state: "installed" },
    { candidate: null }, { candidate: { ...result.candidate, scope: {} } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, dst_ports: null } } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, dst_prefix: "203.0.113.10/22" } } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, src_prefix: "" } } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, src_prefix: "2001:db8::/32" } } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, packet_length: { min: 1400, max: 1000 } } } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, tcp_flags: "syn" } } },
    { candidate: { ...result.candidate, scope: { ...result.candidate.scope, fragment: "all" } } },
    { candidate: { ...result.candidate, action: { action_type: "redirect" } } },
    { candidate: { ...result.candidate, action: { action_type: "police", rate_bps: 0 } } },
    { candidate: { ...result.candidate, expires_at_cap: "invalid" } },
  ])("refuses malformed, widened or unknown response fields %j", (change) => {
    expect(parseFlowSpecAdmissionPreview({ ...result, ...change }, 200)).toBeNull()
  })

  it("returns structured refusals and unavailable checks but treats malformed results as unavailable", async () => {
    for (const [status, outcome] of [[422, "refused"], [503, "unavailable"]] as const) {
      controller.route("POST", "/v1/mitigations/preview", () => json({ ...result, outcome, failed_check: "safelist", reason: "Safelist check" }, status))
      await expect(previewFlowSpecAdmission(request)).resolves.toMatchObject({ outcome })
    }

    controller.route("POST", "/v1/mitigations/preview", () => json({ ...result, checked_at: "invalid" }))

    await expect(previewFlowSpecAdmission(request)).rejects.toThrow("Admission check unavailable")
  })
})

describe("optional controller admission check", () => {
  it("shows the exact server candidate and evidence limits without creating intent", async () => {
    controller.route("POST", "/v1/mitigations/preview", () => json(result))
    await openForm()
    fireEvent.click(screen.getByRole("button", { name: "Check admission" }))
    const region = screen.getByRole("region", { name: "Controller admission" })
    expect(await within(region).findByText("Controller checks passed")).toBeInTheDocument()
    expect(region).toHaveTextContent("match destination 203.0.112.0/22 protocol udp destination-port 443 then discard")
    expect(region).toHaveTextContent("Customer allocation · POP test-pop · 300s requested · enforced")
    expect(region).toHaveTextContent("no capacity is reserved")
    expect(region).toHaveTextContent("Creation rechecks")
    expect(region).toHaveTextContent("are unobserved")
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations/preview")[0].body ?? "")).toEqual(request)
    fill(/^Destination ports/, "53")
    expect(screen.queryByText("Controller checks passed")).not.toBeInTheDocument()
  })

  it("ignores an in-flight result after any form edit", async () => {
    let release: ((response: Response) => void) | undefined
    controller.route("POST", "/v1/mitigations/preview", () => new Promise<Response>(resolve => { release = resolve }))
    await openForm()
    fireEvent.click(screen.getByRole("button", { name: "Check admission" }))
    await waitFor(() => expect(release).toBeDefined())
    fill(/^Reason/, "new evidence")
    await act(async () => { release?.(json(result)) })
    expect(screen.queryByText("Controller checks passed")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Check admission" })).toBeEnabled()
  })

  it.each([[422, "refused", "Admission refused"], [503, "unavailable", "Checks unavailable"]] as const)("distinguishes %s %s", async (status, outcome, label) => {
    controller.route("POST", "/v1/mitigations/preview", () => json({ ...result, outcome, failed_check: "safelist", reason: "Protected address overlaps the destination" }, status))
    await openForm()
    fireEvent.click(screen.getByRole("button", { name: "Check admission" }))
    expect(await screen.findByText(label)).toBeInTheDocument()
    expect(screen.getByText("Protected address overlaps the destination")).toBeInTheDocument()
    expect(screen.queryByText("Controller checks passed")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Create rule" })).toBeEnabled()
  })

  it("keeps a malformed date or candidate from crashing or showing success", async () => {
    controller.route("POST", "/v1/mitigations/preview", () => json({ ...result, checked_at: "invalid", candidate: {} }))
    await openForm()
    fireEvent.click(screen.getByRole("button", { name: "Check admission" }))
    expect(await screen.findByText(/Admission check unavailable/)).toBeInTheDocument()
    expect(screen.queryByText("Controller checks passed")).not.toBeInTheDocument()
  })
})
