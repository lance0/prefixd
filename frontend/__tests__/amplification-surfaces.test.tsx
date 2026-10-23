import { Suspense } from "react"
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import { EventDetailPanel } from "@/components/dashboard/event-detail-panel"
import { FlowSpecRuleDialog, toRequest, validateRule, type RuleForm } from "@/components/dashboard/flowspec-rule-dialog"
import { describeMatch, formatFlowSpecRule } from "@/components/dashboard/flowspec-preview"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { PlaybookEditor } from "@/components/dashboard/playbook-editor"
import { PlaybookYamlEditor } from "@/components/dashboard/playbook-yaml-editor"
import { createMitigation, updatePlaybooks, type ConfigPlaybook, type Event, type Mitigation } from "@/lib/api"
import { failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const createdAt = new Date(Date.now() - 60_000).toISOString()

function rule(id: string, fields: Partial<Mitigation>): Mitigation {
  return {
    mitigation_id: id, scope_hash: `scope-${id}`, status: "active",
    customer_id: null, service_id: null, pop: "test-pop", victim_ip: "203.0.113.10",
    vector: "udp_amplification", action_type: "discard", rate_bps: null,
    dst_prefix: "203.0.113.10/32", protocol: 17, dst_ports: [], src_ports: [], fragment: null, packet_length: null,
    created_at: createdAt, updated_at: createdAt, expires_at: new Date(Date.now() + 300_000).toISOString(),
    withdrawn_at: null, triggering_event_id: "event-amp", last_event_id: "event-amp", reason: "reflection",
    acknowledged_at: null, acknowledged_by: null, origin_mode: "enforced",
    ...fields,
  }
}

const sourcePortRule = rule("00000000-0000-4000-8000-000000000123", { src_prefix: "198.51.100.0/24", src_ports: [123, 389, 1900, 3702, 5353, 11211] })

const fragmentRule = rule("00000000-0000-4000-8000-000000000012", { fragment: "non_first", action_type: "police", rate_bps: 20_000_000 })

const lengthRule = rule("00000000-0000-4000-8000-000000000010", {
  src_ports: [11211], packet_length: { min: 1000, max: 65535 }, triggering_event_id: "event-other",
})

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal("ResizeObserver", class {
    observe = vi.fn()
    unobserve = vi.fn()
    disconnect = vi.fn()
  })
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: createdAt }))
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: [sourcePortRule, fragmentRule, lengthRule], count: 3, next_cursor: null, has_more: false }))
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

describe("amplification match display", () => {
  it("shows source ports, fragments and packet length in the mitigation list", async () => {
    signIn(controller, "credentials", operatorResponse("viewer"))
    await act(async () => {
      renderApp(<MitigationsContentLive />, { url: "/mitigations" })
    })
    await settle()
    const ports = await screen.findByText("UDP from 198.51.100.0/24 src 123, 389, 1900, 3702, 5353, 11211", { selector: "td" })
    // A long port list wraps inside its cell instead of widening the table.
    expect(ports).toHaveClass("whitespace-normal", "break-words")
    expect(screen.getByText("UDP non-first fragments", { selector: "td" })).toBeInTheDocument()
    expect(screen.getByText("UDP src 11211 length 1000–65535 B", { selector: "td" })).toBeInTheDocument()
  })

  it("shows every component on the detail page and links rules from the same event", async () => {
    signIn(controller, "credentials", operatorResponse("operator"))
    controller.route("GET", `/v1/mitigations/${sourcePortRule.mitigation_id}`, () => json(sourcePortRule))
    await act(async () => {
      renderApp(
        <Suspense fallback={<p>Loading...</p>}>
          <MitigationDetailPage params={Promise.resolve({ id: sourcePortRule.mitigation_id })} />
        </Suspense>,
        { url: `/mitigations/${sourcePortRule.mitigation_id}` },
      )
    })
    await screen.findByText("FlowSpec rule")
    expect(screen.getByText("Source prefix").nextSibling).toHaveTextContent("198.51.100.0/24")
    expect(screen.getByText("Source ports").nextSibling).toHaveTextContent("123, 389, 1900, 3702, 5353, 11211")
    expect(screen.getByText("Matches").parentElement).toHaveTextContent("Matches UDP from 198.51.100.0/24 src 123, 389, 1900, 3702, 5353, 11211 → 203.0.113.10")
    expect(screen.getByText(/source-port 123,389,1900,3702,5353,11211 then discard/)).toBeInTheDocument()

    const siblings = await screen.findByTestId("sibling-rules")
    expect(controller.calls("GET", "/v1/mitigations").some((call) => call.query.get("victim_ip") === "203.0.113.10")).toBe(true)
    // Only the rule with the same triggering event is a sibling.
    expect(within(siblings).getByRole("link", { name: "UDP non-first fragments" })).toHaveAttribute("href", `/mitigations/${fragmentRule.mitigation_id}`)
    expect(within(siblings).queryByText(/11211 length/)).not.toBeInTheDocument()
  })

  it("shows fragment and packet-length fields for those rules", async () => {
    signIn(controller, "credentials", operatorResponse("operator"))
    controller.route("GET", `/v1/mitigations/${lengthRule.mitigation_id}`, () => json(lengthRule))
    await act(async () => {
      renderApp(
        <Suspense fallback={<p>Loading...</p>}>
          <MitigationDetailPage params={Promise.resolve({ id: lengthRule.mitigation_id })} />
        </Suspense>,
        { url: `/mitigations/${lengthRule.mitigation_id}` },
      )
    })
    await screen.findByText("FlowSpec rule")
    expect(screen.getByText("Packet length").nextSibling).toHaveTextContent("1000–65535 bytes")
    expect(screen.getByText(/packet-length 1000-65535/)).toBeInTheDocument()
    expect(screen.queryByText("Fragments")).not.toBeInTheDocument()
  })

  it("shows the event's top source ports, and nothing when the detector sent none", () => {
    const event: Event = {
      event_id: "event-amp", external_event_id: null, source: "fastnetmon", event_timestamp: createdAt,
      ingested_at: createdAt, victim_ip: "203.0.113.10", vector: "udp_amplification", protocol: 17,
      bps: 1_000_000_000, pps: 100_000, top_dst_ports_json: "[]", top_src_ports_json: "[123,389]", confidence: 0.9,
    }

    const { rerender } = render(<EventDetailPanel event={event} onClose={vi.fn()} />)
    expect(screen.getByText("Top source ports").nextSibling).toHaveTextContent("123, 389")
    rerender(<EventDetailPanel event={{ ...event, top_src_ports_json: null }} onClose={vi.fn()} />)
    expect(screen.queryByText("Top source ports")).not.toBeInTheDocument()
  })
})

const validForm: RuleForm = {
  victimIp: "203.0.113.10", protocol: "udp", action: "discard", rateBps: "", dstPorts: "", srcPorts: "123, 389",
  srcPrefix: "",
  nonFirstFragments: false, lengthMin: "", lengthMax: "", ttl: "300", reason: "reflection",
}

describe("manual rule validation", () => {
  const guardrails = { maxPorts: 8, allowFragmentMatch: false, allowPacketLengthMatch: false }

  it("admits aligned destination CIDRs only within explicit prefix bounds", () => {
    const allowed = { maxPorts: 5, dstPrefixMinlen: 22, dstPrefixMaxlen: 32, dstPrefixMinlenV6: 48, dstPrefixMaxlenV6: 128, allowSrcPrefixMatch: true }

    for (const [victimIp, srcPrefix] of [["203.0.112.0/22", "198.51.100.0/24"], ["2001:db8:1234::/48", "2001:db8:ffff::/64"]]) {
      const form = { ...validForm, victimIp, srcPrefix, dstPorts: "443" }
      expect(validateRule(form, allowed)).toEqual({})
      expect(toRequest(form)).toMatchObject({ victim_ip: victimIp, src_prefix: srcPrefix, dst_ports: [443], src_ports: [123, 389] })
    }

    expect(validateRule({ ...validForm, victimIp: "203.0.112.0/22" }, { maxPorts: 5, dstPrefixMinlen: 32 }).victimIp).toContain("dst_prefix_minlen=32")
    expect(validateRule({ ...validForm, victimIp: "2001:db8:1234::/48" }, { maxPorts: 5, dstPrefixMinlenV6: 128 }).victimIp).toContain("dst_prefix_minlen_v6=128")
    expect(validateRule({ ...validForm, victimIp: "203.0.113.1/22" }, allowed).victimIp).toContain("203.0.112.0/22")
    expect(validateRule({ ...validForm, victimIp: "2001:db8:1234::1/48" }, allowed).victimIp).toContain("2001:db8:1234::/48")
  })

  it("keeps source CIDR independent of the UDP-only components and preserves it in requests and displays", () => {
    for (const [victimIp, srcPrefix] of [["203.0.113.10", "198.51.100.9/24"], ["2001:db8::1", "2001:db8:1::/64"]]) {
      const form = { ...validForm, victimIp, srcPrefix, protocol: "tcp", srcPorts: "" }
      expect(validateRule(form, { maxPorts: 5, allowSrcPrefixMatch: true })).toEqual({})
      expect(toRequest(form).src_prefix).toBe(srcPrefix)
      expect(validateRule(form, { maxPorts: 5, allowSrcPrefixMatch: false }).srcPrefix).toContain("allow_src_prefix_match=false")
      const fields = { dst_prefix: `${victimIp}/${victimIp.includes(":") ? 128 : 32}`, src_prefix: srcPrefix, protocol: 6, dst_ports: [], action_type: "discard", rate_bps: null }
      expect(describeMatch(fields)).toBe(`TCP from ${srcPrefix}`)
      expect(formatFlowSpecRule(fields)).toContain(`source ${srcPrefix} protocol tcp`)
    }

    expect(toRequest({ ...validForm, srcPrefix: "  " })).not.toHaveProperty("src_prefix")
  })

  it.each(["198.51.100.1", "198.51.100.1/33", "2001:db8::/64", "bad/24", "198.51.100.0/24/0", "1:2:3/64"])("refuses malformed or foreign-family source %s", (srcPrefix) => {
    expect(validateRule({ ...validForm, srcPrefix }, { maxPorts: 5 }).srcPrefix).toBeTruthy()
  })

  it.each<[string, Partial<RuleForm>, keyof RuleForm, string]>([
    ["source ports need UDP", { protocol: "tcp" }, "protocol", "require protocol UDP"],
    ["ports and fragment never share a rule", { nonFirstFragments: true }, "nonFirstFragments", "cannot share a rule"],
    ["fragments need the opt-in", { srcPorts: "", nonFirstFragments: true }, "nonFirstFragments", "guardrails.allow_fragment_match=false"],
    ["length needs source ports", { srcPorts: "", lengthMin: "1000", lengthMax: "65535" }, "lengthMin", "requires source ports"],
    ["length min must exceed the IPv4 header floor", { lengthMin: "28", lengthMax: "65535" }, "lengthMin", "min above 28"],
    ["length min must exceed the IPv6 header floor", { victimIp: "2001:db8::10", lengthMin: "48", lengthMax: "65535" }, "lengthMin", "min above 48"],
    ["length needs the opt-in", { lengthMin: "1000", lengthMax: "65535" }, "lengthMin", "guardrails.allow_packet_length_match=false"],
    ["source ports are capped by max_ports", { srcPorts: "1,2,3,4,5,6,7,8,9" }, "srcPorts", "guardrails.max_ports=8"],
    ["ports are u16", { srcPorts: "65536" }, "srcPorts", "0-65535"],
    ["ICMP must match the address family", { victimIp: "2001:db8::10", protocol: "icmp", srcPorts: "" }, "protocol", "address family"],
  ])("%s", (_label, change, field, message) => {
    expect(validateRule({ ...validForm, ...change }, guardrails)[field]).toContain(message)
  })

  it("accepts each component once its guardrail allows it", () => {
    const allowed = { maxPorts: 8, allowFragmentMatch: true, allowPacketLengthMatch: true }
    expect(validateRule(validForm, allowed)).toEqual({})
    expect(validateRule({ ...validForm, srcPorts: "", nonFirstFragments: true }, allowed)).toEqual({})
    expect(validateRule({ ...validForm, srcPorts: "11211", lengthMin: "1000", lengthMax: "65535" }, allowed)).toEqual({})
    // Duplicates count once, as the controller canonicalises them.
    expect(validateRule({ ...validForm, srcPorts: "1,2,3,4,5,6,7,8,8" }, allowed)).toEqual({})
    // Without loaded settings the opt-ins are left to the controller.
    expect(validateRule({ ...validForm, srcPorts: "", nonFirstFragments: true }, { maxPorts: 8 })).toEqual({})
  })
})

describe("manual rule dialog", () => {
  function fill(label: RegExp, value: string) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } })
  }

  it("completes from the keyboard and posts the source ports", async () => {
    controller.route("GET", "/v1/health/detail", () => json({ gobgp: { status: "connected" }, speaker: { capabilities: { flowspec_match: { source_prefix: true } } } }))
    controller.route("POST", "/v1/mitigations", () => json(sourcePortRule, 201))
    signIn(controller, "credentials", operatorResponse("operator"))
    let router: ReturnType<typeof renderApp>["router"] | undefined
    await act(async () => {
      router = renderApp(<MitigationsContentLive />, { url: "/mitigations" }).router
    })
    const trigger = await screen.findByRole("button", { name: "Create FlowSpec rule" })
    act(() => trigger.focus())
    fireEvent.click(trigger)
    const dialog = await screen.findByRole("dialog", { name: "Create FlowSpec rule" })
    // Focus moves into the dialog, and every control is reachable in reading order.
    await waitFor(() => expect(within(dialog).getByLabelText(/^Destination IP or CIDR/)).toHaveFocus())
    const order = Array.from(dialog.querySelectorAll<HTMLElement>("input, button")).filter((element) => element.tabIndex >= 0)
    expect(order.map((element) => element.getAttribute("id") ?? element.textContent?.trim())).toEqual([
      "fs-ip", "fs-src-prefix", "fs-protocol", "fs-action", "fs-dst", "fs-src", "fs-fragment", "fs-length-min", "fs-length-max",
      "fs-ttl", "fs-reason", "Cancel", "Create rule", "Close",
    ])
    fill(/^Destination IP or CIDR/, "203.0.113.10")
    fill(/^Source prefix/, "198.51.100.0/24")
    fill(/^Source ports/, "389, 123")
    fill(/^Reason/, "NTP and CLDAP reflection")
    // Enter in a field submits the form.
    fireEvent.submit(within(dialog).getByLabelText(/^Reason/).closest("form")!)
    await waitFor(() => expect(router?.push).toHaveBeenCalledWith(`/mitigations/${sourcePortRule.mitigation_id}`))
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations")[0].body ?? "")).toEqual({
      victim_ip: "203.0.113.10", protocol: "udp", action: "discard", ttl_seconds: 300,
      reason: "NTP and CLDAP reflection", src_prefix: "198.51.100.0/24", src_ports: [389, 123],
    })
  })

  it.each([null, undefined])("applies effective host-only IPv6 bounds when loaded settings contain %s", async (bound) => {
    controller.route("GET", "/v1/config/settings", () => json({ settings: { guardrails: { dst_prefix_minlen: 32, dst_prefix_maxlen: 32, dst_prefix_minlen_v6: bound, dst_prefix_maxlen_v6: bound } }, loaded_at: createdAt }))
    renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    await settle()
    fill(/^Destination IP or CIDR/, "2001:db8:1234::/48")
    fill(/^Reason/, "subnet attack")
    fireEvent.click(screen.getByRole("button", { name: "Create rule" }))
    expect(await screen.findByText(/dst_prefix_minlen_v6=128/)).toBeInTheDocument()
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
  })

  it("previews a subnet's complete match, policing scope and expiry before posting", async () => {
    const subnetRule = rule("subnet", { victim_ip: "203.0.112.0/22", dst_prefix: "203.0.112.0/22", dst_ports: [443], action_type: "police", rate_bps: 8_000_000 })
    controller.route("GET", "/v1/config/settings", () => json({ settings: { guardrails: { dst_prefix_minlen: 22, dst_prefix_maxlen: 32 } }, loaded_at: createdAt }))
    controller.route("POST", "/v1/mitigations", () => json(subnetRule, 201))
    const { router } = renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    await settle()
    fill(/^Destination IP or CIDR/, "203.0.112.0/22")
    fill(/^Destination ports/, "443")
    fill(/^Reason/, "UDP port 443 subnet attack")
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Action" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "police" }))
    fill(/^Rate/, "8000000")
    const preview = screen.getByRole("region", { name: "Rule preview" })
    expect(preview).toHaveTextContent("match destination 203.0.112.0/22 protocol udp destination-port 443 then rate-limit 8.0 Mbps")
    expect(preview).toHaveTextContent("Requested lifetime: 300 seconds")
    expect(preview).toHaveTextContent("across the whole destination")
    fill(/^Destination ports/, "invalid")
    expect(preview).toHaveTextContent("Complete the match fields to preview the rule")
    expect(preview).not.toHaveTextContent("then rate-limit")
    fill(/^Destination ports/, "443")
    fireEvent.submit(screen.getByLabelText(/^Reason/).closest("form")!)
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/mitigations/subnet"))
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations")[0].body ?? "")).toMatchObject({ victim_ip: "203.0.112.0/22", protocol: "udp", dst_ports: [443], action: "police", rate_bps: 8_000_000, ttl_seconds: 300 })
  })

  it("keeps subnet list links and incident reports on the exact CIDR", async () => {
    const subnetRule = rule("cidr-rule", { victim_ip: "203.0.112.0/22", dst_prefix: "203.0.112.0/22", dst_ports: [443] })
    controller.route("GET", "/v1/mitigations", () => json({ mitigations: [subnetRule], count: 1, has_more: false, next_cursor: null }))
    signIn(controller, "credentials", operatorResponse("operator"))
    const list = renderApp(<MitigationsContentLive />, { url: "/mitigations" })
    expect(await screen.findByRole("link", { name: "203.0.112.0/22" })).toHaveAttribute("href", "/mitigations/cidr-rule")
    list.unmount()
    controller.route("GET", "/v1/mitigations/cidr-rule", () => json(subnetRule))
    controller.route("GET", "/v1/reports/incident", () => new Response("# Exact CIDR incident", { headers: { "Content-Type": "text/markdown" } }))
    await act(async () => {
      renderApp(<Suspense fallback={<p>Loading...</p>}><MitigationDetailPage params={Promise.resolve({ id: "cidr-rule" })} /></Suspense>, { url: "/mitigations/cidr-rule" })
    })
    await screen.findByText("FlowSpec rule")
    expect(screen.getByText(/Individual addresses|individual addresses/)).toHaveTextContent("not aggregated")
    expect(document.querySelector('a[href*="ip-history?ip=203.0"]')).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Report" }))
    await screen.findByText("# Exact CIDR incident")
    expect(controller.calls("GET", "/v1/reports/incident")[0].query.get("mitigation_id")).toBe("cidr-rule")
    expect(controller.calls("GET", "/v1/reports/incident")[0].query.has("ip")).toBe(false)
  })

  it.each([undefined, false, "error"])("never posts a source selector when controller support is %s", async (support) => {
    controller.route("GET", "/v1/health/detail", () => support === "error" ? failure(503, "unavailable") : json({ gobgp: { status: "connected" }, speaker: { capabilities: { flowspec_match: { source_prefix: support } } } }))
    const request = toRequest({ ...validForm, srcPrefix: "198.51.100.0/24" })
    await expect(createMitigation(request)).rejects.toThrow(support === "error" ? /unavailable/ : /does not support/)
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
  })

  it("names the guardrail from settings and sends nothing until it is fixed", async () => {
    controller.route("GET", "/v1/config/settings", () => json({ settings: { guardrails: { max_ports: 8, allow_fragment_match: false, allow_packet_length_match: true } }, loaded_at: createdAt }))
    renderApp(<FlowSpecRuleDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    await settle()
    fill(/^Destination IP or CIDR/, "203.0.113.10")
    fill(/^Reason/, "fragment tail")
    fireEvent.click(screen.getByRole("checkbox", { name: "Match non-first fragments only" }))
    fireEvent.click(screen.getByRole("button", { name: "Create rule" }))
    expect(await screen.findByText(/guardrails\.allow_fragment_match=false/)).toBeInTheDocument()
    expect(screen.getByRole("checkbox", { name: "Match non-first fragments only" })).toHaveAccessibleDescription(/allow_fragment_match/)
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
  })

  it("shows the controller's guardrail refusal verbatim and stays open", async () => {
    controller.route("POST", "/v1/mitigations", () => json({ error: "guardrail violation: packet length matching not allowed (guardrails.allow_packet_length_match=false)" }, 422))
    const close = vi.fn()
    renderApp(<FlowSpecRuleDialog open onOpenChange={close} />, { withoutAuth: true })
    fill(/^Destination IP or CIDR/, "203.0.113.10")
    fill(/^Source ports/, "11211")
    fill(/Minimum packet length/, "1000")
    fill(/Maximum packet length/, "65535")
    fill(/^Reason/, "memcached")
    fireEvent.click(screen.getByRole("button", { name: "Create rule" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("API error 422")
    expect(screen.getByRole("alert")).toHaveTextContent("guardrails.allow_packet_length_match=false")
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations")[0].body ?? "")).toEqual(expect.objectContaining({
      src_ports: [11211], packet_length: { min: 1000, max: 65535 },
    }))
    expect(close).not.toHaveBeenCalled()
  })
})

// Shaped like GET /v1/config/playbooks: a `rules` step has no action, unset options are null,
// and one step carries a key this dashboard does not know.
const ampStep = {
  rate_bps: null, ttl_seconds: 300, require_confidence_at_least: null, require_persistence_seconds: null,
  rules: [
    { match: { src_ports: "from_event" as const }, action: "discard" as const },
    { match: { fragment: "non_first" as const }, action: "police" as const, rate_bps: 20_000_000 },
    { match: { src_ports: [11211], packet_length: { min: 1000, max: 65535 } }, action: "discard" as const },
  ],
  future_key: { kept: true },
}

const loaded: ConfigPlaybook[] = [
  { name: "amp_reflection", match: { vector: "udp_amplification", require_top_ports: false }, correlation: null, steps: [ampStep] },
  {
    name: "volumetric_blackhole", match: { vector: "udp_flood", require_top_ports: false }, correlation: null,
    steps: [{ action: "blackhole", rate_bps: null, ttl_seconds: 600, require_confidence_at_least: null, require_persistence_seconds: null }],
  },
]

function sentPlaybooks() {
  const puts = controller.calls("PUT", "/v1/config/playbooks")
  expect(puts).toHaveLength(1)

  return JSON.parse(puts[0].body ?? "").playbooks
}

/** The YAML editor's textarea, checked rather than asserted. */
function yamlText(): string {
  const textbox = screen.getByRole("textbox", { name: "Playbooks YAML" })

  if (!(textbox instanceof HTMLTextAreaElement)) throw new Error("expected the YAML textarea")

  return textbox.value
}

const savePlaybooks = async (playbooks: ConfigPlaybook[]) => { await updatePlaybooks(playbooks) }

describe("playbook editors with rules and blackhole steps", () => {
  beforeEach(() => {
    controller.route("PUT", "/v1/config/playbooks", (request) => json({ ...JSON.parse(request.body ?? ""), total_playbooks: 2, loaded_at: createdAt }))
  })

  it("form: loads, edits the step TTL, and sends every rule field and unknown key", async () => {
    renderApp(<PlaybookEditor playbooks={loaded} onSave={savePlaybooks} saving={false} />, { withoutAuth: true })
    expect(screen.getByText("UDP src from event → discard")).toBeInTheDocument()
    expect(screen.getByText("UDP non-first fragments → police 20 Mbps")).toBeInTheDocument()
    expect(screen.getByText("UDP src 11211 length 1000–65535 B → discard")).toBeInTheDocument()
    expect(screen.getByText("blackhole")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: /Save all/ })).toBeDisabled()

    fireEvent.click(screen.getByRole("button", { name: "Edit playbook amp_reflection" }))
    expect(screen.getByText("Edit rules in the YAML view. This form keeps them unchanged.")).toBeInTheDocument()
    expect(screen.queryByRole("combobox", { name: "Step 1 action" })).not.toBeInTheDocument()
    fireEvent.change(screen.getByLabelText("Step 1 TTL (seconds)"), { target: { value: "240" } })
    fireEvent.click(screen.getByRole("button", { name: /Save all/ }))

    await waitFor(() => expect(controller.calls("PUT", "/v1/config/playbooks")).toHaveLength(1))
    expect(sentPlaybooks()).toEqual([
      { ...loaded[0], steps: [{ ...ampStep, ttl_seconds: 240 }] },
      loaded[1],
    ])
  })

  it("YAML: loads, edits, and sends every rule field and unknown key", async () => {
    renderApp(<PlaybookYamlEditor playbooks={loaded} onSave={savePlaybooks} saving={false} />, { withoutAuth: true })
    const text = yamlText()
    expect(text).toContain("src_ports: from_event")
    expect(text).toContain("action: blackhole")
    expect(text).toContain("future_key:")

    fireEvent.change(screen.getByRole("textbox", { name: "Playbooks YAML" }), { target: { value: text.replace("ttl_seconds: 300", "ttl_seconds: 240") } })
    fireEvent.click(screen.getByRole("button", { name: "Apply" }))

    await waitFor(() => expect(controller.calls("PUT", "/v1/config/playbooks")).toHaveLength(1))
    const withoutNulls = JSON.parse(JSON.stringify(loaded, (_key, value) => value ?? undefined))
    withoutNulls[0].steps[0].ttl_seconds = 240
    expect(sentPlaybooks()).toEqual(withoutNulls)
  })

  it.each(["form", "YAML"])("%s: shows the controller's validation errors verbatim", async (view) => {
    const refusal = "playbook[0] (\"amp_reflection\") step[0]: rule[1]: fragment matching not allowed (guardrails.allow_fragment_match=false)"
    controller.route("PUT", "/v1/config/playbooks", () => json({ errors: [refusal] }, 400))

    if (view === "form") {
      renderApp(<PlaybookEditor playbooks={loaded} onSave={savePlaybooks} saving={false} />, { withoutAuth: true })
      fireEvent.click(screen.getByRole("button", { name: "Remove playbook volumetric_blackhole" }))
      fireEvent.click(screen.getByRole("button", { name: /Save all/ }))
    } else {
      renderApp(<PlaybookYamlEditor playbooks={loaded} onSave={savePlaybooks} saving={false} />, { withoutAuth: true })
      fireEvent.change(screen.getByRole("textbox", { name: "Playbooks YAML" }), { target: { value: `${yamlText()}\n` } })
      fireEvent.click(screen.getByRole("button", { name: "Apply" }))
    }

    const alert = await screen.findByRole("alert")
    expect(alert).toHaveTextContent("The controller refused the save:")
    expect(within(alert).getByText(refusal)).toBeInTheDocument()
  })

  it("flags a blackhole step in an amplification playbook before saving", () => {
    renderApp(<PlaybookYamlEditor playbooks={loaded} onSave={savePlaybooks} saving={false} />, { withoutAuth: true })
    const draft = "playbooks:\n  - name: amp\n    match:\n      vector: udp_amplification\n    steps:\n      - action: blackhole\n        ttl_seconds: 600\n"
    fireEvent.change(screen.getByRole("textbox", { name: "Playbooks YAML" }), { target: { value: draft } })
    expect(screen.getByText(/a blackhole step is not valid in udp_amplification playbooks/)).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Apply" })).toBeDisabled()
  })
})

describe("controller failure text", () => {
  it("falls back to the raw message when the body is not JSON", async () => {
    controller.route("PUT", "/v1/config/playbooks", () => failure(502, "bad gateway"))
    renderApp(<PlaybookEditor playbooks={loaded} onSave={savePlaybooks} saving={false} />, { withoutAuth: true })
    fireEvent.click(screen.getByRole("button", { name: "Remove playbook volumetric_blackhole" }))
    fireEvent.click(screen.getByRole("button", { name: /Save all/ }))
    expect(await screen.findByRole("alert")).toHaveTextContent("API error 502: bad gateway")
  })
})
