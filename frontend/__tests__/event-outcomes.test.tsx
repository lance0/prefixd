import { fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { SWRConfig } from "swr"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import { EventOutcomePill, eventOutcomeTone } from "@/components/dashboard/status-pill"
import { EVENT_OUTCOMES, type Event } from "@/lib/api"
import { json, renderApp, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const base = {
  external_event_id: null, source: "fastnetmon", vector: "udp_flood",
  event_timestamp: "2026-11-14T00:00:00Z", ingested_at: "2026-11-14T00:00:00Z",
  protocol: 17, bps: 1000, pps: 10, top_dst_ports_json: "[]", confidence: 0.9,
}

const rows: Event[] = [
  { ...base, event_id: "00000000-0000-0000-0000-000000000003", victim_ip: "203.0.113.10", outcome: "mitigated", outcome_reason: null, outcome_mitigation_ids: ["11111111-1111-1111-1111-111111111111"] },
  { ...base, event_id: "00000000-0000-0000-0000-000000000002", victim_ip: "203.0.113.11", outcome: "safelisted", outcome_reason: "guardrail violation: IP 203.0.113.11 is safelisted", outcome_mitigation_ids: [] },
  // From before outcomes were recorded, or an older controller.
  { ...base, event_id: "00000000-0000-0000-0000-000000000001", victim_ip: "203.0.113.12" },
]

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

beforeEach(() => {
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
  controller.route("GET", "/v1/events", ({ query }) => {
    const outcomes = query.get("outcome")?.split(",")
    const page = rows.filter((row) => !outcomes || outcomes.includes(row.outcome ?? "not_recorded"))

    return json({ events: page, count: page.length, has_more: false, next_cursor: null })
  })
})

function renderEvents() {
  return renderApp(<SWRConfig value={{ dedupingInterval: 0 }}><EventsContentLive /></SWRConfig>, { withoutAuth: true })
}

describe("event outcomes", () => {
  it("shows why each event did or did not mitigate", async () => {
    renderEvents()
    await screen.findByRole("link", { name: "203.0.113.10" })
    expect(screen.getByRole("columnheader", { name: "Outcome" })).toBeInTheDocument()
    const [, mitigated, refused, legacy] = screen.getAllByRole("row")
    expect(within(mitigated).getByText("Mitigated")).toHaveAttribute("data-tone", "success")
    expect(within(refused).getByText("Safelisted")).toHaveAttribute("data-tone", "warning")
    expect(within(refused).getByText("guardrail violation: IP 203.0.113.11 is safelisted")).toBeInTheDocument()
    expect(within(legacy).getByText("Outcome not recorded")).toHaveAttribute("data-tone", "neutral")

    fireEvent.click(within(mitigated).getByRole("button", { name: "View event details" }))
    const dialog = await screen.findByRole("dialog", { name: "Event details" })
    expect(within(dialog).getByText("Mitigated")).toBeInTheDocument()
    expect(within(dialog).getByRole("link", { name: "11111111-1111-1111-1111-111111111111" })).toHaveAttribute("href", "/mitigations/11111111-1111-1111-1111-111111111111")
  })

  it("filters by outcome on the server and resets to the first page", async () => {
    renderEvents()
    await screen.findByRole("link", { name: "203.0.113.10" })
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Outcome" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "Any refusal or failure" }))
    await waitFor(() => expect(screen.queryByRole("link", { name: "203.0.113.10" })).not.toBeInTheDocument())
    expect(screen.getByRole("link", { name: "203.0.113.11" })).toBeInTheDocument()
    const query = controller.calls("GET", "/v1/events").at(-1)!.query
    expect(query.get("outcome")).toBe("guardrail_rejected,safelisted,conflict,failed")
    expect(query.has("cursor")).toBe(false)

    fireEvent.keyDown(screen.getByRole("combobox", { name: "Outcome" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "Outcome not recorded" }))
    await screen.findByRole("link", { name: "203.0.113.12" })
    expect(controller.calls("GET", "/v1/events").at(-1)!.query.get("outcome")).toBe("not_recorded")

    fireEvent.keyDown(screen.getByRole("combobox", { name: "Outcome" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "All outcomes" }))
    // The unfiltered page is back; SWR may serve it from cache without a new request.
    await screen.findByRole("link", { name: "203.0.113.10" })
    expect(screen.getByRole("link", { name: "203.0.113.12" })).toBeInTheDocument()
  })

  it("maps every outcome to a labeled tone and unknown values to not recorded", () => {
    expect(EVENT_OUTCOMES.map(eventOutcomeTone)).toEqual([
      "success", "success", "info", "danger", "warning", "warning",
      "neutral", "info", "danger", "danger", "neutral", "neutral",
    ])
    render(<EventOutcomePill outcome="something_new" />)
    expect(screen.getByText("Outcome not recorded")).toHaveAttribute("data-tone", "neutral")
  })
})
