import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { formatConfidence } from "@/lib/confidence"
import { ConfidenceBar } from "@/components/dashboard/confidence-bar"
import { EventDetailPanel } from "@/components/dashboard/event-detail-panel"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import { CommandPalette } from "@/components/dashboard/command-palette"
import IpHistoryPage from "@/app/(dashboard)/ip-history/page"
import { CacheTab } from "@/components/dashboard/correlation/cache-tab"
import type { Event } from "@/lib/api"
import { json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const event: Event = {
  event_id: "event-1", external_event_id: null, source: "fastnetmon",
  event_timestamp: "2026-10-18T12:00:00Z", ingested_at: "2026-10-18T12:00:01Z",
  victim_ip: "203.0.113.10", vector: "udp_flood", protocol: 17,
  bps: null, pps: null, top_dst_ports_json: "[53]", confidence: 0.95,
}

// JSON cannot carry NaN, so the API's invalid confidence is an out-of-range fraction.
const events = [0.95, 0, null, 1.5].map((confidence, index) => ({
  ...event, confidence, event_id: `event-${index}`, victim_ip: `203.0.113.${index + 10}`,
}))

afterEach(() => { cleanup(); vi.unstubAllGlobals() })

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({
    media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn(),
  })))
  controller.route("GET", "/v1/events", () => json({ events, count: events.length, next_cursor: null, has_more: false }))
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: [], count: 0, next_cursor: null, has_more: false }))
})

describe("confidence fraction formatting", () => {
  it.each([
    [undefined, "Unavailable"], [null, "Unavailable"],
    [NaN, "Invalid"], [Infinity, "Invalid"], [-Infinity, "Invalid"],
    [-0.1, "Invalid"], [1.1, "Invalid"],
    [0, "0%"], [0.499, "50%"], [0.5, "50%"], [0.799, "80%"],
    [0.8, "80%"], [0.95, "95%"], [1, "100%"],
  ])("formats %s as %s without inventing evidence", (value, label) => {
    expect(formatConfidence(value)).toBe(label)
  })

  it.each([0, 0.499, 0.5, 0.799, 0.8, 0.95, 1])("uses fraction %s for the bar and its accessible value", (value) => {
    render(<ConfidenceBar value={value} />)
    const bar = screen.getByRole("meter", { name: "Confidence" })
    expect(bar).toHaveAttribute("aria-valuenow", String(value * 100))
    expect(bar).toHaveAttribute("aria-valuetext", formatConfidence(value))
    expect(bar.firstElementChild).toHaveStyle({ width: `${value * 100}%` })
    expect(bar.firstElementChild).toHaveClass(value >= 0.8 ? "bg-primary" : "bg-muted-foreground")
    expect(screen.getByText(formatConfidence(value))).toBeInTheDocument()
  })

  it.each([undefined, null, NaN, Infinity, -0.1, 1.1])("does not draw a zero bar for unavailable or invalid %s", (value) => {
    render(<ConfidenceBar value={value} />)
    expect(screen.queryByRole("meter")).not.toBeInTheDocument()
    expect(screen.getByText(formatConfidence(value))).toBeInTheDocument()
  })
})

describe("confidence display callers", () => {
  it("shows API fractions, zero, missing and invalid confidence in event list rows", async () => {
    renderApp(<EventsContentLive />, { withoutAuth: true })
    await screen.findByRole("link", { name: "203.0.113.10" })

    for (const [index, label] of ["95%", "0%", "Unavailable", "Invalid"].entries()) {
      const row = screen.getByRole("link", { name: `203.0.113.${index + 10}` }).closest("tr")!
      expect(within(row).getByText(label)).toBeInTheDocument()
      expect(within(row).queryByText("0.95%")).not.toBeInTheDocument()
    }
  })

  it.each([
    [0, "0%", "Low"], [0.499, "50%", "Low"], [0.5, "50%", "Medium"],
    [0.799, "80%", "Medium"], [0.8, "80%", "High"], [0.95, "95%", "High"],
    [1, "100%", "High"], [null, "Unavailable", null], [NaN, "Invalid", null],
  ])("shows detail confidence %s with raw fraction classification", (confidence, label, level) => {
    render(<EventDetailPanel event={{ ...event, confidence }} onClose={vi.fn()} />)
    const confidenceCard = screen.getByText("Confidence").closest<HTMLElement>('[data-slot="card"]')!
    expect(within(confidenceCard).getByText(label)).toBeInTheDocument()
    expect(within(confidenceCard).queryByText("N/A")).not.toBeInTheDocument()
    expect(within(confidenceCard).queryByText("0.95%")).not.toBeInTheDocument()
    expect(screen.getByText(level ? new RegExp(`${level} reported confidence`) : /No valid confidence reported/)).toBeInTheDocument()
    expect(screen.getByText(/Confidence alone does not confirm mitigation or router installation/)).toBeInTheDocument()
    expect(screen.queryByText(/automatic mitigation applied/)).not.toBeInTheDocument()
  })

  it("preserves zero and missing confidence in command palette event results", async () => {
    // cmdk measures its list with ResizeObserver in a browser.
    const observer = class { observe() {} unobserve() {} disconnect() {} }
    const scrollIntoView = Object.getOwnPropertyDescriptor(Element.prototype, "scrollIntoView")
    Object.defineProperty(Element.prototype, "scrollIntoView", { configurable: true, value: vi.fn() })
    vi.stubGlobal("ResizeObserver", observer)

    try {
      renderApp(<CommandPalette open onOpenChange={vi.fn()} />, { withoutAuth: true })
      // Search once results have loaded, as an operator would.
      await waitFor(() => expect(controller.calls("GET", "/v1/events")).toHaveLength(1))
      await settle()
      fireEvent.change(screen.getByPlaceholderText("Search mitigations, events, pages…"), { target: { value: "203.0.113" } })

      for (const label of ["95%", "0%", "Unavailable", "Invalid"]) {
        expect(await screen.findByText(label)).toBeInTheDocument()
      }
    } finally {
      cleanup()
      vi.unstubAllGlobals()

      if (scrollIntoView) Object.defineProperty(Element.prototype, "scrollIntoView", scrollIntoView)
      else Reflect.deleteProperty(Element.prototype, "scrollIntoView")
    }
  })

  it("uses the same confidence states in IP history", async () => {
    controller.route("GET", "/v1/ip/203.0.113.10/history", () => json({ ip: "203.0.113.10", events, mitigations: [], customer: null, service: null }))
    renderApp(<IpHistoryPage />, { url: "/ip-history?ip=203.0.113.10", withoutAuth: true })

    for (const label of ["95%", "0%", "Unavailable", "Invalid"]) {
      expect(await screen.findByText(`Confidence: ${label}`)).toBeInTheDocument()
    }
  })

  it("uses percentages and explicit missing confidence in the corroborator cache", async () => {
    controller.route("GET", "/v1/signals/corroborator/cache", () => json({
      total: events.length, by_source: [],
      signals: events.map(e => ({
        signal_id: e.event_id, source: e.source, vector: e.vector, confidence: e.confidence,
        customer_id: null, service_id: null, pop: null, interface: null,
        ingested_at: e.ingested_at, expires_at: "2026-10-18T13:00:00Z",
      })),
    }))
    renderApp(<CacheTab />, { withoutAuth: true })

    for (const label of ["95%", "0%", "Unavailable", "Invalid"]) {
      expect(await screen.findByText(label)).toBeInTheDocument()
    }
  })
})
