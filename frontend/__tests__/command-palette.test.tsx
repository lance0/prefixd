import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, screen, waitFor } from "@testing-library/react"
import { CommandPalette } from "@/components/dashboard/command-palette"
import type { Event, Mitigation } from "@/lib/api"
import { deferred, json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const mitigation: Mitigation = {
  mitigation_id: "4b8e0f62-1d3a-4c55-9a70-2f61c8d3e914", scope_hash: "scope-1", status: "active",
  customer_id: "cust-acme", service_id: null, pop: "iad1", victim_ip: "203.0.113.10",
  vector: "udp_flood", action_type: "discard", rate_bps: null,
  dst_prefix: "203.0.113.10/32", protocol: 17, dst_ports: [53],
  created_at: "2026-10-18T11:59:00Z", updated_at: "2026-10-18T11:59:00Z",
  expires_at: "2026-10-18T12:09:00Z", withdrawn_at: null,
  triggering_event_id: "event-1", last_event_id: "event-1", reason: "DNS flood detected",
  acknowledged_at: null, acknowledged_by: null,
}

const event: Event = {
  event_id: "7c1e2a90-35d4-4f08-b6e2-90a1d4c7f352", external_event_id: null, source: "fastnetmon",
  event_timestamp: "2026-10-18T12:00:00Z", ingested_at: "2026-10-18T12:00:01Z",
  victim_ip: "198.51.100.7", vector: "syn_flood", protocol: 6,
  bps: null, pps: null, top_dst_ports_json: "[443]", confidence: 0.8,
}

const scrollIntoView = Object.getOwnPropertyDescriptor(Element.prototype, "scrollIntoView")

beforeEach(() => {
  // cmdk measures its list and scrolls the selected item in a browser.
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} })
  Object.defineProperty(Element.prototype, "scrollIntoView", { configurable: true, value: vi.fn() })
})

afterEach(() => {
  cleanup()

  if (scrollIntoView) Object.defineProperty(Element.prototype, "scrollIntoView", scrollIntoView)
  else Reflect.deleteProperty(Element.prototype, "scrollIntoView")
})

describe("command palette search", () => {
  it.each([
    ["an event ID", event.event_id.slice(0, 13), "198.51.100.7", `/events?id=${event.event_id}`],
    ["a mitigation ID", mitigation.mitigation_id.slice(0, 13), "203.0.113.10", `/mitigations/${mitigation.mitigation_id}`],
    ["a customer", "cust-acme", "203.0.113.10", `/mitigations/${mitigation.mitigation_id}`],
  ])("keeps a result matched by %s that loads after typing, and opens it from the keyboard", async (_, query, ip, route) => {
    const mitigations = deferred<Response>()
    const events = deferred<Response>()
    controller.route("GET", "/v1/mitigations", () => mitigations.promise)
    controller.route("GET", "/v1/events", () => events.promise)
    const onOpenChange = vi.fn()
    const { router } = renderApp(<CommandPalette open onOpenChange={onOpenChange} />, { withoutAuth: true })

    const input = screen.getByPlaceholderText("Search mitigations, events, pages…")
    fireEvent.change(input, { target: { value: query } })
    await waitFor(() => expect(controller.calls("GET", "/v1/events")).toHaveLength(1))
    expect(screen.queryByText(ip)).not.toBeInTheDocument()

    mitigations.resolve(json({ mitigations: [mitigation], count: 1, next_cursor: null, has_more: false }))
    events.resolve(json({ events: [event], count: 1, next_cursor: null, has_more: false }))
    await settle()

    const row = (await screen.findByText(ip)).closest("[cmdk-item]")
    expect(row).not.toBeNull()
    expect(screen.getAllByRole("option")).toEqual([row])

    fireEvent.keyDown(input, { key: "ArrowDown" })
    expect(row).toHaveAttribute("aria-selected", "true")
    fireEvent.keyDown(input, { key: "Enter" })
    expect(onOpenChange).toHaveBeenCalledWith(false)
    expect(router.push).toHaveBeenCalledWith(route)
  })
})
