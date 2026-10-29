import { describe, expect, it } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
import type { AuditEntry, Event, Mitigation } from "@/lib/api"
import { formatTimestamp } from "@/lib/format"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import { AuditLogContentLive } from "@/components/dashboard/audit-log-content-live"
import { deferred, failure, json, operatorResponse, renderApp, signIn, useFakeController, type ApiHandler } from "./support/fake-controller"

const controller = useFakeController()

function serveMitigations(answer: ApiHandler) {
  signIn(controller, "credentials", operatorResponse("operator"))
  controller.route("GET", "/v1/mitigations", answer)
}

const loaded = (mitigations: Mitigation[]) => ({ query }: { query: URLSearchParams }) => {
  const q = query.get("q")?.toLowerCase() ?? ""
  const matching = mitigations.filter((row) => [row.victim_ip, row.vector, row.customer_id ?? "", row.mitigation_id].some((value) => value.toLowerCase().includes(q)))
  const start = Number(query.get("cursor") ?? 0)
  const limit = Number(query.get("limit") ?? 100)
  const rows = matching.slice(start, start + limit)
  const hasMore = start + rows.length < matching.length

  return json({ mitigations: rows, count: rows.length, next_cursor: hasMore ? String(start + limit) : null, has_more: hasMore })
}

describe("list states", () => {
  it("shows a failed mitigations fetch as an error with retry, never as an empty table", async () => {
    serveMitigations(() => failure(502))
    renderApp(<MitigationsContentLive />)
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to load mitigations")
    expect(screen.getByRole("alert")).toHaveTextContent("Rules may still be active")
    expect(screen.queryByRole("table")).not.toBeInTheDocument()
    expect(screen.queryByText(/No mitigations/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Retry mitigations" }))
    await waitFor(() => expect(controller.calls("GET", "/v1/mitigations")).toHaveLength(2))
  })

  it("keeps the toolbar usable while showing skeleton rows for the first load", async () => {
    serveMitigations(() => deferred<Response>().promise)
    renderApp(<MitigationsContentLive />)
    await waitFor(() => expect(controller.calls("GET", "/v1/mitigations")).toHaveLength(1))
    expect(screen.getByRole("status", { name: "Loading mitigations" })).toBeInTheDocument()
    expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toBeEnabled()
  })

  it("separates an empty status selection from a search that matches nothing", async () => {
    serveMitigations(loaded([]))
    renderApp(<MitigationsContentLive />)
    expect(await screen.findByText("No mitigations with these statuses")).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText("Search IP, vector or ID…"), { target: { value: "198.51.100.9" } })
    expect(await screen.findByText("No matching mitigations")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Clear search and filters" }))
    expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toHaveValue("")
    expect(await screen.findByText("No mitigations with these statuses")).toBeInTheDocument()
  })

  it("exposes status filters as pressed toggles", async () => {
    serveMitigations(loaded([]))
    renderApp(<MitigationsContentLive />)
    const active = await screen.findByRole("button", { name: "active" })
    expect(active).toHaveAttribute("aria-pressed", "true")
    fireEvent.click(active)
    expect(active).toHaveAttribute("aria-pressed", "false")
    expect(screen.getByRole("button", { name: "expired" })).toHaveAttribute("aria-pressed", "false")
  })

  it("shows the expiry countdown with its absolute UTC deadline as visible text", async () => {
    const expiresAt = new Date(Date.now() + 26 * 60_000 + 30_000).toISOString()

    const now = new Date().toISOString()

    const mitigation: Mitigation = {
      mitigation_id: "m-1", scope_hash: "scope-1", status: "active", customer_id: null, service_id: null, pop: "iad1",
      victim_ip: "203.0.113.10", vector: "udp_flood", action_type: "police", rate_bps: 5_000_000,
      dst_prefix: "203.0.113.10/32", protocol: 17, dst_ports: [53], created_at: now, updated_at: now,
      expires_at: expiresAt, withdrawn_at: null, triggering_event_id: "e-1", last_event_id: "e-1",
      reason: "udp flood", acknowledged_at: null, acknowledged_by: null,
    }

    serveMitigations(loaded([mitigation]))
    renderApp(<MitigationsContentLive />)
    const deadline = await screen.findByText(formatTimestamp(expiresAt))
    expect(deadline).toBeVisible()
    expect(deadline.closest("td")).toHaveTextContent(/26m/)
    expect(deadline.closest("td")?.querySelector("time")).toHaveAttribute("dateTime", expiresAt)
  })

  it("tags only dry-run-origin rows as simulations", async () => {
    const now = new Date().toISOString()

    const base: Mitigation = {
      mitigation_id: "m-1", scope_hash: "scope-1", status: "active", customer_id: null, service_id: null, pop: "iad1",
      victim_ip: "203.0.113.1", vector: "udp_flood", action_type: "discard", rate_bps: null,
      dst_prefix: "203.0.113.1/32", protocol: 17, dst_ports: [53], created_at: now, updated_at: now,
      expires_at: new Date(Date.now() + 600_000).toISOString(), withdrawn_at: null, triggering_event_id: "e-1",
      last_event_id: "e-1", reason: "udp flood", acknowledged_at: null, acknowledged_by: null, origin_mode: "dry-run",
    }

    serveMitigations(loaded([
      base,
      { ...base, mitigation_id: "m-2", victim_ip: "203.0.113.2", origin_mode: "enforced" },
      { ...base, mitigation_id: "m-3", victim_ip: "203.0.113.3", origin_mode: null },
    ]))
    renderApp(<MitigationsContentLive />)
    await screen.findByRole("link", { name: "203.0.113.1" })
    const rowFor = (ip: string) => screen.getByRole("link", { name: ip }).closest("tr")

    expect(rowFor("203.0.113.1")).toHaveTextContent("Simulation")
    expect(rowFor("203.0.113.2")).not.toHaveTextContent("Simulation")
    expect(rowFor("203.0.113.3")).not.toHaveTextContent(/Simulation|Origin unknown/)
  })

  it("shows a failed events fetch as an error rather than an empty list", async () => {
    controller.route("GET", "/v1/events", () => failure(500))
    renderApp(<EventsContentLive />, { withoutAuth: true })
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to load events")
    expect(screen.queryByText("No events yet")).not.toBeInTheDocument()
  })

  it("reports events as loading until a successful empty response arrives", async () => {
    const pending = deferred<Response>()
    controller.route("GET", "/v1/events", () => pending.promise)
    renderApp(<EventsContentLive />, { withoutAuth: true })
    expect(await screen.findByRole("status", { name: "Loading events" })).toBeInTheDocument()
    expect(screen.queryByText("No events yet")).not.toBeInTheDocument()
    expect(screen.getByRole("textbox", { name: "Search events" })).toBeEnabled()
    pending.resolve(json({ events: [], count: 0, next_cursor: null, has_more: false }))
    expect(await screen.findByText("No events yet")).toBeInTheDocument()
  })
})

describe("list pagination", () => {
  const events: Event[] = Array.from({ length: 41 }, (_, index) => ({
    event_id: `event-${index + 1}`, external_event_id: null,
    source: index === 0 ? "suricata" : "fastnetmon",
    event_timestamp: new Date(Date.UTC(2026, 9, 22, 12) - index * 1000).toISOString(),
    ingested_at: new Date(Date.UTC(2026, 9, 22, 12) - index * 1000).toISOString(),
    victim_ip: `203.0.113.${index + 1}`, vector: index === 0 ? "syn_flood" : "udp_flood",
    protocol: 17, bps: 1000, pps: 10, top_dst_ports_json: "[]", confidence: 0.9,
  }))

  it("returns to the first matching page when mitigation search leaves multiple pages", async () => {
    const mitigations: Mitigation[] = events.map((event, index) => ({
      mitigation_id: `mitigation-${index + 1}`, scope_hash: `scope-${index + 1}`, status: "active",
      customer_id: null, service_id: null, pop: "iad1", victim_ip: index === 0 ? "198.51.100.1" : event.victim_ip,
      vector: "udp_flood", action_type: "discard", rate_bps: null, dst_prefix: `${index === 0 ? "198.51.100.1" : event.victim_ip}/32`,
      protocol: 17, dst_ports: [], created_at: event.event_timestamp, updated_at: event.event_timestamp,
      expires_at: "2026-10-24T12:00:00Z", withdrawn_at: null, triggering_event_id: event.event_id,
      last_event_id: event.event_id, reason: "flood", acknowledged_at: null, acknowledged_by: null,
    }))

    serveMitigations(loaded(mitigations))
    renderApp(<MitigationsContentLive />)
    await screen.findByText("Page 1")
    fireEvent.click(screen.getByRole("button", { name: "Next" }))
    await screen.findByText("Page 2")
    fireEvent.click(screen.getByRole("button", { name: "Next" }))
    await screen.findByText("Page 3")
    fireEvent.change(screen.getByRole("textbox", { name: "Search mitigations" }), { target: { value: "203.0.113." } })
    expect(await screen.findByText("Page 1")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "203.0.113.2" })).toBeInTheDocument()
  })

  it("returns to the first matching page when audit search leaves multiple pages", async () => {
    const entries: AuditEntry[] = events.map((event, index) => ({
      audit_id: `audit-${index + 1}`, timestamp: event.event_timestamp, schema_version: 1,
      actor_type: "operator", actor_id: "alice", action: "mitigation.withdrawn",
      target_type: "mitigation", target_id: `route-${index + 1}`, details: { group: index === 0 ? "outside" : "matching" },
    }))

    controller.route("GET", "/v1/audit", () => json({ entries, count: entries.length, next_cursor: null, has_more: false }))
    renderApp(<AuditLogContentLive />, { withoutAuth: true })
    await screen.findByText("Page 1 of 3")
    fireEvent.click(screen.getByRole("button", { name: "Next" }))
    fireEvent.click(screen.getByRole("button", { name: "Next" }))
    fireEvent.change(screen.getByRole("textbox", { name: "Search audit log" }), { target: { value: "matching" } })
    expect(await screen.findByText("Page 1 of 2")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "route-2" })).toHaveAttribute("href", "/mitigations/route-2")
  })

})
