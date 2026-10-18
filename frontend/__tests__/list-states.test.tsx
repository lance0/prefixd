import { describe, expect, it } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
import type { Mitigation } from "@/lib/api"
import { formatUtc } from "@/lib/format"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import { deferred, failure, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

function serveMitigations(answer: () => Response | Promise<Response>) {
  signIn(controller, "credentials", operatorResponse("operator"))
  controller.route("GET", "/v1/mitigations", answer)
}

const loaded = (mitigations: Mitigation[]) => () => json({ mitigations, count: mitigations.length, next_cursor: null, has_more: false })

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
    expect(screen.getByText("No matching mitigations")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Clear search and filters" }))
    expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toHaveValue("")
    expect(screen.getByText("No mitigations with these statuses")).toBeInTheDocument()
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
    const deadline = await screen.findByText(formatUtc(expiresAt))
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
})
