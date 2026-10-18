import type { ReactNode } from "react"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"
import type { Mitigation } from "@/lib/api"
import { formatUtc } from "@/lib/format"

const mocks = vi.hoisted(() => ({ useMitigations: vi.fn(), useEvents: vi.fn(), mutate: vi.fn() }))

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn() }) }))

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: { children: ReactNode; href: string }) => <a href={href} {...props}>{children}</a>,
}))

vi.mock("@/hooks/use-api", () => ({ useMitigations: mocks.useMitigations, useEvents: mocks.useEvents }))

vi.mock("@/hooks/use-permissions", () => ({ usePermissions: () => ({ settled: true, canWithdraw: true }) }))

vi.mock("@/lib/api", () => ({ withdrawMitigation: vi.fn(), bulkWithdrawMitigations: vi.fn() }))

vi.mock("@/components/dashboard/mitigate-now-dialog", () => ({ MitigateNowDialog: () => null }))

import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { EventsContentLive } from "@/components/dashboard/events-content-live"

const loaded = (mitigations: Mitigation[]) => ({ data: { mitigations }, error: undefined, isLoading: false, mutate: mocks.mutate })

afterEach(cleanup)

describe("list states", () => {
  it("shows a failed mitigations fetch as an error with retry, never as an empty table", () => {
    mocks.useMitigations.mockReturnValue({ data: undefined, error: new Error("HTTP 502"), isLoading: false, mutate: mocks.mutate })
    render(<MitigationsContentLive />)
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load mitigations")
    expect(screen.getByRole("alert")).toHaveTextContent("Rules may still be active")
    expect(screen.queryByRole("table")).not.toBeInTheDocument()
    expect(screen.queryByText(/No mitigations/)).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Retry mitigations" }))
    expect(mocks.mutate).toHaveBeenCalled()
  })

  it("keeps the toolbar usable while showing skeleton rows for the first load", () => {
    mocks.useMitigations.mockReturnValue({ data: undefined, error: undefined, isLoading: true, mutate: mocks.mutate })
    render(<MitigationsContentLive />)
    expect(screen.getByRole("status", { name: "Loading mitigations" })).toBeInTheDocument()
    expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toBeEnabled()
  })

  it("separates an empty status selection from a search that matches nothing", () => {
    mocks.useMitigations.mockReturnValue(loaded([]))
    render(<MitigationsContentLive />)
    expect(screen.getByText("No mitigations with these statuses")).toBeInTheDocument()

    fireEvent.change(screen.getByPlaceholderText("Search IP, vector or ID…"), { target: { value: "198.51.100.9" } })
    expect(screen.getByText("No matching mitigations")).toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Clear search and filters" }))
    expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toHaveValue("")
    expect(screen.getByText("No mitigations with these statuses")).toBeInTheDocument()
  })

  it("exposes status filters as pressed toggles", () => {
    mocks.useMitigations.mockReturnValue(loaded([]))
    render(<MitigationsContentLive />)
    const active = screen.getByRole("button", { name: "active" })
    expect(active).toHaveAttribute("aria-pressed", "true")
    fireEvent.click(active)
    expect(active).toHaveAttribute("aria-pressed", "false")
    expect(screen.getByRole("button", { name: "expired" })).toHaveAttribute("aria-pressed", "false")
  })

  it("shows the expiry countdown with its absolute UTC deadline as visible text", () => {
    const expiresAt = new Date(Date.now() + 26 * 60_000 + 30_000).toISOString()
    // SAFETY: only the fields the row renders are needed for this assertion.
    const mitigation = {
      mitigation_id: "m-1", status: "active", victim_ip: "203.0.113.10", vector: "udp_flood", action_type: "police",
      rate_bps: 5_000_000, dst_ports: [53], customer_id: null, pop: "iad1", created_at: new Date().toISOString(), expires_at: expiresAt,
    } as unknown as Mitigation
    mocks.useMitigations.mockReturnValue(loaded([mitigation]))
    render(<MitigationsContentLive />)
    const deadline = screen.getByText(formatUtc(expiresAt))
    expect(deadline).toBeVisible()
    expect(deadline.closest("td")).toHaveTextContent(/26m/)
    expect(deadline.closest("td")?.querySelector("time")).toHaveAttribute("dateTime", expiresAt)
  })

  it("shows a failed events fetch as an error rather than an empty list", () => {
    mocks.useEvents.mockReturnValue({ data: undefined, error: new Error("HTTP 500"), isLoading: false, mutate: mocks.mutate })
    render(<EventsContentLive />)
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load events")
    expect(screen.queryByText("No events yet")).not.toBeInTheDocument()
  })
})
