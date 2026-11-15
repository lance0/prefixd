import { act } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { renderToString } from "react-dom/server"
import { hydrateRoot } from "react-dom/client"
import { TimeZoneProvider, TIME_ZONE_STORAGE_KEY, useTimeFormat, useTimeZone } from "@/components/time-zone-provider"
import { DisplayPreferencesPanel } from "@/components/dashboard/display-preferences"
import { ActiveMitigationsMini } from "@/components/dashboard/active-mitigations-mini"
import { AuditLogContentLive } from "@/components/dashboard/audit-log-content-live"
import { json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"
import type { AuditEntry, Mitigation } from "@/lib/api"

const controller = useFakeController()
const stamp = "2026-11-01T06:30:00Z"
const originalScrollIntoView = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "scrollIntoView")

function TimeReadout() {
  const { timeZone, formatTime } = useTimeFormat()
  const { setTimeZone } = useTimeZone()

  return <><output aria-label="Display time">{timeZone}: {formatTime(stamp)}</output><button onClick={() => setTimeZone("America/New_York")}>Choose New York</button></>
}

beforeEach(() => {
  localStorage.clear()
  // jsdom has no layout/scroll API; the actual Radix selection behavior still runs.
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", { configurable: true, value: vi.fn() })
  vi.spyOn(Date, "now").mockReturnValue(Date.parse("2026-10-18T12:00:00Z"))
})

afterEach(() => {
  cleanup()
  localStorage.clear()
  vi.restoreAllMocks()

  if (originalScrollIntoView) Object.defineProperty(HTMLElement.prototype, "scrollIntoView", originalScrollIntoView)
  else Reflect.deleteProperty(HTMLElement.prototype, "scrollIntoView")
})

describe("browser display timezone", () => {
  it("defaults to UTC and persists an explicit choice across remounts", () => {
    const first = render(<TimeZoneProvider><TimeReadout /></TimeZoneProvider>)
    expect(screen.getByLabelText("Display time")).toHaveTextContent("UTC: 01 Nov 06:30:00 UTC")
    fireEvent.click(screen.getByRole("button", { name: "Choose New York" }))
    expect(screen.getByLabelText("Display time")).toHaveTextContent("America/New_York: 01 Nov 01:30:00 UTC-05:00")
    expect(localStorage.getItem(TIME_ZONE_STORAGE_KEY)).toBe("America/New_York")
    first.unmount()
    render(<TimeZoneProvider><TimeReadout /></TimeZoneProvider>)
    expect(screen.getByLabelText("Display time")).toHaveTextContent("America/New_York: 01 Nov 01:30:00 UTC-05:00")
  })

  it("reports an invalid stored choice and safely uses UTC", () => {
    localStorage.setItem(TIME_ZONE_STORAGE_KEY, "not/a-zone")
    render(<TimeZoneProvider><DisplayPreferencesPanel /><TimeReadout /></TimeZoneProvider>)
    expect(screen.getByLabelText("Display time")).toHaveTextContent("UTC: 01 Nov 06:30:00 UTC")
    expect(screen.getByText("Saved timezone is unavailable. UTC is in use.")).toBeInTheDocument()
  })

  it("selects a supported timezone through the labelled preference control", async () => {
    render(<TimeZoneProvider><DisplayPreferencesPanel /><TimeReadout /></TimeZoneProvider>)
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Display timezone" }), { key: "Enter" })
    const option = await screen.findByRole("option", { name: "America/New_York" })
    option.focus()
    fireEvent.keyDown(option, { key: "Enter" })
    expect(screen.getByLabelText("Display time")).toHaveTextContent("01:30:00 UTC-05:00")
    expect(localStorage.getItem(TIME_ZONE_STORAGE_KEY)).toBe("America/New_York")
  })

  it("uses UTC on the server and hydrates a saved zone without mismatched HTML", async () => {
    localStorage.setItem(TIME_ZONE_STORAGE_KEY, "America/New_York")
    const tree = <TimeZoneProvider><TimeReadout /></TimeZoneProvider>
    const container = document.createElement("div")
    container.innerHTML = renderToString(tree)
    expect(container.textContent).toContain("UTC: 01 Nov 06:30:00 UTC")
    document.body.appendChild(container)
    const onRecoverableError = vi.fn()
    let hydrated: ReturnType<typeof hydrateRoot> | undefined

    await act(async () => { hydrated = hydrateRoot(container, tree, { onRecoverableError }) })
    expect(container.textContent).toContain("America/New_York: 01 Nov 01:30:00 UTC-05:00")
    expect(onRecoverableError).not.toHaveBeenCalled()
    await act(async () => { hydrated?.unmount() })
    container.remove()
  })

  it("updates an already mounted view when another tab changes the saved choice", () => {
    render(<TimeZoneProvider><TimeReadout /></TimeZoneProvider>)
    act(() => {
      localStorage.setItem(TIME_ZONE_STORAGE_KEY, "America/New_York")
      window.dispatchEvent(new StorageEvent("storage", { key: TIME_ZONE_STORAGE_KEY }))
    })
    expect(screen.getByLabelText("Display time")).toHaveTextContent("01:30:00 UTC-05:00")
  })

  it("keeps the active choice but reports a failed browser save", () => {
    render(<TimeZoneProvider><DisplayPreferencesPanel /><TimeReadout /></TimeZoneProvider>)
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => { throw new DOMException("blocked", "SecurityError") })
    fireEvent.click(screen.getByRole("button", { name: "Choose New York" }))
    expect(screen.getByLabelText("Display time")).toHaveTextContent("01:30:00 UTC-05:00")
    expect(screen.getByText(/Could not save the timezone in this browser/)).toBeInTheDocument()
  })

  it("rerenders real mitigation and audit views without changing timestamps, TTL or API queries", async () => {
    const now = Date.parse("2026-11-01T05:00:00Z")
    vi.spyOn(Date, "now").mockReturnValue(now)
    const expires = "2026-11-01T06:05:00Z"

    const mitigation: Mitigation = {
      mitigation_id: "rule-1", scope_hash: "scope-1", status: "active",
      customer_id: null, service_id: null, pop: "example", victim_ip: "192.0.2.10",
      dst_prefix: "192.0.2.10/32", action_type: "discard", rate_bps: null,
      vector: "unknown", protocol: null, dst_ports: [], reason: "owned fixture",
      created_at: stamp, updated_at: stamp, expires_at: expires, withdrawn_at: null,
      triggering_event_id: "event-1", last_event_id: "event-1",
      acknowledged_at: null, acknowledged_by: null,
    }

    const audit: AuditEntry = {
      audit_id: "audit-1", schema_version: 1, timestamp: stamp, actor_type: "system", actor_id: null,
      action: "mitigation.created", target_type: "mitigation", target_id: "rule-1", details: {},
    }

    signIn(controller, "credentials", operatorResponse("operator"))
    controller.route("GET", "/v1/audit", () => json({ entries: [audit], count: 1, next_cursor: null, has_more: false }))
    const { container } = renderApp(<TimeZoneProvider><TimeReadout /><ActiveMitigationsMini mitigations={[mitigation]} /><AuditLogContentLive /></TimeZoneProvider>)
    expect(await screen.findByText("01 Nov 06:30:00 UTC")).toBeInTheDocument()
    expect(screen.getByText("1h 5m")).toBeInTheDocument()
    const requests = controller.requests.map(request => [request.method, request.path, request.query.toString()])
    fireEvent.click(screen.getByRole("button", { name: "Choose New York" }))
    expect(screen.getByText("01 Nov 01:05:00 UTC-05:00")).toBeInTheDocument()
    expect(screen.getByText("01 Nov 01:30:00 UTC-05:00")).toBeInTheDocument()
    expect(screen.getByText("1h 5m")).toBeInTheDocument()
    expect(container.querySelector(`time[datetime="${expires}"]`)).toBeInTheDocument()
    expect(container.querySelector(`time[datetime="${stamp}"]`)).toBeInTheDocument()
    await waitFor(() => expect(controller.requests.map(request => [request.method, request.path, request.query.toString()])).toEqual(requests))
  })
})
