import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, screen, waitFor } from "@testing-library/react"
import { ControllerHealthBanner } from "@/components/dashboard/controller-health-banner"
import { TopBar } from "@/components/dashboard/top-bar"
import { Dialog } from "@/components/ui/dialog"
import { WebSocketProvider } from "@/components/websocket-provider"
import { useHealthDetail } from "@/hooks/use-api"
import type { HealthResponse } from "@/lib/api"
import { deferred, failure, json, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
let served: HealthResponse | undefined
let monotonic = 1000

function Banner() {
  const { data: health, error, isStale, receiptAge } = useHealthDetail()

  return <ControllerHealthBanner health={health} error={error} isStale={isStale} receiptAge={receiptAge} />
}

beforeEach(() => {
  monotonic = 1000
  vi.spyOn(performance, "now").mockImplementation(() => monotonic)
  served = {
    status: "healthy", mode: "enforced", version: "test", pop: "test", uptime_seconds: 10,
    bgp_sessions: {}, active_mitigations: 0, database: "connected", gobgp: { status: "connected" },
    auth_mode: "none", bgp_session_up: false,
    speaker: { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true } },
  }
  controller.route("GET", "/v1/health/detail", () => {
    if (!served) return deferred<Response>().promise
    const { bgp_session_up: _derived, ...wire } = served

    return json(wire)
  })
})

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

function lease(state: NonNullable<NonNullable<HealthResponse["speaker"]>["lease"]>["state"], remaining: number | null = null) {
  served!.speaker!.lease = { state, remaining_seconds: remaining }
}

async function show() {
  const view = renderApp(<Banner />, { withoutAuth: true })
  await waitFor(() => expect(controller.calls("GET", "/v1/health/detail")).toHaveLength(1))
  await settle()

  return view
}

describe("controller health banner", () => {
  it("mounts exactly one warning inside the top bar using health detail", async () => {
    signIn(controller, "none", null)
    served!.status = "standby"
    // Leave the independent realtime transport connecting while HTTP answers.
    vi.stubGlobal("WebSocket", class { static OPEN = 1; readyState = 0; close() {} })
    renderApp(<WebSocketProvider><Dialog><TopBar /></Dialog></WebSocketProvider>)
    await waitFor(() => expect(screen.getByLabelText("Controller warning")).toHaveTextContent("Controller standby"))
    const banner = screen.getByLabelText("Controller warning")
    expect(banner.closest("header")).toBeInTheDocument()
    expect(screen.getAllByLabelText("Controller warning")).toHaveLength(1)
    expect(controller.calls("GET", "/v1/health/detail")).toHaveLength(1)
    expect(controller.calls("GET", "/v1/config/settings")).toHaveLength(0)
  })

  it.each(["none", "live"] as const)("shows no warning for fresh %s lease state", async state => {
    lease(state, state === "live" ? 60 : null)
    await show()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
  })

  it("warns when a live lease is overdue and clears after a successful renewal", async () => {
    lease("live", 0)
    served!.speaker!.lease!.renewal_overdue = true
    const view = await show()
    expect(screen.getByRole("status")).toHaveTextContent("Lease renewal overdue (about 0 s left)")
    expect(screen.getByRole("status")).not.toHaveTextContent("expired")
    lease("live", 60)
    served!.speaker!.lease!.renewal_overdue = false
    await act(() => view.mutate()("health-detail"))
    await settle()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
  })

  it("allows an enforced controller without leases", async () => {
    await show()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
    expect(controller.requests.map(request => request.path)).toEqual(["/v1/health/detail"])
  })

  it.each(["renewal_failing", "expired", "live"] as const)("suppresses historical %s lease warnings only for known empty intent", async state => {
    lease(state, 0)
    served!.speaker!.lease!.has_leased_intent = false
    served!.speaker!.lease!.renewal_overdue = true
    const view = await show()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
    served!.speaker!.lease!.has_leased_intent = true
    await act(() => view.mutate()("health-detail"))
    await settle()
    expect(screen.getByRole("status")).toHaveTextContent(/Lease renewal|Injection lease expired/)
  })

  it("does not hide a failed health read behind cached empty intent", async () => {
    lease("expired", 0)
    served!.speaker!.lease!.has_leased_intent = false
    const view = await show()
    controller.route("GET", "/v1/health/detail", () => failure(503, "offline"))
    await act(() => view.mutate()("health-detail"))
    await settle()
    expect(screen.getByRole("status")).toHaveTextContent("Controller health unavailable")
  })

  it.each([
    ["renewal_failing", "Lease renewal failing (about 40 s left)"],
    ["expired", "Injection lease expired"],
    ["not_renewing", "Injection lease is not renewing"],
    ["standby", "Lease state unknown in standby"],
  ] as const)("shows the %s warning", async (state, message) => {
    lease(state, 40)
    await show()
    expect(screen.getByRole("status")).toHaveTextContent(message)
    expect(screen.getAllByLabelText("Controller warning")).toHaveLength(1)
  })

  it.each(["dry-run", "enforced"] as const)("prioritizes standby over %s and a failed lease", async mode => {
    served!.status = "standby"
    served!.mode = mode
    lease("renewal_failing", 40)
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Controller standby")
    expect(screen.getByRole("status")).not.toHaveTextContent(/Dry-run|s left/)
  })

  it.each(["expired", "not_renewing"] as const)("prioritizes dry-run over %s", async state => {
    served!.mode = "dry-run"
    lease(state)
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Dry-run mode. This controller sends no routing changes.")
    expect(screen.getByRole("status")).not.toHaveTextContent(/expired|not renewing/)
  })

  it("shows dry-run even without a lease", async () => {
    served!.mode = "dry-run"
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Dry-run mode")
  })

  it("keeps missing mode unknown", async () => {
    delete served!.mode
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Controller operation mode is unknown")
  })

  it("keeps an unknown lease state visible", async () => {
    controller.route("GET", "/v1/health/detail", () => json({
      ...served, speaker: { ...served!.speaker, lease: { state: "future", remaining_seconds: 60 } },
    }))
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Injection lease state is unknown")
  })

  it.each([null, -1, Number.NaN])("does not invent a countdown from %s", async remaining => {
    lease("renewal_failing", remaining)
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Time remaining is unavailable")
    expect(screen.getByRole("status")).not.toHaveTextContent("s left")
  })

  it("shows loading without claiming health", async () => {
    served = undefined
    await show()
    expect(screen.getByRole("status")).toHaveTextContent("Checking controller health")
  })

  it("counts down from receipt age, clamps at zero, then marks a stalled read stale", async () => {
    lease("renewal_failing", 12)
    vi.useFakeTimers()
    renderApp(<Banner />, { withoutAuth: true })
    await act(() => vi.advanceTimersByTimeAsync(0))
    expect(screen.getByRole("status")).toHaveTextContent("about 12 s left")
    controller.route("GET", "/v1/health/detail", () => deferred<Response>().promise)
    monotonic += 5000
    act(() => vi.advanceTimersByTime(5000))
    expect(screen.getByRole("status")).toHaveTextContent("about 7 s left")
    monotonic += 10000
    act(() => vi.advanceTimersByTime(10000))
    expect(screen.getByRole("status")).toHaveTextContent("about 0 s left")
    monotonic += 5000
    act(() => vi.advanceTimersByTime(5000))
    expect(screen.getByRole("status")).toHaveTextContent("Controller health is stale")
    expect(screen.getByRole("status")).not.toHaveTextContent("s left")
    vi.setSystemTime(new Date("2000-01-01T00:00:00Z"))
    act(() => vi.advanceTimersByTime(5000))
    expect(screen.getByRole("status")).toHaveTextContent("Controller health is stale")
  })

  it.each(["live", "renewal_failing", "expired"] as const)("replaces cached %s state on error and clears the warning after recovery", async state => {
    lease(state, 40)
    const view = await show()
    controller.route("GET", "/v1/health/detail", () => failure(503, "offline"))
    await act(() => view.mutate()("health-detail"))
    await settle()
    expect(screen.getByRole("status")).toHaveTextContent("Controller health unavailable")
    expect(screen.getByRole("status")).not.toHaveTextContent(/s left|expired|live/)
    lease("live", 60)
    controller.route("GET", "/v1/health/detail", () => json(served))
    await act(() => view.mutate()("health-detail"))
    await settle()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
  })

  it("replaces a cached live lease after its receipt becomes stale", async () => {
    lease("live", 60)
    const view = await show()
    expect(screen.queryByRole("status")).not.toBeInTheDocument()
    monotonic += 20000
    view.rerender(<Banner />)
    expect(screen.getByRole("status")).toHaveTextContent("Controller health is stale")
  })
})
