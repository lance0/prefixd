import type { ReactElement } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, screen, waitFor } from "@testing-library/react"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import AdminPage from "@/app/(dashboard)/admin/page"
import { healthReceiptAge } from "@/hooks/use-api"
import type { HealthResponse } from "@/lib/api"
import { deferred, failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

/** What /v1/health/detail answers; undefined keeps the first poll in flight. */
let served: HealthResponse | undefined

/** Milliseconds added to the browser's monotonic clock, to age a received snapshot. */
let clockOffset = 0

beforeEach(() => {
  served = undefined
  clockOffset = 0
  const realNow = performance.now.bind(performance)
  vi.spyOn(performance, "now").mockImplementation(() => realNow() + clockOffset)
  signIn(controller, "credentials", operatorResponse("viewer"))
  controller.route("GET", "/v1/health/detail", () => {
    if (!served) return deferred<Response>().promise
    const { bgp_session_up: _derived, ...wire } = served

    return json(wire)
  })
  controller.route("GET", "/v1/stats", () => json({ total_active: 0, total_mitigations: 0, total_events: 0, pops: [] }))
  controller.route("GET", "/v1/safelist", () => json([]))
  controller.route("GET", "/v1/pops", () => json([]))
  controller.route("GET", "/v1/operators", () => json({ operators: [], count: 0 }))
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
})

afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks() })

function health(status: string, peers: Record<string, string> = {}): HealthResponse {
  return {
    status: "healthy", version: "test", pop: "test", uptime_seconds: 10,
    bgp_sessions: peers, active_mitigations: 0, database: "connected",
    gobgp: { status }, auth_mode: "none",
    bgp_session_up: status === "connected" && Object.keys(peers).length > 0 && Object.values(peers).every(state => state === "established"),
  }
}

function observed(): HealthResponse {
  served = health("connected", { router: "established" })

  return served
}

/** Renders a view once its first health poll has answered (or is still in flight). */
async function show(ui: ReactElement) {
  const view = renderApp(ui, { url: "/admin" })
  await waitFor(() => expect(controller.calls("GET", "/v1/health/detail").length).toBeGreaterThan(0))
  await settle()

  return view
}

/** Ages the received snapshot past three poll intervals without another response. */
function ageSnapshot(view: Awaited<ReturnType<typeof show>>, ui: ReactElement) {
  clockOffset += 20000
  view.rerender(ui)
}

/** Fails the next poll while SWR still holds the last successful snapshot. */
async function failNextPoll(view: Awaited<ReturnType<typeof show>>) {
  controller.route("GET", "/v1/health/detail", () => failure(503, "offline"))
  await act(() => view.mutate()("health-detail"))
  await settle()
}

interface PeerCase {
  status: string
  peers: Record<string, string>
  badge: string
  detail: string
}

const peerCases: PeerCase[] = [
  { status: "unsupported", peers: {}, badge: "unsupported", detail: "BGP peer observation is unsupported by this speaker" },
  { status: "error", peers: {}, badge: "error", detail: "BGP peer observation failed" },
  { status: "connected", peers: {}, badge: "no peers", detail: "No BGP peers configured" },
  { status: "connected", peers: { router: "established" }, badge: "up", detail: "router" },
  { status: "connected", peers: { router: "idle" }, badge: "down", detail: "router" },
]

describe("speaker observation UI", () => {
  it.each(peerCases)("renders $status with $peers peers distinctly in both views", async ({ status, peers, badge, detail }) => {
    // Older servers omit additive speaker metadata.
    served = health(status, peers)
    await show(<BgpSessionStatus />)
    expect(screen.getByText(badge)).toBeInTheDocument()
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent(`Peers ${badge}`)
    await show(<AdminPage />)
    expect(screen.getByText(detail)).toBeInTheDocument()
    expect(screen.queryByText(/FlowSpec announcements are active/)).not.toBeInTheDocument()
  })

  it.each([false, true, undefined])("annotates rule-reader availability only when explicitly false (%s)", async (reader) => {
    const snapshot = observed()

    if (reader !== undefined) {
      snapshot.speaker = { backend: "test", capabilities: { rule_reader: reader, peer_observer: true } }
    }

    await show(<AdminPage />)
    const annotation = screen.queryByText("Rule observation is unsupported by this speaker")

    if (reader === false) expect(annotation).toBeInTheDocument()
    else expect(annotation).not.toBeInTheDocument()
    expect(screen.getByText("router")).toBeInTheDocument()
    expect(screen.getByText("established")).toBeInTheDocument()
  })

  it("labels version and uptime as controller data, with backend and session counts separate", async () => {
    const snapshot = health("connected", { edge1: "established", edge2: "idle" })
    snapshot.version = "0.22.0"
    snapshot.uptime_seconds = 3660
    snapshot.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true } }
    served = snapshot
    await show(<BgpSessionStatus />)
    const strip = screen.getByLabelText("Speaker and controller health")
    expect(screen.getByText("rustbgpd")).toBeInTheDocument()
    expect(screen.getByText("down")).toBeInTheDocument()
    expect(strip).toHaveTextContent("Peers down")
    expect(strip).toHaveTextContent("1/2 established")
    expect(strip).toHaveTextContent("Controller v0.22.0 · up 1h 1m")
    expect(strip).not.toHaveTextContent(/installed|speaker version|speaker uptime/i)
  })

  it("keeps an initial health fetch separate from successful empty peers", async () => {
    await show(<BgpSessionStatus />)
    expect(screen.getByText("loading")).toBeInTheDocument()
    expect(screen.queryByText("no peers")).not.toBeInTheDocument()
  })

  it("shows a fetch error instead of stale successful peer state", async () => {
    observed()
    const view = await show(<BgpSessionStatus />)
    expect(screen.getByText("up")).toBeInTheDocument()
    await failNextPoll(view)
    expect(screen.getByText("error")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
  })

  it.each([0, 3660])("shows observed daemon metadata independently of controller uptime (%s)", async (uptime) => {
    const snapshot = observed()
    snapshot.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true, daemon_health: true },
      daemon: { status: "observed", version: "actual-daemon-version", uptime_seconds: uptime, ready: true, observed_at: new Date().toISOString() } }
    await show(<BgpSessionStatus />)
    const strip = screen.getByLabelText("Speaker and controller health")
    expect(strip).toHaveTextContent("Daemon actual-daemon-version")
    expect(strip).toHaveTextContent(`up ${uptime === 0 ? "0s" : "1h 1m"} · ready`)
    expect(strip).toHaveTextContent("Controller vtest · up 10s")
    expect(strip).toHaveTextContent("Received 0s ago")
  })

  it.each(["unsupported", "error"] as const)("does not substitute controller metadata when daemon observation is %s", async (status) => {
    const snapshot = observed()
    snapshot.speaker = { backend: "gobgp", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status, version: null, uptime_seconds: null, ready: null, observed_at: null } }
    await show(<BgpSessionStatus />)
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent(`Daemon ${status === "error" ? "unavailable" : "unsupported"}`)
  })

  it("preserves missing version and not-ready process state", async () => {
    const snapshot = observed()
    snapshot.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: null, uptime_seconds: 0, ready: false, observed_at: new Date().toISOString() } }
    await show(<BgpSessionStatus />)
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent("Daemon version unavailable · up 0s · not ready")
    expect(screen.getByText("not ready")).toHaveClass("text-destructive")
  })

  it("does not retain a healthy peer badge or old daemon metadata beyond three poll intervals", async () => {
    const snapshot = observed()
    snapshot.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: "old-version", uptime_seconds: 123, ready: true, observed_at: new Date(Date.now() - 20000).toISOString() } }
    const view = await show(<BgpSessionStatus />)
    ageSnapshot(view, <BgpSessionStatus />)
    expect(screen.getByText("stale")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
    expect(screen.queryByText("old-version")).not.toBeInTheDocument()
    expect(screen.getByText("Health observation is stale. Retrying automatically.")).toBeInTheDocument()
    expect(screen.queryByText("connected")).not.toBeInTheDocument()
  })

  it("hides cached daemon and controller observations on fetch failure", async () => {
    const snapshot = observed()
    snapshot.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: "cached-version", uptime_seconds: 123, ready: true, observed_at: new Date().toISOString() } }
    const view = await show(<BgpSessionStatus />)
    expect(screen.getByText("cached-version")).toBeInTheDocument()
    await failNextPoll(view)
    expect(screen.queryByText("cached-version")).not.toBeInTheDocument()
    expect(screen.getByText("error")).toBeInTheDocument()
  })

  it("uses only local receipt time, independent of server clock skew", async () => {
    const now = performance.now()
    expect(healthReceiptAge(undefined, now)).toBeNull()
    expect(healthReceiptAge(Number.NaN, now)).toBeNull()
    expect(healthReceiptAge(now + 1000, now)).toBeNull()
    expect(healthReceiptAge(now - 5000, now)).toBe(5000)
    const snapshot = observed()
    snapshot.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: "real-version", uptime_seconds: 0, ready: true, observed_at: "2099-01-01T00:00:00Z" } }
    await show(<BgpSessionStatus />)
    expect(screen.getByText("up")).toBeInTheDocument()
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent("real-version")
  })

  it("expires a cached GoBGP UP snapshot while preserving unsupported daemon metadata", async () => {
    const snapshot = observed()
    snapshot.speaker = { backend: "gobgp", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "unsupported", version: null, uptime_seconds: null, ready: null, observed_at: null } }
    const view = await show(<BgpSessionStatus />)
    ageSnapshot(view, <BgpSessionStatus />)
    expect(screen.getByText("stale")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent("Daemon unsupported")
  })

  it("expires a stalled successful fetch by browser receipt age without another response", async () => {
    const { bgp_session_up: _derived, ...wire } = observed()
    // Answer the first poll only; later polls stall.
    controller.route("GET", "/v1/health/detail", () => {
      controller.route("GET", "/v1/health/detail", () => deferred<Response>().promise)

      return json(wire)
    })
    vi.useFakeTimers()
    let monotonic = 1000
    vi.spyOn(performance, "now").mockImplementation(() => monotonic)
    renderApp(<BgpSessionStatus />, { url: "/admin" })
    await act(() => vi.advanceTimersByTimeAsync(0))
    expect(screen.getByText("up")).toBeInTheDocument()
    monotonic += 20000
    act(() => vi.advanceTimersByTime(20000))
    expect(screen.getByText("stale")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
    expect(screen.queryByText("connected")).not.toBeInTheDocument()
    vi.setSystemTime(new Date("2000-01-01T00:00:00Z"))
    act(() => vi.advanceTimersByTime(5000))
    expect(screen.getByText("stale")).toBeInTheDocument()
  })

  it.each(["stale", "error"])("hides Admin established badges for %s cached health", async (state) => {
    observed()
    const view = await show(<AdminPage />)
    expect(screen.getByText("established")).toBeInTheDocument()

    if (state === "stale") ageSnapshot(view, <AdminPage />)
    else await failNextPoll(view)
    expect(screen.queryByText("established")).not.toBeInTheDocument()
    expect(screen.queryByText("router")).not.toBeInTheDocument()
  })
})
