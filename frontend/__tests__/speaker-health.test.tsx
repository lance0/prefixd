import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, cleanup, render, screen } from "@testing-library/react"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import AdminPage from "@/app/(dashboard)/admin/page"
import { healthReceiptAge, type HealthDetailSnapshot } from "@/hooks/use-api"

const mock = vi.hoisted(() => ({ health: undefined as HealthDetailSnapshot | undefined, error: undefined as Error | undefined }))
vi.mock("swr", async (importOriginal) => ({
  ...await importOriginal<typeof import("swr")>(),
  default: () => ({ data: mock.health, error: mock.error, isLoading: !mock.health && !mock.error }),
}))
vi.mock("@/hooks/use-api", async (importOriginal) => ({
  ...await importOriginal<typeof import("@/hooks/use-api")>(),
  usePops: () => ({ data: [] }),
  useStats: () => ({}),
  useSafelist: () => ({ data: [] }),
  useOperators: () => ({ data: [] }),
}))
vi.mock("@/hooks/use-reduced-motion", () => ({ useReducedMotion: () => true }))
vi.mock("next/navigation", () => ({ usePathname: () => "/admin", useSearchParams: () => new URLSearchParams() }))
vi.mock("@/hooks/use-permissions", () => ({ usePermissions: () => ({}) }))
vi.mock("@/hooks/use-auth", () => ({ useAuth: () => ({ operator: null }) }))
vi.mock("@/components/dashboard/dashboard-layout", () => ({ DashboardLayout: ({ children }: { children: ReactNode }) => <>{children}</> }))

afterEach(() => { cleanup(); vi.useRealTimers(); vi.restoreAllMocks() })
beforeEach(() => { mock.health = undefined; mock.error = undefined })

function health(status: string, peers: Record<string, string> = {}): HealthDetailSnapshot {
  return {
    receivedAt: performance.now(), status: "healthy", version: "test", pop: "test", uptime_seconds: 10,
    bgp_sessions: peers, active_mitigations: 0, database: "connected",
    gobgp: { status }, auth_mode: "none",
    bgp_session_up: status === "connected" && Object.keys(peers).length > 0 && Object.values(peers).every(state => state === "established"),
  }
}

describe("speaker observation UI", () => {
  it.each([
    ["unsupported", {}, "unsupported", "BGP peer observation is unsupported by this speaker"],
    ["error", {}, "error", "BGP peer observation failed"],
    ["connected", {}, "no peers", "No BGP peers configured"],
    ["connected", { router: "established" }, "up", "router"],
    ["connected", { router: "idle" }, "down", "router"],
  ])("renders %s with %j peers distinctly in both views", (status, peers, badge, detail) => {
    // Older servers omit additive speaker metadata.
    mock.health = health(status as string, peers as Record<string, string>)
    render(<BgpSessionStatus />)
    expect(screen.getByText(badge as string)).toBeInTheDocument()
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent(`Peers ${badge}`)
    render(<AdminPage />)
    expect(screen.getByText(detail as string)).toBeInTheDocument()
    expect(screen.queryByText(/FlowSpec announcements are active/)).not.toBeInTheDocument()
  })

  it.each([false, true, undefined])("annotates rule-reader availability only when explicitly false (%s)", (reader) => {
    mock.health = health("connected", { router: "established" })
    if (reader !== undefined) {
      mock.health.speaker = { backend: "test", capabilities: { rule_reader: reader, peer_observer: true } }
    }
    render(<AdminPage />)
    const annotation = screen.queryByText("Rule observation is unsupported by this speaker")
    if (reader === false) expect(annotation).toBeInTheDocument()
    else expect(annotation).not.toBeInTheDocument()
    expect(screen.getByText("router")).toBeInTheDocument()
    expect(screen.getByText("established")).toBeInTheDocument()
  })

  it("labels version and uptime as controller data, with backend and session counts separate", () => {
    mock.health = health("connected", { edge1: "established", edge2: "idle" })
    mock.health.version = "0.22.0"
    mock.health.uptime_seconds = 3660
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true } }
    render(<BgpSessionStatus />)
    const strip = screen.getByLabelText("Speaker and controller health")
    expect(screen.getByText("rustbgpd")).toBeInTheDocument()
    expect(screen.getByText("down")).toBeInTheDocument()
    expect(strip).toHaveTextContent("Peers down")
    expect(strip).toHaveTextContent("1/2 established")
    expect(strip).toHaveTextContent("Controller v0.22.0 · up 1h 1m")
    expect(strip).not.toHaveTextContent(/installed|speaker version|speaker uptime/i)
  })

  it("keeps an initial health fetch separate from successful empty peers", () => {
    render(<BgpSessionStatus />)
    expect(screen.getByText("loading")).toBeInTheDocument()
    expect(screen.queryByText("no peers")).not.toBeInTheDocument()
  })

  it("shows a fetch error instead of stale successful peer state", () => {
    mock.health = health("connected", { router: "established" })
    mock.error = new Error("offline")
    render(<BgpSessionStatus />)
    expect(screen.getByText("error")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
  })
  it.each([0, 3660])("shows observed daemon metadata independently of controller uptime (%s)", (uptime) => {
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true, daemon_health: true },
      daemon: { status: "observed", version: "actual-daemon-version", uptime_seconds: uptime, ready: true, observed_at: new Date().toISOString() } }
    render(<BgpSessionStatus />)
    const strip = screen.getByLabelText("Speaker and controller health")
    expect(strip).toHaveTextContent("Daemon actual-daemon-version")
    expect(strip).toHaveTextContent(`up ${uptime === 0 ? "0s" : "1h 1m"} · ready`)
    expect(strip).toHaveTextContent("Controller vtest · up 10s")
    expect(strip).toHaveTextContent("Received 0s ago")
  })

  it.each(["unsupported", "error"] as const)("does not substitute controller metadata when daemon observation is %s", (status) => {
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "gobgp", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status, version: null, uptime_seconds: null, ready: null, observed_at: null } }
    render(<BgpSessionStatus />)
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent(`Daemon ${status === "error" ? "unavailable" : "unsupported"}`)
  })

  it("preserves missing version and not-ready process state", () => {
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: null, uptime_seconds: 0, ready: false, observed_at: new Date().toISOString() } }
    render(<BgpSessionStatus />)
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent("Daemon version unavailable · up 0s · not ready")
    expect(screen.getByText("not ready")).toHaveClass("text-destructive")
  })

  it("does not retain a healthy peer badge or old daemon metadata beyond three poll intervals", () => {
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: "old-version", uptime_seconds: 123, ready: true, observed_at: new Date(Date.now() - 20000).toISOString() } }
    mock.health.receivedAt = performance.now() - 20000
    render(<BgpSessionStatus />)
    expect(screen.getByText("stale")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
    expect(screen.queryByText("old-version")).not.toBeInTheDocument()
    expect(screen.getByText("Health observation is stale. Retrying automatically.")).toBeInTheDocument()
    expect(screen.queryByText("connected")).not.toBeInTheDocument()
  })

  it("hides cached daemon and controller observations on fetch failure", () => {
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: "cached-version", uptime_seconds: 123, ready: true, observed_at: new Date().toISOString() } }
    mock.error = new Error("offline")
    render(<BgpSessionStatus />)
    expect(screen.queryByText("cached-version")).not.toBeInTheDocument()
    expect(screen.getByText("error")).toBeInTheDocument()
  })

  it("uses only local receipt time, independent of server clock skew", () => {
    const now = performance.now()
    expect(healthReceiptAge(undefined, now)).toBeNull()
    expect(healthReceiptAge(Number.NaN, now)).toBeNull()
    expect(healthReceiptAge(now + 1000, now)).toBeNull()
    expect(healthReceiptAge(now - 5000, now)).toBe(5000)
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "rustbgpd", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "observed", version: "real-version", uptime_seconds: 0, ready: true, observed_at: "2099-01-01T00:00:00Z" } }
    render(<BgpSessionStatus />)
    expect(screen.getByText("up")).toBeInTheDocument()
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent("real-version")
  })

  it("expires a cached GoBGP UP snapshot while preserving unsupported daemon metadata", () => {
    mock.health = health("connected", { router: "established" })
    mock.health.speaker = { backend: "gobgp", capabilities: { rule_reader: true, peer_observer: true },
      daemon: { status: "unsupported", version: null, uptime_seconds: null, ready: null, observed_at: null } }
    mock.health.receivedAt = performance.now() - 20000
    render(<BgpSessionStatus />)
    expect(screen.getByText("stale")).toBeInTheDocument()
    expect(screen.queryByText("up")).not.toBeInTheDocument()
    expect(screen.getByLabelText("Speaker and controller health")).toHaveTextContent("Daemon unsupported")
  })

  it("expires a stalled successful fetch by browser receipt age without another response", () => {
    vi.useFakeTimers()
    let monotonic = 1000
    vi.spyOn(performance, "now").mockImplementation(() => monotonic)
    mock.health = health("connected", { router: "established" })
    render(<BgpSessionStatus />)
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

  it.each(["stale", "error"])("hides Admin established badges for %s cached health", (state) => {
    mock.health = health("connected", { router: "established" })
    if (state === "stale") mock.health.receivedAt = performance.now() - 20000
    else mock.error = new Error("offline")
    render(<AdminPage />)
    expect(screen.queryByText("established")).not.toBeInTheDocument()
    expect(screen.queryByText("router")).not.toBeInTheDocument()
  })

})
