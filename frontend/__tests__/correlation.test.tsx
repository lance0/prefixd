import { describe, it, expect, beforeEach, vi } from "vitest"
import { act, fireEvent, screen, waitFor } from "@testing-library/react"
import { SignalsTab } from "@/components/dashboard/correlation/signals-tab"
import { GroupsTab } from "@/components/dashboard/correlation/groups-tab"
import { ConfigTab } from "@/components/dashboard/correlation/config-tab"
import type { ConfigPlaybooksResponse, CorrelationConfig, Event, SignalGroup } from "@/lib/api"
import { deferred, failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

// ─── Sample Data ────────────────────────────────────────

const sampleGroups: SignalGroup[] = [
  {
    group_id: "grp-1",
    victim_ip: "203.0.113.10",
    vector: "udp_flood",
    created_at: new Date(Date.now() - 300000).toISOString(),
    window_expires_at: new Date(Date.now() + 300000).toISOString(),
    derived_confidence: 0.88,
    source_count: 2,
    status: "open",
    corroboration_met: true,
  },
  {
    group_id: "grp-2",
    victim_ip: "198.51.100.25",
    vector: "syn_flood",
    created_at: new Date(Date.now() - 600000).toISOString(),
    window_expires_at: new Date(Date.now() - 100000).toISOString(),
    derived_confidence: 0.45,
    source_count: 1,
    status: "expired",
    corroboration_met: false,
  },
]

const sampleConfig: CorrelationConfig = {
  enabled: true,
  window_seconds: 300,
  min_sources: 2,
  confidence_threshold: 0.5,
  default_weight: 1.0,
  sources: {
    fastnetmon: { weight: 1.0, type: "detector", confidence_mapping: {} },
    alertmanager: { weight: 0.8, type: "telemetry", confidence_mapping: {} },
  },
}

const samplePlaybooks: ConfigPlaybooksResponse = {
  playbooks: [{ name: "udp_flood_default", match: { vector: "udp_flood" }, steps: [] }],
  total_playbooks: 1,
  loaded_at: new Date().toISOString(),
}

// fastnetmon reported recently; alertmanager is configured but has not been seen.
const recentEvent: Event = {
  event_id: "event-1", external_event_id: null, source: "fastnetmon",
  event_timestamp: new Date().toISOString(), ingested_at: new Date().toISOString(),
  victim_ip: "203.0.113.10", vector: "udp_flood", protocol: 17,
  bps: null, pps: null, top_dst_ports_json: "[]", confidence: 0.95,
}

type Answer<T> = T | Response | "pending"

/** A signal group as JSON: serde_json writes a non-finite derived confidence as null. */
type WireSignalGroup = Omit<SignalGroup, "derived_confidence"> & { derived_confidence: number | null }

function answer<T>(value: Answer<T>): Response | Promise<Response> {
  return value === "pending" ? deferred<Response>().promise : value instanceof Response ? value : json(value)
}

function serveConfig(config: Answer<CorrelationConfig>) {
  controller.route("GET", "/v1/config/correlation", () =>
    config === "pending" || config instanceof Response ? answer(config) : json({ config, loaded_at: new Date().toISOString() }))
}

function serveEvents(events: Event[]) {
  controller.route("GET", "/v1/events", () => json({ events, count: events.length, next_cursor: null, has_more: false }))
}

function serveGroups(groups: Answer<WireSignalGroup[]>, hasMore = false) {
  controller.route("GET", "/v1/signal-groups", () =>
    groups === "pending" || groups instanceof Response
      ? answer(groups)
      : json({ groups, count: groups.length, next_cursor: hasMore ? "abc" : null, has_more: hasMore }))
}

// ─── Setup ──────────────────────────────────────────────

beforeEach(() => {
  // Auth disabled: every permission is granted, as for an admin.
  signIn(controller, "none", null)
  serveConfig(sampleConfig)
  serveEvents([recentEvent])
  controller.route("GET", "/v1/config/playbooks", () => json(samplePlaybooks))
})

/** Renders a tab once its requests have answered or are still in flight. */
async function show(ui: React.ReactElement, path: string) {
  const view = renderApp(ui, { url: "/correlation" })
  await waitFor(() => expect(controller.calls("GET", path).length).toBeGreaterThan(0))
  await settle()
  await settle()

  return view
}

// ─── Tests ──────────────────────────────────────────────

describe("SignalsTab", () => {
  it("renders source status cards with health indicators", async () => {
    serveGroups(sampleGroups)

    await show(<SignalsTab />, "/v1/config/correlation")

    // Source cards visible (may appear in both cards and weight viz)
    expect(screen.getAllByText("fastnetmon").length).toBeGreaterThan(0)
    expect(screen.getAllByText("alertmanager").length).toBeGreaterThan(0)

    // Type badges
    expect(screen.getByText("detector")).toBeInTheDocument()
    expect(screen.getByText("telemetry")).toBeInTheDocument()

    // Weight display
    expect(screen.getAllByText("1.0").length).toBeGreaterThan(0)
    expect(screen.getAllByText("0.8").length).toBeGreaterThan(0)
  })

  // JSON cannot carry NaN, so the API's invalid confidence is an out-of-range fraction.
  it("preserves zero, missing and invalid confidence in recent signals", async () => {
    serveGroups([0.95, 0, null, 1.5].map((confidence, index) => ({
      ...sampleGroups[0], group_id: `group-${index}`, derived_confidence: confidence,
    })))
    await show(<SignalsTab />, "/v1/signal-groups")

    for (const label of ["95%", "0%", "Unavailable", "Invalid"]) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it("renders loading skeletons while fetching", async () => {
    serveConfig("pending")
    serveGroups("pending")

    const { container } = await show(<SignalsTab />, "/v1/signal-groups")

    // Skeleton elements are rendered
    const skeletons = container.querySelectorAll("[data-slot='skeleton']")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders empty state when no sources configured", async () => {
    serveConfig({ ...sampleConfig, sources: {} })
    serveEvents([])
    serveGroups([])

    await show(<SignalsTab />, "/v1/config/correlation")

    expect(screen.getByText("No signal sources configured")).toBeInTheDocument()
  })

  it("renders error state on fetch failure", async () => {
    serveConfig(failure(500, "fail"))
    serveGroups([])

    await show(<SignalsTab />, "/v1/config/correlation")

    expect(screen.getByText("Unable to load signal sources")).toBeInTheDocument()
  })

  it("renders recent signals table with group data", async () => {
    serveGroups(sampleGroups)

    await show(<SignalsTab />, "/v1/signal-groups")

    // Table headers
    expect(screen.getByText("Victim IP")).toBeInTheDocument()
    expect(screen.getByText("Vector")).toBeInTheDocument()

    // Group data
    expect(screen.getByText("203.0.113.10")).toBeInTheDocument()
    expect(screen.getByText("198.51.100.25")).toBeInTheDocument()
    expect(screen.getByText("udp flood")).toBeInTheDocument()
    expect(screen.getByText("syn flood")).toBeInTheDocument()
  })
})

describe("GroupsTab", () => {
  it("renders filterable group list", async () => {
    serveGroups(sampleGroups)

    await show(<GroupsTab />, "/v1/signal-groups")

    // Table with data
    expect(screen.getByText("203.0.113.10")).toBeInTheDocument()
    expect(screen.getByText("198.51.100.25")).toBeInTheDocument()
    expect(screen.getByText("88%")).toBeInTheDocument()
    expect(screen.getByText("45%")).toBeInTheDocument()
  })

  it.each([
    [0, "0%", "text-warning"],
    [0.499, "50%", "text-warning"],
    [0.5, "50%", "text-foreground"],
    [0.799, "80%", "text-foreground"],
    [0.8, "80%", "font-medium"],
    [0.95, "95%", "font-medium"],
    [1, "100%", "font-medium"],
    [null, "Unavailable", "text-muted-foreground"],
    [1.5, "Invalid", "text-muted-foreground"],
  ])("classifies confidence %s before rounding its label", async (confidence, label, color) => {
    serveGroups([{ ...sampleGroups[0], derived_confidence: confidence }])
    await show(<GroupsTab />, "/v1/signal-groups")
    expect(screen.getByText(label)).toHaveClass(color)
  })

  it("renders empty state with clear-filters option", async () => {
    serveGroups([])

    await show(<GroupsTab />, "/v1/signal-groups")

    expect(screen.getByText("No signal groups yet")).toBeInTheDocument()
  })

  it("renders loading skeletons", async () => {
    serveGroups("pending")

    const { container } = await show(<GroupsTab />, "/v1/signal-groups")

    const skeletons = container.querySelectorAll("[data-slot='skeleton']")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders error state", async () => {
    serveGroups(failure(500, "fail"))

    await show(<GroupsTab />, "/v1/signal-groups")

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load signal groups")
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument()
    expect(screen.queryByText("No signal groups yet")).not.toBeInTheDocument()
  })

  it("shows Load More button when has_more is true", async () => {
    serveGroups(sampleGroups, true)

    await show(<GroupsTab />, "/v1/signal-groups")

    expect(screen.getByText("Load more")).toBeInTheDocument()
  })

  it("keeps Load more usable while a background poll revalidates loaded pages", async () => {
    controller.route("GET", "/v1/signal-groups", ({ query }) => {
      const group = sampleGroups[query.get("cursor") ? 1 : 0]

      return json({ groups: [group], count: 1, next_cursor: group.group_id, has_more: true })
    })
    vi.useFakeTimers()

    try {
      renderApp(<GroupsTab />, { url: "/correlation" })
      await act(() => vi.advanceTimersByTimeAsync(0))
      fireEvent.click(screen.getByRole("button", { name: "Load more" }))
      await act(() => vi.advanceTimersByTimeAsync(0))
      expect(screen.getByText("198.51.100.25")).toBeInTheDocument()
      const loaded = controller.calls("GET", "/v1/signal-groups").length
      serveGroups("pending")
      await act(() => vi.advanceTimersByTimeAsync(5000))
      expect(controller.calls("GET", "/v1/signal-groups").length).toBeGreaterThan(loaded)
      expect(screen.getByRole("button", { name: "Load more" })).toBeEnabled()
    } finally {
      vi.clearAllTimers()
      vi.useRealTimers()
    }
  })
})

describe("ConfigTab", () => {
  it("renders correlation settings form (admin)", async () => {
    await show(<ConfigTab />, "/v1/config/correlation")

    // Settings section
    expect(screen.getByText("Correlation settings")).toBeInTheDocument()
    expect(screen.getByText("Enabled")).toBeInTheDocument()

    // Form fields
    expect(screen.getByLabelText("Window (seconds)")).toBeInTheDocument()
    expect(screen.getByLabelText("Min sources")).toBeInTheDocument()
    expect(screen.getByLabelText("Confidence threshold")).toBeInTheDocument()

    // Signal sources section
    expect(screen.getByText("Signal sources")).toBeInTheDocument()
    expect(screen.getByText("Add source")).toBeInTheDocument()
  })

  it("shows read-only message for non-admin", async () => {
    signIn(controller, "credentials", operatorResponse("operator"))

    await show(<ConfigTab />, "/v1/config/correlation")
    await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))
    await settle()

    expect(screen.getByText("Admin access required to edit settings")).toBeInTheDocument()
    // Add Source button should not be present for non-admin
    expect(screen.queryByText("Add source")).not.toBeInTheDocument()
  })

  it("renders per-playbook overrides with link to Playbooks tab", async () => {
    await show(<ConfigTab />, "/v1/config/playbooks")

    expect(screen.getByText("Per-playbook overrides")).toBeInTheDocument()
    expect(screen.getByText("udp_flood_default")).toBeInTheDocument()
    expect(screen.getByText("Edit in playbooks")).toBeInTheDocument()
  })

  it("renders source CRUD cards for admin", async () => {
    await show(<ConfigTab />, "/v1/config/correlation")

    // Source cards
    expect(screen.getByText("fastnetmon")).toBeInTheDocument()
    expect(screen.getByText("alertmanager")).toBeInTheDocument()

    // Edit and Remove buttons visible for admin
    expect(screen.getAllByText("Edit").length).toBe(2)
    expect(screen.getAllByText("Remove").length).toBe(2)
  })

  it("renders loading state", async () => {
    serveConfig("pending")
    controller.route("GET", "/v1/config/playbooks", () => deferred<Response>().promise)

    const { container } = await show(<ConfigTab />, "/v1/config/correlation")

    const skeletons = container.querySelectorAll("[data-slot='skeleton']")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})
