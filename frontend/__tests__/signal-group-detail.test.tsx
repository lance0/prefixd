import { describe, it, expect, beforeEach } from "vitest"
import { screen, act, within, waitFor, fireEvent } from "@testing-library/react"
import { Suspense } from "react"
import SignalGroupDetailPage from "@/app/(dashboard)/correlation/groups/[id]/page"
import type { CorrelationConfig, SignalGroupDetailResponse, SignalGroupEvent } from "@/lib/api"
import { deferred, failure, json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

// ─── Sample Data ────────────────────────────────────────

const sampleEvents: SignalGroupEvent[] = [
  {
    group_id: "grp-1",
    event_id: "evt-001-aaaa-bbbb-cccc",
    source: "fastnetmon",
    confidence: 0.95,
    source_weight: 1.0,
    ingested_at: new Date(Date.now() - 300000).toISOString(),
    victim_ip: "203.0.113.10",
    vector: "udp_flood",
  },
  {
    group_id: "grp-1",
    event_id: "evt-002-aaaa-bbbb-cccc",
    source: "alertmanager",
    confidence: 0.8,
    source_weight: 0.8,
    ingested_at: new Date(Date.now() - 240000).toISOString(),
    victim_ip: "203.0.113.10",
    vector: "udp_flood",
  },
]

const resolvedGroup: SignalGroupDetailResponse = {
  group_id: "grp-1",
  victim_ip: "203.0.113.10",
  vector: "udp_flood",
  created_at: new Date(Date.now() - 300000).toISOString(),
  window_expires_at: new Date(Date.now() + 300000).toISOString(),
  derived_confidence: 0.88,
  source_count: 2,
  status: "resolved",
  corroboration_met: true,
  events: sampleEvents,
  mitigation_id: "mit-001-aaaa-bbbb-cccc",
}

const openGroup: SignalGroupDetailResponse = {
  group_id: "grp-2",
  victim_ip: "198.51.100.25",
  vector: "syn_flood",
  created_at: new Date(Date.now() - 120000).toISOString(),
  window_expires_at: new Date(Date.now() + 180000).toISOString(),
  derived_confidence: 0.45,
  source_count: 1,
  status: "open",
  corroboration_met: false,
  events: [sampleEvents[0]],
  mitigation_id: null,
}

const expiredGroup: SignalGroupDetailResponse = {
  group_id: "grp-3",
  victim_ip: "192.0.2.100",
  vector: "ntp_amplification",
  created_at: new Date(Date.now() - 600000).toISOString(),
  window_expires_at: new Date(Date.now() - 300000).toISOString(),
  derived_confidence: 0.65,
  source_count: 1,
  status: "expired",
  corroboration_met: false,
  events: [sampleEvents[0]],
  mitigation_id: null,
}

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

// ─── Setup ──────────────────────────────────────────────

beforeEach(() => {
  serveConfig(sampleConfig)
})

function serveConfig(config: CorrelationConfig) {
  controller.route("GET", "/v1/config/correlation", () => json({ config, loaded_at: new Date().toISOString() }))
}

/** Serves one signal group: its detail, a pending request, or a failure. */
function serveGroup(id: string, answer: SignalGroupDetailResponse | Response | "pending") {
  controller.route("GET", `/v1/signal-groups/${id}`, () =>
    answer === "pending" ? deferred<Response>().promise : answer instanceof Response ? answer : json(answer))
}

// ─── Tests ──────────────────────────────────────────────

// Helper: render page and wait for the async params promise to resolve
async function renderPage(id: string) {
  let result!: ReturnType<typeof renderApp>
  await act(async () => {
    result = renderApp(
      <Suspense fallback={<div>Loading suspense...</div>}>
        <SignalGroupDetailPage params={Promise.resolve({ id })} />
      </Suspense>,
      { url: `/correlation/groups/${id}`, withoutAuth: true },
    )
  })
  await waitFor(() => expect(controller.calls("GET", `/v1/signal-groups/${id}`)).toHaveLength(1))
  await settle()
  await settle()

  return result
}

describe("SignalGroupDetailPage", () => {
  it("renders loading state", async () => {
    serveGroup("grp-1", "pending")

    await renderPage("grp-1")

    // A structural skeleton inside the page, not a full-page spinner
    expect(screen.getByRole("status", { name: "Loading signal group" })).toBeInTheDocument()
    expect(screen.getByRole("heading", { level: 1, name: "Signal group" })).toBeInTheDocument()
  })

  it("renders not-found state for unknown group ID", async () => {
    serveGroup("unknown-id", failure(404, "signal group not found"))

    await renderPage("unknown-id")

    expect(screen.getByText("Signal group not found")).toBeInTheDocument()
    expect(
      screen.getByText(
        "The requested signal group ID does not exist or has been removed.",
      ),
    ).toBeInTheDocument()
    expect(screen.getByText("Correlation")).toBeInTheDocument()
  })

  it("renders a retryable error, not not-found, when the request fails", async () => {
    serveGroup("some-id", failure(502, "bad gateway"))

    await renderPage("some-id")

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load this signal group")
    expect(screen.queryByText("Signal group not found")).not.toBeInTheDocument()
    fireEvent.click(screen.getByRole("button", { name: "Retry" }))
    await waitFor(() => expect(controller.calls("GET", "/v1/signal-groups/some-id")).toHaveLength(2))
  })

  it("renders resolved group with all sections", async () => {
    serveGroup("grp-1", resolvedGroup)

    await renderPage("grp-1")

    // Header: victim IP
    expect(screen.getByText("203.0.113.10")).toBeInTheDocument()

    // Vector badge
    expect(screen.getByText("udp flood")).toBeInTheDocument()

    // Status badge
    expect(screen.getByText("Resolved")).toBeInTheDocument()

    // Source count
    expect(screen.getByText("2 sources")).toBeInTheDocument()

    // Contributing events section
    expect(screen.getByText("Contributing events")).toBeInTheDocument()
    expect(screen.getByText("2 events")).toBeInTheDocument()

    // Events in timeline with source badges (appear in both timeline and confidence table)
    expect(screen.getAllByText("fastnetmon").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("alertmanager").length).toBeGreaterThanOrEqual(1)

    // Confidence breakdown section
    expect(screen.getByText("Confidence breakdown")).toBeInTheDocument()
    expect(screen.getByText("Raw confidence")).toBeInTheDocument()
    expect(screen.getByText("Weighted contribution")).toBeInTheDocument()
    expect(screen.getByText("Derived total")).toBeInTheDocument()

    // Corroboration section — should show "Corroborated"
    expect(screen.getByText("Corroborated")).toBeInTheDocument()

    // Linked mitigation card
    expect(screen.getByText("Linked mitigation")).toBeInTheDocument()
    const mitigationLink = screen.getByText("mit-001-…")
    expect(mitigationLink.closest("a")).toHaveAttribute(
      "href",
      "/mitigations/mit-001-aaaa-bbbb-cccc",
    )
  })

  it("renders open group with pending corroboration", async () => {
    serveGroup("grp-2", openGroup)

    await renderPage("grp-2")

    // Header
    expect(screen.getByText("198.51.100.25")).toBeInTheDocument()
    expect(screen.getByText("syn flood")).toBeInTheDocument()
    expect(screen.getByText("Open")).toBeInTheDocument()

    // Pending corroboration badge
    expect(screen.getByText("Pending corroboration 1/2")).toBeInTheDocument()
    expect(
      screen.getByText("1 more distinct source needed"),
    ).toBeInTheDocument()

    // No mitigation - open status explanation
    expect(screen.getByText("No mitigation created")).toBeInTheDocument()
    expect(
      screen.getByText(/Corroboration threshold has not been met yet/),
    ).toBeInTheDocument()
  })

  it("renders expired group with appropriate explanation", async () => {
    serveGroup("grp-3", expiredGroup)

    await renderPage("grp-3")

    // Status badge
    expect(screen.getByText("Expired")).toBeInTheDocument()

    // Pending corroboration
    expect(screen.getByText("Pending corroboration 1/2")).toBeInTheDocument()

    // No mitigation - expired explanation
    expect(screen.getByText("No mitigation created")).toBeInTheDocument()
    expect(
      screen.getByText(/correlation window expired/),
    ).toBeInTheDocument()
  })

  it("renders confidence breakdown with correct math", async () => {
    serveGroup("grp-1", resolvedGroup)

    await renderPage("grp-1")

    // The derived confidence of 88% appears in both the confidence table and summary sidebar
    const allConfidence = screen.getAllByText("88%")
    expect(allConfidence.length).toBeGreaterThanOrEqual(2) // table footer + summary

    // Weight column should show total weight
    // fastnetmon 1.0 + alertmanager 0.8 = 1.8
    expect(screen.getByText("1.8")).toBeInTheDocument()
  })

  // JSON cannot carry NaN, so the API's invalid confidence is an out-of-range fraction.
  it.each([
    [0, "0%"], [null, "Unavailable"], [1.5, "Invalid"],
  ])("does not replace raw or weighted confidence %s with a fabricated zero", async (confidence, label) => {
    serveGroup("grp-1", {
      ...resolvedGroup,
      derived_confidence: 0,
      events: [{ ...sampleEvents[0], confidence }],
    })
    serveConfig({ ...sampleConfig, confidence_threshold: 0 })
    await renderPage("grp-1")
    const row = within(screen.getByRole("table")).getByText("fastnetmon").closest("tr")!
    const cells = within(row).getAllByRole("cell")
    expect(cells[1]).toHaveTextContent(label)
    expect(cells[3]).toHaveTextContent(label)
    expect(screen.getByRole("meter", { name: "Confidence" })).toHaveAttribute("aria-valuenow", "0")
    expect(screen.getByText("Confidence threshold").nextElementSibling).toHaveTextContent("0%")
  })

  it("matches the backend's zero contribution for valid signals with zero total weight", async () => {
    serveGroup("grp-1", {
      ...resolvedGroup,
      derived_confidence: 0,
      events: sampleEvents.map(event => ({ ...event, source_weight: 0 })),
    })
    await renderPage("grp-1")
    const table = screen.getByRole("table")

    for (const [source, raw] of [["fastnetmon", "95%"], ["alertmanager", "80%"]]) {
      const cells = within(within(table).getByText(source).closest("tr")!).getAllByRole("cell")
      expect(cells[1]).toHaveTextContent(raw)
      expect(cells[2]).toHaveTextContent("0.0")
      expect(cells[3]).toHaveTextContent("0%")
    }

    expect(within(table).queryByText("Invalid")).not.toBeInTheDocument()
    expect(screen.getByRole("meter", { name: "Confidence" })).toHaveAttribute("aria-valuenow", "0")
  })

  it("shows invalid derived confidence without drawing an evidence bar", async () => {
    serveGroup("grp-1", { ...resolvedGroup, derived_confidence: 1.5 })
    await renderPage("grp-1")
    expect(screen.getAllByText("Invalid")).toHaveLength(2)
    expect(screen.queryByRole("meter")).not.toBeInTheDocument()
  })

  it("renders bidirectional navigation links", async () => {
    serveGroup("grp-1", resolvedGroup)

    await renderPage("grp-1")

    // Back link
    expect(screen.getByText("Correlation")).toBeInTheDocument()

    // Mitigation link
    const mitigationLink = screen.getByText("mit-001-…").closest("a")
    expect(mitigationLink).toHaveAttribute(
      "href",
      "/mitigations/mit-001-aaaa-bbbb-cccc",
    )

    // IP history link
    const ipLink = screen.getByText("203.0.113.10").closest("a")
    expect(ipLink).toHaveAttribute(
      "href",
      "/ip-history?ip=203.0.113.10",
    )

    // Event links
    const eventLink = screen.getByText("evt-001-")
    expect(eventLink.closest("a")).toHaveAttribute(
      "href",
      "/events?id=evt-001-aaaa-bbbb-cccc",
    )
  })
})
