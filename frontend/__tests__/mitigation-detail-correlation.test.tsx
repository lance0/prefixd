import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen, waitFor, act, within } from "@testing-library/react"
import { Suspense } from "react"

// ─── Mocks ──────────────────────────────────────────────

const mockPush = vi.fn()
vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush, back: vi.fn() }),
  usePathname: () => "/mitigations/mit-001",
  useSearchParams: () => new URLSearchParams(),
}))

vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: { children: React.ReactNode; href: string }) => (
    <a href={href} {...props}>{children}</a>
  ),
}))

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// Mock use-api hooks
const mockUseMitigation = vi.fn()
const mockUseConfigInventory = vi.fn()
const mockUseSignalGroupDetail = vi.fn()

vi.mock("@/hooks/use-api", () => ({
  useMitigation: (...args: unknown[]) => mockUseMitigation(...args),
  useConfigInventory: () => mockUseConfigInventory(),
  useSignalGroupDetail: (...args: unknown[]) => mockUseSignalGroupDetail(...args),
}))

// Mock use-permissions
vi.mock("@/hooks/use-permissions", () => ({
  usePermissions: () => ({
    settled: true,
    authDisabled: true,
    isAdmin: true,
    isOperator: true,
    canWithdraw: true,
    canAcknowledge: true,
  }),
}))

// Mock DashboardLayout
vi.mock("@/components/dashboard/dashboard-layout", () => ({
  DashboardLayout: ({ children }: { children: React.ReactNode }) => (
    <div data-testid="dashboard-layout">{children}</div>
  ),
}))

// Mock StatusBadge and ActionBadge
vi.mock("@/components/dashboard/status-badge", () => ({
  StatusBadge: ({ status }: { status: string }) => <span data-testid="status-badge">{status}</span>,
}))

vi.mock("@/components/dashboard/action-badge", () => ({
  ActionBadge: () => <span data-testid="action-badge">action</span>,
}))

// Mock FlowSpecPreview
vi.mock("@/components/dashboard/flowspec-preview", () => ({
  FlowSpecPreview: () => <div data-testid="flowspec-preview" />,
  formatFlowSpecRule: () => "flowspec-rule",
}))

// Mock IncidentReportDialog
vi.mock("@/components/dashboard/incident-report-dialog", () => ({
  IncidentReportDialog: () => null,
}))

// Mock API functions
vi.mock("@/lib/api", async () => {
  const actual = await vi.importActual("@/lib/api")
  return {
    ...actual,
    withdrawMitigation: vi.fn(),
    getIncidentReport: vi.fn(),
  }
})

// ─── Imports ────────────────────────────────────────────

import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"

// ─── Sample Data ────────────────────────────────────────

const baseMitigation = {
  mitigation_id: "mit-001-aaaa-bbbb-cccc",
  scope_hash: "abc123",
  status: "active" as const,
  customer_id: "cust_acme",
  service_id: "svc_dns",
  pop: "iad1",
  victim_ip: "203.0.113.10",
  vector: "udp_flood",
  action_type: "police" as const,
  rate_bps: 5000000,
  dst_prefix: "203.0.113.10/32",
  protocol: 17,
  dst_ports: [53],
  created_at: new Date(Date.now() - 120000).toISOString(),
  updated_at: new Date(Date.now() - 120000).toISOString(),
  expires_at: new Date(Date.now() + 180000).toISOString(),
  withdrawn_at: null,
  triggering_event_id: "evt-001",
  last_event_id: "evt-001",
  reason: "UDP flood detected",
  acknowledged_at: null,
  acknowledged_by: null,
}

const correlatedMitigation = {
  ...baseMitigation,
  correlation: {
    signal_group_id: "sg-001-aaaa-bbbb-cccc-dddd",
    derived_confidence: 0.88,
    source_count: 2,
    corroboration_met: true,
    contributing_sources: ["fastnetmon", "alertmanager"],
    explanation:
      'Corroboration achieved: 2 of 2 required sources confirmed UDP flood on 203.0.113.10. Derived confidence 88% (threshold 50%). Sources: fastnetmon (95% × 1.0), alertmanager (80% × 0.8).',
  },
}

const nonCorrelatedMitigation = {
  ...baseMitigation,
  correlation: null,
}

const signalGroupDetailData = {
  group_id: "sg-001-aaaa-bbbb-cccc-dddd",
  victim_ip: "203.0.113.10",
  vector: "udp_flood",
  created_at: new Date(Date.now() - 300000).toISOString(),
  window_expires_at: new Date(Date.now() + 300000).toISOString(),
  derived_confidence: 0.88,
  source_count: 2,
  status: "resolved" as const,
  corroboration_met: true,
  mitigation_id: "mit-001-aaaa-bbbb-cccc",
  events: [
    {
      group_id: "sg-001-aaaa-bbbb-cccc-dddd",
      event_id: "evt-001",
      source: "fastnetmon",
      confidence: 0.95,
      source_weight: 1.0,
      ingested_at: new Date(Date.now() - 300000).toISOString(),
      victim_ip: "203.0.113.10",
      vector: "udp_flood",
    },
    {
      group_id: "sg-001-aaaa-bbbb-cccc-dddd",
      event_id: "evt-002",
      source: "alertmanager",
      confidence: 0.8,
      source_weight: 0.8,
      ingested_at: new Date(Date.now() - 240000).toISOString(),
      victim_ip: "203.0.113.10",
      vector: "udp_flood",
    },
  ],
}

// ─── Helper ─────────────────────────────────────────────

async function renderPage() {
  let result: ReturnType<typeof render>
  await act(async () => {
    result = render(
      <Suspense fallback={<div>Loading suspense...</div>}>
        <MitigationDetailPage params={Promise.resolve({ id: "mit-001-aaaa-bbbb-cccc" })} />
      </Suspense>
    )
  })
  return result!
}

// ─── Tests ──────────────────────────────────────────────

describe("Mitigation Detail – Correlation Section", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConfigInventory.mockReturnValue({ data: null })
  })

  it("shows Correlation card with all fields for a correlated mitigation", async () => {
    mockUseMitigation.mockReturnValue({
      data: correlatedMitigation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: signalGroupDetailData,
      isLoading: false,
      error: null,
    })

    await renderPage()

    expect(screen.getByTestId("correlation-card")).toBeTruthy()

    // Signal group link
    const groupLink = screen.getByText("sg-001-aaaa-bbbb-cccc-dddd")
    expect(groupLink.closest("a")).toBeTruthy()
    expect(groupLink.closest("a")?.getAttribute("href")).toBe(
      "/correlation/groups/sg-001-aaaa-bbbb-cccc-dddd"
    )

    // Derived confidence percentage
    expect(screen.getByText("88%")).toBeTruthy()

    // Source count
    expect(screen.getByText(/2 sources/)).toBeTruthy()

    // Contributing source names (badge + table)
    expect(screen.getAllByText("fastnetmon").length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText("alertmanager").length).toBeGreaterThanOrEqual(1)

    // Corroboration badge
    expect(screen.getByText("Corroborated")).toBeTruthy()

    // Why explanation text
    expect(screen.getByText(/Corroboration achieved/)).toBeTruthy()
  })

  it.each([
    [0, "0%"], [null, "Unavailable"], [NaN, "Invalid"],
  ])("preserves source confidence %s in mitigation reasons", async (confidence, label) => {
    mockUseMitigation.mockReturnValue({ data: {
      ...correlatedMitigation,
      correlation: { ...correlatedMitigation.correlation, derived_confidence: 0 },
    }, mutate: vi.fn() })
    mockUseSignalGroupDetail.mockReturnValue({ data: {
      ...signalGroupDetailData,
      events: [{ ...signalGroupDetailData.events[0], confidence }],
    } })
    await renderPage()
    const row = within(screen.getByRole("table")).getByText("fastnetmon").closest("tr")!
    expect(within(row).getAllByRole("cell")[1]).toHaveTextContent(label)
    expect(screen.getByRole("meter", { name: "Confidence" })).toHaveAttribute("aria-valuenow", "0")
  })

  it("shows contributing sources table with confidence and weight from signal group detail", async () => {
    mockUseMitigation.mockReturnValue({
      data: correlatedMitigation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: signalGroupDetailData,
      isLoading: false,
      error: null,
    })

    await renderPage()

    // Table headers
    expect(screen.getByText("Contributing sources")).toBeTruthy()
    expect(screen.getByText("Confidence")).toBeTruthy()
    expect(screen.getByText("Weight")).toBeTruthy()

    // fastnetmon: 95% confidence, 1.0 weight
    expect(screen.getByText("95%")).toBeTruthy()
    expect(screen.getByText("1.0")).toBeTruthy()

    // alertmanager: 80% confidence, 0.8 weight
    expect(screen.getByText("80%")).toBeTruthy()
    expect(screen.getByText("0.8")).toBeTruthy()
  })

  it("shows signal group link that navigates to /correlation/groups/{id}", async () => {
    mockUseMitigation.mockReturnValue({
      data: correlatedMitigation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: signalGroupDetailData,
      isLoading: false,
      error: null,
    })

    await renderPage()

    const link = screen.getByText("sg-001-aaaa-bbbb-cccc-dddd")
    const anchor = link.closest("a")
    expect(anchor?.getAttribute("href")).toBe(
      "/correlation/groups/sg-001-aaaa-bbbb-cccc-dddd"
    )
  })

  it("shows muted message for non-correlated mitigation", async () => {
    mockUseMitigation.mockReturnValue({
      data: nonCorrelatedMitigation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
    })

    await renderPage()

    expect(screen.getByTestId("no-correlation-card")).toBeTruthy()
    expect(screen.getByText(/Single-source mitigation/)).toBeTruthy()
    expect(screen.queryByTestId("correlation-card")).toBeNull()
  })

  it("hides correlation section when mitigation has no correlation field", async () => {
    const mitigationWithoutCorrelation = { ...baseMitigation }
    // No correlation field at all
    mockUseMitigation.mockReturnValue({
      data: mitigationWithoutCorrelation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
    })

    await renderPage()

    expect(screen.getByTestId("no-correlation-card")).toBeTruthy()
    expect(screen.getByText(/Single-source mitigation/)).toBeTruthy()
  })

  it("renders pending corroboration badge when not met", async () => {
    const pendingCorrelation = {
      ...baseMitigation,
      correlation: {
        signal_group_id: "sg-002",
        derived_confidence: 0.45,
        source_count: 1,
        corroboration_met: false,
        contributing_sources: ["fastnetmon"],
        explanation: "Awaiting additional sources for corroboration.",
      },
    }

    mockUseMitigation.mockReturnValue({
      data: pendingCorrelation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
    })

    await renderPage()

    expect(screen.getByTestId("correlation-card")).toBeTruthy()
    expect(screen.getByText("Pending")).toBeTruthy()
    expect(screen.queryByText("Corroborated")).toBeNull()
  })

  it("passes signal_group_id to useSignalGroupDetail hook", async () => {
    mockUseMitigation.mockReturnValue({
      data: correlatedMitigation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: signalGroupDetailData,
      isLoading: false,
      error: null,
    })

    await renderPage()

    expect(mockUseSignalGroupDetail).toHaveBeenCalledWith(
      "sg-001-aaaa-bbbb-cccc-dddd"
    )
  })

  it("passes null to useSignalGroupDetail when no correlation", async () => {
    mockUseMitigation.mockReturnValue({
      data: nonCorrelatedMitigation,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseSignalGroupDetail.mockReturnValue({
      data: null,
      isLoading: false,
      error: null,
    })

    await renderPage()

    expect(mockUseSignalGroupDetail).toHaveBeenCalledWith(null)
  })
})

describe("Mitigation Detail – load failures", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockUseConfigInventory.mockReturnValue({ data: null })
    mockUseSignalGroupDetail.mockReturnValue({ data: undefined, isLoading: false, error: null })
  })

  it("shows a retryable error rather than not-found when the request fails", async () => {
    const mutate = vi.fn()
    mockUseMitigation.mockReturnValue({ data: undefined, error: new Error("API error 500: database unavailable"), isLoading: false, mutate })

    await renderPage()

    expect(screen.getByRole("alert").textContent).toContain("Unable to load this mitigation")
    expect(screen.queryByText("Mitigation not found")).toBeNull()
    screen.getByRole("button", { name: "Retry" }).click()
    expect(mutate).toHaveBeenCalled()
  })

  it("keeps not-found for a 404", async () => {
    mockUseMitigation.mockReturnValue({ data: undefined, error: new Error("API error 404: not found"), isLoading: false, mutate: vi.fn() })

    await renderPage()

    expect(screen.getByText("Mitigation not found")).toBeTruthy()
    expect(screen.queryByRole("alert")).toBeNull()
  })
})
