import { describe, it, expect, vi, beforeEach } from "vitest"
import { render, screen } from "@testing-library/react"

// ─── Mocks ──────────────────────────────────────────────

// Mock next/navigation
const mockPush = vi.fn()
const mockReplace = vi.fn()
const mockSearchParams = new URLSearchParams()

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: mockPush, replace: mockReplace }),
  usePathname: () => "/correlation",
  useSearchParams: () => mockSearchParams,
}))

// Mock next/link
vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: { children: React.ReactNode; href: string }) => (
    <a href={href} {...props}>{children}</a>
  ),
}))

// Mock sonner
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

// Mock SWR config
vi.mock("swr", async () => {
  const actual = await vi.importActual("swr")

  return { ...actual }
})

// Mock use-api hooks
const mockUseSignalSources = vi.fn()
const mockUseSignalGroups = vi.fn()
const mockUseSignalGroupsPaginated = vi.fn()
const mockUseCorrelationConfig = vi.fn()
const mockUseConfigPlaybooks = vi.fn()
const mockUseOpenSignalGroupCount = vi.fn()

vi.mock("@/hooks/use-api", () => ({
  useSignalSources: () => mockUseSignalSources(),
  useSignalGroups: () => mockUseSignalGroups(),
  useSignalGroupsPaginated: () => mockUseSignalGroupsPaginated(),
  useCorrelationConfig: () => mockUseCorrelationConfig(),
  useConfigPlaybooks: () => mockUseConfigPlaybooks(),
  useOpenSignalGroupCount: () => mockUseOpenSignalGroupCount(),
  useHealth: () => ({ data: { auth_mode: "none" }, isLoading: false }),
  useStats: () => ({ data: { total_active: 3 } }),
}))

// Mock use-permissions
const mockPermissions = vi.fn()

vi.mock("@/hooks/use-permissions", () => ({
  usePermissions: () => mockPermissions(),
}))

// Mock use-auth
vi.mock("@/hooks/use-auth", () => ({
  useAuth: () => ({ operator: { role: "admin" }, isLoading: false }),
}))

// Mock use-keyboard-shortcuts
vi.mock("@/hooks/use-keyboard-shortcuts", () => ({
  useKeyboardShortcuts: () => {},
}))

// ─── Imports ────────────────────────────────────────────

import { SignalsTab } from "@/components/dashboard/correlation/signals-tab"
import { GroupsTab } from "@/components/dashboard/correlation/groups-tab"
import { ConfigTab } from "@/components/dashboard/correlation/config-tab"

// ─── Sample Data ────────────────────────────────────────

const sampleSources = [
  { name: "fastnetmon", type: "detector", weight: 1.0, last_seen: new Date().toISOString(), event_count: 42, healthy: true },
  { name: "alertmanager", type: "telemetry", weight: 0.8, last_seen: null, event_count: 0, healthy: false },
]

const sampleGroups = [
  {
    group_id: "grp-1",
    victim_ip: "203.0.113.10",
    vector: "udp_flood",
    created_at: new Date(Date.now() - 300000).toISOString(),
    window_expires_at: new Date(Date.now() + 300000).toISOString(),
    derived_confidence: 0.88,
    source_count: 2,
    status: "open" as const,
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
    status: "expired" as const,
    corroboration_met: false,
  },
]

const sampleConfig = {
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

const samplePlaybooks = {
  playbooks: [{ name: "udp_flood_default", match: { vector: "udp_flood" }, steps: [] }],
  total_playbooks: 1,
  loaded_at: new Date().toISOString(),
}

// ─── Setup ──────────────────────────────────────────────

beforeEach(() => {
  vi.clearAllMocks()

  mockPermissions.mockReturnValue({
    settled: true,
    authDisabled: true,
    isAdmin: true,
    isOperator: true,
    isViewer: true,
    canWithdraw: true,
    canManageSafelist: true,
    canManageUsers: true,
    canReloadConfig: true,
    canEditPlaybooks: true,
    canEditAlerting: true,
    role: "admin",
  })
})

// ─── Tests ──────────────────────────────────────────────

describe("SignalsTab", () => {
  it("renders source status cards with health indicators", () => {
    mockUseSignalSources.mockReturnValue({ data: sampleSources, error: null, isLoading: false })
    mockUseSignalGroups.mockReturnValue({
      data: { groups: sampleGroups, count: 2, next_cursor: null, has_more: false },
      error: null,
      isLoading: false,
    })

    render(<SignalsTab />)

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

  it("preserves zero, missing and invalid confidence in recent signals", () => {
    mockUseSignalSources.mockReturnValue({ data: sampleSources })
    mockUseSignalGroups.mockReturnValue({ data: { groups: [0.95, 0, null, NaN].map((confidence, index) => ({
      ...sampleGroups[0], group_id: `group-${index}`, derived_confidence: confidence,
    })) } })
    render(<SignalsTab />)

    for (const label of ["95%", "0%", "Unavailable", "Invalid"]) {
      expect(screen.getByText(label)).toBeInTheDocument()
    }
  })

  it("renders loading skeletons while fetching", () => {
    mockUseSignalSources.mockReturnValue({ data: undefined, error: null, isLoading: true })
    mockUseSignalGroups.mockReturnValue({ data: undefined, error: null, isLoading: true })

    const { container } = render(<SignalsTab />)

    // Skeleton elements are rendered
    const skeletons = container.querySelectorAll("[data-slot='skeleton']")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders empty state when no sources configured", () => {
    mockUseSignalSources.mockReturnValue({ data: [], error: null, isLoading: false })
    mockUseSignalGroups.mockReturnValue({
      data: { groups: [], count: 0, next_cursor: null, has_more: false },
      error: null,
      isLoading: false,
    })

    render(<SignalsTab />)

    expect(screen.getByText("No signal sources configured")).toBeInTheDocument()
  })

  it("renders error state on fetch failure", () => {
    mockUseSignalSources.mockReturnValue({ data: undefined, error: new Error("fail"), isLoading: false })
    mockUseSignalGroups.mockReturnValue({
      data: { groups: [], count: 0, next_cursor: null, has_more: false },
      error: null,
      isLoading: false,
    })

    render(<SignalsTab />)

    expect(screen.getByText("Unable to load signal sources")).toBeInTheDocument()
  })

  it("renders recent signals table with group data", () => {
    mockUseSignalSources.mockReturnValue({ data: sampleSources, error: null, isLoading: false })
    mockUseSignalGroups.mockReturnValue({
      data: { groups: sampleGroups, count: 2, next_cursor: null, has_more: false },
      error: null,
      isLoading: false,
    })

    render(<SignalsTab />)

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
  it("renders filterable group list", () => {
    mockUseSignalGroupsPaginated.mockReturnValue({
      data: [{ groups: sampleGroups, count: 2, next_cursor: null, has_more: false }],
      error: null,
      isLoading: false,
      isValidating: false,
      size: 1,
      setSize: vi.fn(),
    })

    render(<GroupsTab />)

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
    [NaN, "Invalid", "text-muted-foreground"],
  ])("classifies confidence %s before rounding its label", (confidence, label, color) => {
    mockUseSignalGroupsPaginated.mockReturnValue({
      data: [{ groups: [{ ...sampleGroups[0], derived_confidence: confidence }], count: 1, next_cursor: null, has_more: false }],
      size: 1, setSize: vi.fn(),
    })
    render(<GroupsTab />)
    expect(screen.getByText(label)).toHaveClass(color)
  })

  it("renders empty state with clear-filters option", () => {
    mockUseSignalGroupsPaginated.mockReturnValue({
      data: [{ groups: [], count: 0, next_cursor: null, has_more: false }],
      error: null,
      isLoading: false,
      isValidating: false,
      size: 1,
      setSize: vi.fn(),
    })

    render(<GroupsTab />)

    expect(screen.getByText("No signal groups yet")).toBeInTheDocument()
  })

  it("renders loading skeletons", () => {
    mockUseSignalGroupsPaginated.mockReturnValue({
      data: undefined,
      error: null,
      isLoading: true,
      isValidating: false,
      size: 1,
      setSize: vi.fn(),
    })

    const { container } = render(<GroupsTab />)

    const skeletons = container.querySelectorAll("[data-slot='skeleton']")
    expect(skeletons.length).toBeGreaterThan(0)
  })

  it("renders error state", () => {
    mockUseSignalGroupsPaginated.mockReturnValue({
      data: undefined,
      error: new Error("fail"),
      isLoading: false,
      isValidating: false,
      size: 1,
      setSize: vi.fn(),
    })

    render(<GroupsTab />)

    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load signal groups")
    expect(screen.getByRole("button", { name: "Retry" })).toBeInTheDocument()
    expect(screen.queryByText("No signal groups yet")).not.toBeInTheDocument()
  })

  it("shows Load More button when has_more is true", () => {
    mockUseSignalGroupsPaginated.mockReturnValue({
      data: [{ groups: sampleGroups, count: 2, next_cursor: "abc", has_more: true }],
      error: null,
      isLoading: false,
      isValidating: false,
      size: 1,
      setSize: vi.fn(),
    })

    render(<GroupsTab />)

    expect(screen.getByText("Load more")).toBeInTheDocument()
  })
})

describe("ConfigTab", () => {
  it("renders correlation settings form (admin)", () => {
    mockUseCorrelationConfig.mockReturnValue({
      data: sampleConfig,
      error: null,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseConfigPlaybooks.mockReturnValue({ data: samplePlaybooks })

    render(<ConfigTab />)

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

  it("shows read-only message for non-admin", () => {
    mockPermissions.mockReturnValue({
      settled: true,
      authDisabled: false,
      isAdmin: false,
      isOperator: true,
      isViewer: true,
      canWithdraw: true,
      canManageSafelist: false,
      canManageUsers: false,
      canReloadConfig: false,
      canEditPlaybooks: false,
      canEditAlerting: false,
      role: "operator",
    })

    mockUseCorrelationConfig.mockReturnValue({
      data: sampleConfig,
      error: null,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseConfigPlaybooks.mockReturnValue({ data: samplePlaybooks })

    render(<ConfigTab />)

    expect(screen.getByText("Admin access required to edit settings")).toBeInTheDocument()
    // Add Source button should not be present for non-admin
    expect(screen.queryByText("Add source")).not.toBeInTheDocument()
  })

  it("renders per-playbook overrides with link to Playbooks tab", () => {
    mockUseCorrelationConfig.mockReturnValue({
      data: sampleConfig,
      error: null,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseConfigPlaybooks.mockReturnValue({ data: samplePlaybooks })

    render(<ConfigTab />)

    expect(screen.getByText("Per-playbook overrides")).toBeInTheDocument()
    expect(screen.getByText("udp_flood_default")).toBeInTheDocument()
    expect(screen.getByText("Edit in playbooks")).toBeInTheDocument()
  })

  it("renders source CRUD cards for admin", () => {
    mockUseCorrelationConfig.mockReturnValue({
      data: sampleConfig,
      error: null,
      isLoading: false,
      mutate: vi.fn(),
    })
    mockUseConfigPlaybooks.mockReturnValue({ data: samplePlaybooks })

    render(<ConfigTab />)

    // Source cards
    expect(screen.getByText("fastnetmon")).toBeInTheDocument()
    expect(screen.getByText("alertmanager")).toBeInTheDocument()

    // Edit and Remove buttons visible for admin
    expect(screen.getAllByText("Edit").length).toBe(2)
    expect(screen.getAllByText("Remove").length).toBe(2)
  })

  it("renders loading state", () => {
    mockUseCorrelationConfig.mockReturnValue({
      data: undefined,
      error: null,
      isLoading: true,
      mutate: vi.fn(),
    })
    mockUseConfigPlaybooks.mockReturnValue({ data: null })

    const { container } = render(<ConfigTab />)

    const skeletons = container.querySelectorAll("[data-slot='skeleton']")
    expect(skeletons.length).toBeGreaterThan(0)
  })
})
