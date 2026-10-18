import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { UserMenu } from "@/components/user-menu"

const mock = vi.hoisted(() => ({
  health: { auth_mode: "credentials" } as { auth_mode: string } | undefined,
  healthLoading: false,
  authLoading: false,
  operator: { id: "operator-1", username: "alice", role: "admin" } as { id: string; username: string; role: string } | null,
  logout: vi.fn(),
  push: vi.fn(),
}))

vi.mock("@/hooks/use-auth", () => ({ useAuth: () => ({ operator: mock.operator, isLoading: mock.authLoading, logout: mock.logout }) }))
vi.mock("@/hooks/use-api", () => ({ useHealth: () => ({ data: mock.health, isLoading: mock.healthLoading }) }))
vi.mock("next/navigation", () => ({ useRouter: () => ({ push: mock.push }) }))
vi.mock("@/components/dashboard/notification-preferences", () => ({ NotificationPreferencesPanel: () => <p>Preferences editor</p> }))

afterEach(cleanup)
beforeEach(() => {
  vi.clearAllMocks()
  mock.health = { auth_mode: "credentials" }
  mock.healthLoading = false
  mock.authLoading = false
  mock.operator = { id: "operator-1", username: "alice", role: "admin" }
  mock.logout.mockResolvedValue(undefined)
})

describe("operator menu authentication mode", () => {
  it.each([
    { mode: "none", healthLoading: false, authLoading: false },
    { mode: undefined, healthLoading: true, authLoading: false },
    { mode: undefined, healthLoading: false, authLoading: false },
    { mode: "credentials", healthLoading: false, authLoading: true },
  ])("hides a retained named operator when mode is $mode and loading is $healthLoading/$authLoading", ({ mode, healthLoading, authLoading }) => {
    mock.health = mode ? { auth_mode: mode } : undefined
    mock.healthLoading = healthLoading
    mock.authLoading = authLoading
    render(<UserMenu />)
    expect(screen.queryByRole("button", { name: "Operator menu for alice" })).not.toBeInTheDocument()
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
    expect(screen.queryByText("Sign out")).not.toBeInTheDocument()
    expect(screen.queryByText("Preferences editor")).not.toBeInTheDocument()
  })

  it("removes an open named preferences dialog when mode becomes none", async () => {
    const view = render(<UserMenu />)
    fireEvent.keyDown(screen.getByRole("button", { name: "Operator menu for alice" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("menuitem", { name: "Notifications" }))
    expect(await screen.findByRole("dialog", { name: "Notification preferences" })).toBeInTheDocument()
    expect(screen.getByText("Preferences editor")).toBeInTheDocument()
    mock.health = { auth_mode: "none" }
    view.rerender(<UserMenu />)
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
    expect(mock.logout).not.toHaveBeenCalled()
  })

  it.each(["credentials", "bearer"])("preserves named sign out in %s mode", async (mode) => {
    mock.health = { auth_mode: mode }
    render(<UserMenu />)
    fireEvent.keyDown(screen.getByRole("button", { name: "Operator menu for alice" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("menuitem", { name: "Sign out" }))
    await waitFor(() => expect(mock.logout).toHaveBeenCalledOnce())
    await waitFor(() => expect(mock.push).toHaveBeenCalledWith("/login"))
  })

  it("has no named controls without an authenticated operator", () => {
    mock.operator = null
    render(<UserMenu />)
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
  })
})
