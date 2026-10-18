import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import LoginPage from "@/app/login/page"

const mock = vi.hoisted(() => ({
  health: { auth_mode: "credentials" } as { auth_mode: string } | undefined,
  healthLoading: false,
  authLoading: false,
  authenticated: false,
  login: vi.fn(),
  push: vi.fn(),
}))

vi.mock("@/hooks/use-auth", () => ({ useAuth: () => ({ login: mock.login, isAuthenticated: mock.authenticated, isLoading: mock.authLoading }) }))

vi.mock("@/hooks/use-api", () => ({ useHealth: () => ({ data: mock.health, isLoading: mock.healthLoading }) }))

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: mock.push }) }))

afterEach(cleanup)

beforeEach(() => {
  vi.clearAllMocks()
  mock.health = { auth_mode: "credentials" }
  mock.healthLoading = false
  mock.authLoading = false
  mock.authenticated = false
  mock.login.mockResolvedValue(undefined)
})

describe("login authentication mode", () => {
  it.each([
    { mode: undefined, healthLoading: true, authLoading: false },
    { mode: undefined, healthLoading: false, authLoading: false },
    { mode: "credentials", healthLoading: false, authLoading: true },
  ])("has no actionable form while mode is $mode and loading is $healthLoading/$authLoading", ({ mode, healthLoading, authLoading }) => {
    mock.health = mode ? { auth_mode: mode } : undefined
    mock.healthLoading = healthLoading
    mock.authLoading = authLoading
    render(<LoginPage />)
    expect(screen.queryByRole("textbox", { name: "Username" })).not.toBeInTheDocument()
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    expect(screen.getByRole("status")).toBeInTheDocument()
    expect(mock.login).not.toHaveBeenCalled()
    expect(mock.push).not.toHaveBeenCalled()
  })

  it.each([false, true])("redirects anonymous mode without showing a form (retained login=%s)", async (authenticated) => {
    mock.health = { auth_mode: "none" }
    mock.authenticated = authenticated
    render(<LoginPage />)
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    await waitFor(() => expect(mock.push).toHaveBeenCalledWith("/"))
    expect(mock.login).not.toHaveBeenCalled()
  })

  it.each(["credentials", "bearer"])("preserves password sign in for %s mode", async (mode) => {
    mock.health = { auth_mode: mode }
    render(<LoginPage />)
    fireEvent.change(screen.getByRole("textbox", { name: "Username" }), { target: { value: "alice" } })
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct-password" } })
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }))
    await waitFor(() => expect(mock.login).toHaveBeenCalledWith({ username: "alice", password: "correct-password" }))
    await waitFor(() => expect(mock.push).toHaveBeenCalledWith("/"))
  })

  it("keeps the form hidden until a known mode resolves, even with a retained operator", () => {
    mock.authenticated = true
    mock.health = undefined
    render(<LoginPage />)
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    expect(screen.getByRole("status")).toHaveTextContent("Unable to determine authentication mode")
    expect(mock.push).not.toHaveBeenCalled()
  })

  it("preserves the already authenticated credentials redirect", async () => {
    mock.authenticated = true
    render(<LoginPage />)
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    await waitFor(() => expect(mock.push).toHaveBeenCalledWith("/"))
  })
})
