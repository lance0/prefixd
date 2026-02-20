import { describe, it, expect, vi, beforeEach } from "vitest"
import { renderHook, act, waitFor } from "@testing-library/react"
import type { ReactNode } from "react"

const mockGetCurrentUser = vi.fn()
const mockLogin = vi.fn()
const mockLogout = vi.fn()

vi.mock("@/lib/auth", () => ({
  getCurrentUser: () => mockGetCurrentUser(),
  login: (creds: any) => mockLogin(creds),
  logout: () => mockLogout(),
}))

import { AuthProvider, useAuth } from "@/hooks/use-auth"

function wrapper({ children }: { children: ReactNode }) {
  return <AuthProvider>{children}</AuthProvider>
}

describe("useAuth", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockGetCurrentUser.mockResolvedValue(null)
    mockLogin.mockResolvedValue({ id: "1", username: "admin", role: "admin" })
    mockLogout.mockResolvedValue(undefined)
  })

  it("throws when used outside AuthProvider", () => {
    expect(() => {
      renderHook(() => useAuth())
    }).toThrow("useAuth must be used within an AuthProvider")
  })

  it("starts loading then settles with no user", async () => {
    const { result } = renderHook(() => useAuth(), { wrapper })

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.operator).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
  })

  it("login sets operator", async () => {
    const { result } = renderHook(() => useAuth(), { wrapper })

    await waitFor(() => expect(result.current.isLoading).toBe(false))

    await act(async () => {
      await result.current.login({ username: "admin", password: "pass" })
    })

    expect(result.current.operator).toEqual({ id: "1", username: "admin", role: "admin" })
    expect(result.current.isAuthenticated).toBe(true)
  })

  it("logout clears operator", async () => {
    mockGetCurrentUser.mockResolvedValue({ id: "1", username: "admin", role: "admin" })
    const { result } = renderHook(() => useAuth(), { wrapper })

    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))

    await act(async () => {
      await result.current.logout()
    })

    expect(result.current.operator).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
  })

  it("clears operator on auth-expired event", async () => {
    mockGetCurrentUser.mockResolvedValue({ id: "1", username: "admin", role: "admin" })
    const { result } = renderHook(() => useAuth(), { wrapper })

    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))

    act(() => {
      window.dispatchEvent(new Event("prefixd:auth-expired"))
    })

    expect(result.current.operator).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
  })
})
