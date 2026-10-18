import { describe, it, expect, beforeEach } from "vitest"
import { renderHook, act, waitFor } from "@testing-library/react"
import { useAuth } from "@/hooks/use-auth"
import { appWrapper, failure, json, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const admin = { operator_id: "1", username: "admin", role: "admin" } as const

function signedIn(operator: boolean) {
  controller.route("GET", "/v1/auth/me", () => operator ? json(admin) : failure(401, "unauthorized"))
}

describe("useAuth", () => {
  beforeEach(() => {
    signedIn(false)
    controller.route("POST", "/v1/auth/login", () => json(admin))
    controller.route("POST", "/v1/auth/logout", () => new Response(null, { status: 204 }))
  })

  it("throws when used outside AuthProvider", () => {
    expect(() => {
      renderHook(() => useAuth())
    }).toThrow("useAuth must be used within an AuthProvider")
  })

  it("starts loading then settles with no user", async () => {
    const { result } = renderHook(() => useAuth(), appWrapper())

    expect(result.current.isLoading).toBe(true)

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false)
    })

    expect(result.current.operator).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
  })

  it("login sets operator", async () => {
    const { result } = renderHook(() => useAuth(), appWrapper())

    await waitFor(() => expect(result.current.isLoading).toBe(false))

    await act(async () => {
      await result.current.login({ username: "admin", password: "pass" })
    })

    expect(JSON.parse(controller.calls("POST", "/v1/auth/login")[0].body ?? "")).toEqual({ username: "admin", password: "pass" })
    expect(result.current.operator).toEqual({ id: "1", username: "admin", role: "admin" })
    expect(result.current.isAuthenticated).toBe(true)
  })

  it("logout clears operator", async () => {
    signedIn(true)
    const { result } = renderHook(() => useAuth(), appWrapper())

    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))

    await act(async () => {
      await result.current.logout()
    })

    expect(controller.calls("POST", "/v1/auth/logout")).toHaveLength(1)
    expect(result.current.operator).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
  })

  it("clears operator on auth-expired event", async () => {
    signedIn(true)
    const { result, router } = renderHookWithRouter()

    await waitFor(() => expect(result.current.isAuthenticated).toBe(true))

    act(() => {
      window.dispatchEvent(new Event("prefixd:auth-expired"))
    })

    expect(result.current.operator).toBeNull()
    expect(result.current.isAuthenticated).toBe(false)
    expect(router.push).toHaveBeenCalledWith("/login")
  })
})

function renderHookWithRouter() {
  const { wrapper, handles } = appWrapper()

  return { ...renderHook(() => useAuth(), { wrapper }), router: handles.router }
}
