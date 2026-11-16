import { describe, it, expect } from "vitest"
import { act, renderHook, waitFor } from "@testing-library/react"
import { usePermissions } from "@/hooks/use-permissions"
import type { OperatorRole } from "@/lib/auth"
import { appWrapper, deferred, failure, json, operatorResponse, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

function session(authMode: string, role: OperatorRole | null) {
  controller.route("GET", "/v1/health", () => json({ status: "ok", version: "test", auth_mode: authMode }))
  controller.route("GET", "/v1/auth/me", () => role ? json(operatorResponse(role)) : failure(401, "unauthorized"))
}

async function settledPermissions() {
  const { result } = renderHook(() => usePermissions(), appWrapper())
  await waitFor(() => expect(result.current.settled).toBe(true))

  return result.current
}

describe("usePermissions", () => {
  it.each([null, "admin"] as const)("lets mTLS list operators but never manage identities (session %s)", async (role) => {
    session("mtls", role)

    const perms = await settledPermissions()

    expect(perms.canListOperators).toBe(true)
    expect(perms.canManageIdentity).toBe(false)
  })

  it("keeps identity management to an Admin session in credentials mode", async () => {
    session("credentials", "admin")
    expect((await settledPermissions()).canManageIdentity).toBe(true)
  })

  it("grants all permissions when auth is disabled", async () => {
    session("none", null)

    const perms = await settledPermissions()

    expect(perms.settled).toBe(true)
    expect(perms.authDisabled).toBe(true)
    expect(perms.isAdmin).toBe(true)
    expect(perms.isOperator).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canListOperators).toBe(true)
    expect(perms.canReloadConfig).toBe(true)
    expect(perms.role).toBe("admin")
  })

  it("grants full permissions for admin role", async () => {
    session("credentials", "admin")

    const perms = await settledPermissions()

    expect(perms.settled).toBe(true)
    expect(perms.isAdmin).toBe(true)
    expect(perms.isOperator).toBe(true)
    expect(perms.isViewer).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canListOperators).toBe(true)
    expect(perms.canManageSafelist).toBe(true)
    expect(perms.canReloadConfig).toBe(true)
  })

  it("grants operator permissions but not admin", async () => {
    session("credentials", "operator")

    const perms = await settledPermissions()

    expect(perms.isAdmin).toBe(false)
    expect(perms.isOperator).toBe(true)
    expect(perms.isViewer).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canListOperators).toBe(false)
    expect(perms.canManageSafelist).toBe(false)
    expect(perms.canReloadConfig).toBe(false)
  })

  it("denies write permissions for viewer role", async () => {
    session("credentials", "viewer")

    const perms = await settledPermissions()

    expect(perms.isAdmin).toBe(false)
    expect(perms.isOperator).toBe(false)
    expect(perms.isViewer).toBe(true)
    expect(perms.canWithdraw).toBe(false)
    expect(perms.canListOperators).toBe(false)
    expect(perms.canManageSafelist).toBe(false)
    expect(perms.canReloadConfig).toBe(false)
  })

  it("denies everything while still loading (deny-by-default)", async () => {
    controller.route("GET", "/v1/health", () => deferred<Response>().promise)
    controller.route("GET", "/v1/auth/me", () => deferred<Response>().promise)
    const { result } = renderHook(() => usePermissions(), appWrapper())
    await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))

    const perms = result.current

    expect(perms.settled).toBe(false)
    expect(perms.authDisabled).toBe(false)
    expect(perms.isAdmin).toBe(false)
    expect(perms.isOperator).toBe(false)
    expect(perms.isViewer).toBe(false)
    expect(perms.canWithdraw).toBe(false)
    expect(perms.canListOperators).toBe(false)
  })

  it.each(["health", "auth"])("waits for initial %s before allowing anonymous mode", async (pending) => {
    session("none", null)
    controller.route("GET", pending === "health" ? "/v1/health" : "/v1/auth/me", () => deferred<Response>().promise)
    const { result } = renderHook(() => usePermissions(), appWrapper())
    await act(async () => {})
    expect(result.current.settled).toBe(false)
    expect(result.current.authDisabled).toBe(false)
    expect(result.current.canWithdraw).toBe(false)
    expect(result.current.canListOperators).toBe(false)
  })

  it.each([null, "viewer", "operator", "admin"] as const)("keeps %s permissions unchanged during a failed-health retry", async (role) => {
    session("credentials", role)
    controller.route("GET", "/v1/health", () => failure(503))
    const { wrapper, handles } = appWrapper()
    const { result } = renderHook(() => usePermissions(), { wrapper })
    await waitFor(() => expect(result.current.settled).toBe(true))
    const permissions = result.current
    expect(permissions.authDisabled).toBe(false)
    expect(permissions.role).toBe(role ?? undefined)
    const response = deferred<Response>()
    controller.route("GET", "/v1/health", () => response.promise)
    let revalidation: Promise<unknown> | undefined
    await act(async () => { revalidation = handles.mutate()("health") })
    await waitFor(() => expect(controller.calls("GET", "/v1/health")).toHaveLength(2))
    expect(result.current).toEqual(permissions)
    await act(async () => {
      response.resolve(failure(503))
      await revalidation
    })
    expect(result.current).toEqual(permissions)
  })
})
