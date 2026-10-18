import { describe, it, expect } from "vitest"
import { renderHook, waitFor } from "@testing-library/react"
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
  it("grants all permissions when auth is disabled", async () => {
    session("none", null)

    const perms = await settledPermissions()

    expect(perms.settled).toBe(true)
    expect(perms.authDisabled).toBe(true)
    expect(perms.isAdmin).toBe(true)
    expect(perms.isOperator).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canManageUsers).toBe(true)
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
    expect(perms.canManageUsers).toBe(true)
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
    expect(perms.canManageUsers).toBe(false)
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
    expect(perms.canManageUsers).toBe(false)
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
    expect(perms.canManageUsers).toBe(false)
  })
})
