import { describe, it, expect, vi, beforeEach } from "vitest"

const mockUseAuth = vi.fn()
const mockUseHealth = vi.fn()

vi.mock("@/hooks/use-auth", () => ({ useAuth: () => mockUseAuth() }))
vi.mock("@/hooks/use-api", () => ({ useHealth: () => mockUseHealth() }))

import { usePermissions } from "@/hooks/use-permissions"

describe("usePermissions", () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it("grants all permissions when auth is disabled", () => {
    mockUseAuth.mockReturnValue({ operator: null, isLoading: false })
    mockUseHealth.mockReturnValue({ data: { auth_mode: "none" }, isLoading: false })

    const perms = usePermissions()

    expect(perms.settled).toBe(true)
    expect(perms.authDisabled).toBe(true)
    expect(perms.isAdmin).toBe(true)
    expect(perms.isOperator).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canManageUsers).toBe(true)
    expect(perms.canReloadConfig).toBe(true)
    expect(perms.role).toBe("admin")
  })

  it("grants full permissions for admin role", () => {
    mockUseAuth.mockReturnValue({ operator: { role: "admin" }, isLoading: false })
    mockUseHealth.mockReturnValue({ data: { auth_mode: "credentials" }, isLoading: false })

    const perms = usePermissions()

    expect(perms.settled).toBe(true)
    expect(perms.isAdmin).toBe(true)
    expect(perms.isOperator).toBe(true)
    expect(perms.isViewer).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canManageUsers).toBe(true)
    expect(perms.canManageSafelist).toBe(true)
    expect(perms.canReloadConfig).toBe(true)
  })

  it("grants operator permissions but not admin", () => {
    mockUseAuth.mockReturnValue({ operator: { role: "operator" }, isLoading: false })
    mockUseHealth.mockReturnValue({ data: { auth_mode: "credentials" }, isLoading: false })

    const perms = usePermissions()

    expect(perms.isAdmin).toBe(false)
    expect(perms.isOperator).toBe(true)
    expect(perms.isViewer).toBe(true)
    expect(perms.canWithdraw).toBe(true)
    expect(perms.canManageUsers).toBe(false)
    expect(perms.canManageSafelist).toBe(false)
    expect(perms.canReloadConfig).toBe(false)
  })

  it("denies write permissions for viewer role", () => {
    mockUseAuth.mockReturnValue({ operator: { role: "viewer" }, isLoading: false })
    mockUseHealth.mockReturnValue({ data: { auth_mode: "credentials" }, isLoading: false })

    const perms = usePermissions()

    expect(perms.isAdmin).toBe(false)
    expect(perms.isOperator).toBe(false)
    expect(perms.isViewer).toBe(true)
    expect(perms.canWithdraw).toBe(false)
    expect(perms.canManageUsers).toBe(false)
    expect(perms.canManageSafelist).toBe(false)
    expect(perms.canReloadConfig).toBe(false)
  })

  it("denies everything while still loading (deny-by-default)", () => {
    mockUseAuth.mockReturnValue({ operator: null, isLoading: true })
    mockUseHealth.mockReturnValue({ data: undefined, isLoading: true })

    const perms = usePermissions()

    expect(perms.settled).toBe(false)
    expect(perms.authDisabled).toBe(false)
    expect(perms.isAdmin).toBe(false)
    expect(perms.isOperator).toBe(false)
    expect(perms.isViewer).toBe(false)
    expect(perms.canWithdraw).toBe(false)
    expect(perms.canManageUsers).toBe(false)
  })
})
