"use client"

import { useAuth } from "./use-auth"
import { useHealth } from "./use-api"

export function usePermissions() {
  const { operator, isLoading: authLoading } = useAuth()
  const { data: health, isLoading: healthLoading, error: healthError } = useHealth()

  const role = operator?.role
  // A completed failure stays settled while SWR retries without cached data.
  const settled = !authLoading && (!healthLoading || Boolean(healthError))

  // Deny-by-default: no permissions until both health and auth have resolved.
  // Backend reports auth_mode in /v1/health. When "none", all operations
  // are allowed -- grant full permissions to match backend behavior.
  // This is defense-in-depth only; backend enforces auth on all endpoints.
  const authDisabled = settled && health?.auth_mode === "none"

  return {
    // True once both health and auth state have resolved
    settled,

    // Whether backend auth is disabled (auth: none)
    authDisabled,

    // Role checks (deny-by-default until settled)
    isAdmin: authDisabled || role === "admin",
    isOperator: authDisabled || role === "operator" || role === "admin",
    isViewer: authDisabled || role === "viewer" || role === "operator" || role === "admin",

    // Permission checks (deny-by-default until settled)
    canWithdraw: authDisabled || role === "admin" || role === "operator",
    canManageSafelist: authDisabled || role === "admin",
    canManageUsers: authDisabled || role === "admin",
    canReloadConfig: authDisabled || role === "admin",
    canEditPlaybooks: authDisabled || role === "admin",
    canEditAlerting: authDisabled || role === "admin",
    // Identity management (tokens, operator accounts, passwords) needs a signed-in
    // Admin session: the controller refuses `none` mode and mTLS clients with 403.
    canManageIdentity: settled && health?.auth_mode === "credentials" && role === "admin",

    // Current role (for display)
    role: authDisabled ? "admin" : role,
  }
}
