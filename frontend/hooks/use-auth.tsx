"use client"

import { useState, useEffect, useCallback, useMemo, createContext, useContext, type ReactNode } from "react"
import { type Operator, type LoginRequest, login as apiLogin, logout as apiLogout, getCurrentUser } from "@/lib/auth"

interface AuthContextValue {
  operator: Operator | null
  isLoading: boolean
  isAuthenticated: boolean
  login: (credentials: LoginRequest) => Promise<void>
  logout: () => Promise<void>
  refresh: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [operator, setOperator] = useState<Operator | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const refresh = useCallback(async () => {
    try {
      const user = await getCurrentUser()
      setOperator(user)
    } catch {
      setOperator(null)
    }
  }, [])

  useEffect(() => {
    refresh().finally(() => setIsLoading(false))
  }, [refresh])

  const login = useCallback(async (credentials: LoginRequest) => {
    const user = await apiLogin(credentials)
    setOperator(user)
  }, [])

  const logout = useCallback(async () => {
    await apiLogout()
    setOperator(null)
  }, [])

  // Memoize context value to prevent unnecessary re-renders (rerender-derived-state)
  const value = useMemo(
    () => ({
      operator,
      isLoading,
      isAuthenticated: operator !== null,
      login,
      logout,
      refresh,
    }),
    [operator, isLoading, login, logout, refresh]
  )

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}
