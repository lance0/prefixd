// Use relative URL to proxy through Next.js API route
const API_BASE = "/api/prefixd"

export type OperatorRole = "admin" | "operator" | "viewer"

export interface Operator {
  id: string
  username: string
  role: OperatorRole
}

export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  operator: Operator
}

export interface AuthState {
  operator: Operator | null
  isLoading: boolean
  isAuthenticated: boolean
}

export async function login(credentials: LoginRequest): Promise<Operator> {
  const res = await fetch(`${API_BASE}/v1/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "include", // Send cookies
    body: JSON.stringify(credentials),
  })

  if (!res.ok) {
    if (res.status === 401) {
      throw new Error("Invalid username or password")
    }
    const error = await res.text()
    throw new Error(`Login failed: ${error}`)
  }

  const data: LoginResponse = await res.json()
  return data.operator
}

export async function logout(): Promise<void> {
  await fetch(`${API_BASE}/v1/auth/logout`, {
    method: "POST",
    credentials: "include",
  })
}

export async function getCurrentUser(): Promise<Operator | null> {
  try {
    const res = await fetch(`${API_BASE}/v1/auth/me`, {
      credentials: "include",
    })

    if (!res.ok) {
      if (res.status === 401) {
        return null
      }
      throw new Error("Failed to get current user")
    }

    const data: { operator: Operator } = await res.json()
    return data.operator
  } catch {
    return null
  }
}
