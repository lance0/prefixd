import { afterEach, describe, expect, it, vi } from "vitest"
import { login, getCurrentUser } from "@/lib/auth"

const originalFetch = globalThis.fetch

function mockFetch(body: unknown, status: number) {
  const fetchMock = vi.fn(async () => ({
    ok: status < 400,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
  }))
  globalThis.fetch = fetchMock as unknown as typeof fetch
  return fetchMock
}

afterEach(() => {
  globalThis.fetch = originalFetch
})

describe("auth API responses", () => {
  // Backend sends a flat snake_case operator (/v1/auth/login, /v1/auth/me).
  // Reading `data.operator` left the dashboard with `undefined`, which hid the
  // user menu (no sign-out) and dropped the role for permission checks.
  const wire = { operator_id: "abc-123", username: "admin", role: "admin" }

  it("maps the login response to an Operator", async () => {
    mockFetch(wire, 200)

    await expect(login({ username: "admin", password: "pw" })).resolves.toEqual({
      id: "abc-123",
      username: "admin",
      role: "admin",
    })
  })

  it("maps the current-user response to an Operator", async () => {
    mockFetch(wire, 200)

    await expect(getCurrentUser()).resolves.toEqual({
      id: "abc-123",
      username: "admin",
      role: "admin",
    })
  })

  it("returns null for an unauthenticated session", async () => {
    mockFetch({ error: "unauthorized" }, 401)

    await expect(getCurrentUser()).resolves.toBeNull()
  })

  it("returns null when the operator payload is not the documented shape", async () => {
    mockFetch({ username: "admin", role: "admin" }, 200)

    await expect(getCurrentUser()).resolves.toBeNull()
  })
})
