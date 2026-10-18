// @vitest-environment node

import { NextRequest } from "next/server"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

type ProxyRoutes = typeof import("@/app/api/prefixd/[...path]/route")

let routes: ProxyRoutes
const fetchMock = vi.fn<typeof fetch>()

beforeEach(async () => {
  vi.resetModules()
  vi.stubEnv("PREFIXD_API", "http://prefixd:8080")
  fetchMock.mockReset()
  fetchMock.mockResolvedValue(new Response("upstream response"))
  vi.stubGlobal("fetch", fetchMock)
  routes = await import("@/app/api/prefixd/[...path]/route")
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.unstubAllEnvs()
})

describe("dashboard API proxy boundary", () => {
  it.each(["GET", "POST", "PUT", "DELETE"] as const)(
    "rejects non-API and normalized metrics paths before %s fetch",
    async (method) => {
      for (const path of [
        [],
        ["metrics"],
        ["openapi.json"],
        ["v10", "health"],
        ["v1", "..", "metrics"],
        ["v1", ".", "..", "metrics"],
        ["v1", "health", "..", "..", "metrics"],
        ["v1", "..", "metrics", ""],
      ]) {
        const response = await routes[method](
          new NextRequest("http://dashboard/api/prefixd/metrics", { method }),
          { params: Promise.resolve({ path }) },
        )

        expect(response.status, JSON.stringify(path)).toBe(404)
        expect(fetchMock).not.toHaveBeenCalled()
      }
    },
  )

  it.each([
    { requestPath: "/api/prefixd/%6detrics", path: ["metrics"] },
    { requestPath: "/api/prefixd/v1/%2e%2e/metrics", path: ["v1", "..", "metrics"] },
    { requestPath: "/api/prefixd/v1/.%2e/metrics", path: ["v1", "..", "metrics"] },
  ])("rejects decoded metrics alias $requestPath", async ({ requestPath, path }) => {
    const response = await routes.GET(
      new NextRequest(`http://dashboard${requestPath}`),
      { params: Promise.resolve({ path }) },
    )

    expect(response.status).toBe(404)
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it("forwards the checked normalized API URL and GET query", async () => {
    await routes.GET(
      new NextRequest("http://dashboard/api/prefixd/v1/health?detail=1&pop=iad1"),
      { params: Promise.resolve({ path: ["v1", "unused", "..", "health"] }) },
    )
    const [url, options] = fetchMock.mock.calls[0]
    expect(new URL(url.toString()).href).toBe("http://prefixd:8080/v1/health?detail=1&pop=iad1")
    expect(options?.method).toBe("GET")
  })

  it.each(["GET", "POST", "PUT", "DELETE"] as const)(
    "preserves encoded CIDR segments and %s request/response forwarding",
    async (method) => {
      fetchMock.mockResolvedValue(new Response("backend result", {
        status: 202,
        headers: {
          "set-cookie": "session=opaque; HttpOnly",
          "x-request-id": "request-control",
          "content-encoding": "gzip",
          "transfer-encoding": "chunked",
        },
      }))
      const body = method === "GET" ? undefined : JSON.stringify({ reason: "operator request" })

      const request = new NextRequest("http://dashboard/api/prefixd/v1/safelist/203.0.113.9%2F32", {
        method,
        headers: { host: "dashboard", authorization: "Bearer opaque", "content-type": "application/json" },
        body,
      })

      const response = await routes[method](request, {
        params: Promise.resolve({ path: ["v1", "safelist", "203.0.113.9/32"] }),
      })

      const [url, options] = fetchMock.mock.calls[0]
      expect(url.toString()).toBe("http://prefixd:8080/v1/safelist/203.0.113.9%2F32")
      expect(options?.method).toBe(method)
      expect(options?.body).toBe(request.body)
      expect(new Headers(options?.headers).get("authorization")).toBe("Bearer opaque")
      expect(new Headers(options?.headers).has("host")).toBe(false)
      expect(response.status).toBe(202)
      expect(await response.text()).toBe("backend result")
      expect(response.headers.get("set-cookie")).toBe("session=opaque; HttpOnly")
      expect(response.headers.get("x-request-id")).toBe("request-control")
      expect(response.headers.has("content-encoding")).toBe(false)
      expect(response.headers.has("transfer-encoding")).toBe(false)
    },
  )

  it("leaves double-encoded dot segments as unknown API paths for the backend", async () => {
    fetchMock.mockResolvedValue(new Response("not found", { status: 404 }))

    const response = await routes.GET(
      new NextRequest("http://dashboard/api/prefixd/v1/%252e%252e/metrics"),
      { params: Promise.resolve({ path: ["v1", "%2e%2e", "metrics"] }) },
    )

    expect(fetchMock.mock.calls[0][0].toString()).toBe("http://prefixd:8080/v1/%252e%252e/metrics")
    expect(response.status).toBe(404)
  })

  it("keeps upstream connection failures as 502 responses", async () => {
    const errorLog = vi.spyOn(console, "error").mockImplementation(() => {})
    fetchMock.mockRejectedValue(new Error("connection refused"))

    try {
      const response = await routes.GET(new NextRequest("http://dashboard/api/prefixd/v1/health"), {
        params: Promise.resolve({ path: ["v1", "health"] }),
      })

      expect(response.status).toBe(502)
      expect(await response.json()).toEqual({ error: "Failed to connect to backend" })
    } finally {
      errorLog.mockRestore()
    }
  })
})
