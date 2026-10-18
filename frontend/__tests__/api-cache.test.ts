import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

beforeEach(() => {
  vi.resetModules()
  vi.useFakeTimers()
})

afterEach(() => {
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe("GET request cache", () => {
  it("shares a pending success and refetches immediately after settlement", async () => {
    let respond!: (response: Response) => void

    const fetchMock = vi.fn().mockImplementationOnce(() => new Promise<Response>((resolve) => {
      respond = resolve
    }))

    vi.stubGlobal("fetch", fetchMock)
    const { getHealth } = await import("@/lib/api")

    const first = getHealth()
    const second = getHealth()
    expect(fetchMock).toHaveBeenCalledTimes(1)

    respond(new Response(JSON.stringify({ status: "first" })))
    await expect(Promise.all([first, second])).resolves.toEqual([
      { status: "first" }, { status: "first" },
    ])

    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ status: "fresh" })))
    await expect(getHealth()).resolves.toEqual({ status: "fresh" })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it.each([401, 403, 500, 503, "offline"] as const)("returns handled %s failures to every caller and permits retry", async (failure) => {
    const fetchMock = vi.fn()

    if (failure === "offline") {
      fetchMock.mockRejectedValueOnce(new TypeError("network offline"))
    } else {
      fetchMock.mockResolvedValueOnce(new Response("denied", { status: failure }))
    }

    vi.stubGlobal("fetch", fetchMock)
    const { getHealth } = await import("@/lib/api")

    const results = await Promise.allSettled([getHealth(), getHealth()])
    expect(fetchMock).toHaveBeenCalledTimes(1)

    for (const result of results) {
      expect(result.status).toBe("rejected")

      if (result.status === "rejected") {
        expect(result.reason.message).toContain(failure === "offline" ? "network offline" : `API error ${failure}`)
      }
    }

    // Vitest must also see no unhandled rejection from the cache cleanup.
    fetchMock.mockResolvedValueOnce(new Response(JSON.stringify({ status: "ok" })))
    await expect(getHealth()).resolves.toEqual({ status: "ok" })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})
