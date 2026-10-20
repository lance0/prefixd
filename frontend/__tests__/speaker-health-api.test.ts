// @vitest-environment node

import { afterEach, describe, expect, it, vi } from "vitest"

afterEach(() => vi.unstubAllGlobals())

describe("health peer summary", () => {
  it.each([
    ["unsupported", {}, false], ["error", { router: "established" }, false],
    ["connected", {}, false], ["connected", { router: "established" }, true],
    ["connected", { router: "idle" }, false],
  ])("derives %s with %j peers safely", async (status, peers, expected) => {
    vi.resetModules()
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(new Response(JSON.stringify({
      gobgp: { status }, bgp_sessions: peers,
    }))))
    const { getHealthDetail } = await import("@/lib/api")
    const result = await getHealthDetail()
    expect(result.bgp_session_up).toBe(expected)
    expect(result.speaker).toBeUndefined()
  })
})
