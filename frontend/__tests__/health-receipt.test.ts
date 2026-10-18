import { afterEach, expect, it, vi } from "vitest"
import { fetchHealthDetailSnapshot } from "@/hooks/use-api"
import { getHealthDetail, type HealthResponse } from "@/lib/api"

vi.mock("@/lib/api", () => ({ getHealthDetail: vi.fn() }))

afterEach(() => vi.restoreAllMocks())

it("records each browser receipt even when API JSON is identical", async () => {
  const response: HealthResponse = { status: "healthy", version: "controller", pop: "test",
    uptime_seconds: 0, bgp_sessions: {}, active_mitigations: 0, database: "connected",
    gobgp: { status: "connected" }, auth_mode: "none", bgp_session_up: false }

  vi.mocked(getHealthDetail).mockResolvedValue(response)
  vi.spyOn(performance, "now").mockReturnValueOnce(1000).mockReturnValueOnce(2000)
  const first = await fetchHealthDetailSnapshot()
  const second = await fetchHealthDetailSnapshot()
  expect(first.receivedAt).toBe(1000)
  expect(second.receivedAt).toBe(2000)
  expect(second).toEqual({ ...first, receivedAt: 2000 })
  expect(response).not.toHaveProperty("receivedAt")
})
