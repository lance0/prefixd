import { afterEach, expect, it, vi } from "vitest"
import { fetchHealthDetailSnapshot } from "@/hooks/use-api"
import { getHealthDetail, type HealthResponse } from "@/lib/api"
import { json, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

afterEach(() => vi.restoreAllMocks())

it("records each browser receipt even when API JSON is identical", async () => {
  const response: HealthResponse = { status: "healthy", version: "controller", pop: "test",
    uptime_seconds: 0, bgp_sessions: {}, active_mitigations: 0, database: "connected",
    gobgp: { status: "connected" }, auth_mode: "none", bgp_session_up: false }

  const { bgp_session_up: _derived, ...wire } = response
  controller.route("GET", "/v1/health/detail", () => json(wire))
  vi.spyOn(performance, "now").mockReturnValueOnce(1000).mockReturnValueOnce(2000)
  const first = await fetchHealthDetailSnapshot()
  const second = await fetchHealthDetailSnapshot()
  expect(controller.calls("GET", "/v1/health/detail")).toHaveLength(2)
  expect(first).toEqual({ ...response, receivedAt: 1000 })
  expect(second).toEqual({ ...first, receivedAt: 2000 })
  // Receipt time belongs to the client snapshot, never to the API response.
  expect(await getHealthDetail()).not.toHaveProperty("receivedAt")
})
