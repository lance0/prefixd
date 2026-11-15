import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, render, screen } from "@testing-library/react"
import type { ReactNode } from "react"
import { ConnectionStatus, StaleDataNotice } from "@/components/connection-status"
import { WebSocketProvider } from "@/components/websocket-provider"
import { useHealth } from "@/hooks/use-api"
import type { ConnectionState } from "@/hooks/use-websocket-types"
import { dataFreshness, STALE_AFTER_MS, type ApiReceipt } from "@/lib/freshness"
import { appWrapper, deferred, failure, json, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

describe("dataFreshness", () => {
  const fresh: ApiReceipt = { lastSuccessAt: 10_000, failing: false }

  it("is live only with a connected feed and a recent response", () => {
    expect(dataFreshness("connected", fresh, 12_000, 0)).toEqual({ state: "live", ageMs: 2_000 })
    expect(dataFreshness("polling", fresh, 12_000, 0)).toEqual({ state: "polling", ageMs: 2_000 })
    expect(dataFreshness("disconnected", fresh, 12_000, 0).state).toBe("polling")
  })

  it("keeps a recent response fresh through one failed poll", () => {
    expect(dataFreshness("connected", { ...fresh, failing: true }, 12_000, 0).state).toBe("live")
  })

  it("turns stale after 15 seconds without a response, whatever the feed says", () => {
    const at = 10_000 + STALE_AFTER_MS

    expect(dataFreshness("connected", fresh, at, 0).state).toBe("live")
    expect(dataFreshness("connected", fresh, at + 1, 0)).toEqual({ state: "stale", ageMs: STALE_AFTER_MS + 1 })
    expect(dataFreshness("connected", { ...fresh, failing: true }, at + 1, 0).state).toBe("offline")
  })

  it("never shows a page that has received nothing as fresh", () => {
    const none: ApiReceipt = { lastSuccessAt: null, failing: false }

    expect(dataFreshness("connected", none, 5_000, 0)).toEqual({ state: "connecting", ageMs: null })
    expect(dataFreshness("connected", { ...none, failing: true }, 5_000, 0).state).toBe("offline")
    // A request that hangs at page load still turns stale.
    expect(dataFreshness("connected", none, STALE_AFTER_MS + 1, 0)).toEqual({ state: "stale", ageMs: null })
  })
})

/** Polls /v1/health like any dashboard page and shows the indicator for one feed state. */
function Polled({ state }: { state: ConnectionState }) {
  useHealth()

  return <ConnectionStatus state={state} />
}

const indicator = () => screen.getByRole("status")
const advance = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms) })

describe("ConnectionStatus", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date", "performance"] })
    // Radix measures the tooltip arrow.
    vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} })
  })

  afterEach(() => vi.useRealTimers())

  function renderPolled(state: ConnectionState) {
    const app = appWrapper({ withoutAuth: true })

    return render(<Polled state={state} />, { wrapper: app.wrapper })
  }

  it("shows Live while the feed is connected and polls succeed", async () => {
    controller.route("GET", "/v1/health", () => json({ status: "ok" }))
    renderPolled("connected")
    await advance(0)
    expect(indicator()).toHaveTextContent("Live")
    expect(indicator()).toHaveAccessibleName(/^Live\. Data is current; last successful API response 0s ago\./)
    await advance(30_000)
    expect(indicator()).toHaveTextContent("Live")
  })

  it("shows Polling with the receipt age when the feed is down", async () => {
    controller.route("GET", "/v1/health", () => json({ status: "ok" }))
    renderPolled("polling")
    await advance(3_000)
    expect(indicator()).toHaveTextContent("Polling(3s ago)")
    expect(indicator()).toHaveAccessibleName(/Realtime feed unavailable/)
  })

  it("shows Offline, not Live, within 15 seconds of the API failing under a connected feed", async () => {
    let up = true
    controller.route("GET", "/v1/health", () => up ? json({ status: "ok" }) : failure(502))
    renderPolled("connected")
    await advance(0)
    expect(indicator()).toHaveTextContent("Live")
    up = false
    await advance(STALE_AFTER_MS + 1_000)
    expect(indicator()).toHaveTextContent(/^Offline\(16s ago\)$/)
    expect(indicator()).toHaveAccessibleName(/API requests are failing; data on screen is out of date: last successful API response 16s ago/)
    // Recovery is immediate once a request succeeds again. The test SWR config does
    // not retry errors, so a focus revalidation stands in for the next poll.
    up = true
    act(() => { window.dispatchEvent(new Event("focus")) })
    await advance(0)
    expect(indicator()).toHaveTextContent("Live")
  })

  it("shows Stale when requests hang without any response", async () => {
    let hang = false
    controller.route("GET", "/v1/health", () => hang ? deferred<Response>().promise : json({ status: "ok" }))
    renderPolled("connected")
    await advance(0)
    hang = true
    await advance(STALE_AFTER_MS + 1_000)
    expect(indicator()).toHaveTextContent("Stale(16s ago)")
  })

  it("shows the disconnected feed as stale, not polling, once polls stop answering", async () => {
    let hang = false
    controller.route("GET", "/v1/health", () => hang ? deferred<Response>().promise : json({ status: "ok" }))
    renderPolled("disconnected")
    await advance(0)
    expect(indicator()).toHaveTextContent("Polling(0s ago)")
    hang = true
    await advance(STALE_AFTER_MS + 1_000)
    expect(indicator()).toHaveTextContent("Stale(16s ago)")
    expect(indicator()).not.toHaveTextContent("Polling")
  })
})

describe("StaleDataNotice", () => {
  beforeEach(() => {
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout", "setInterval", "clearInterval", "Date", "performance"] })
    vi.stubGlobal("WebSocket", class { static OPEN = 1; readyState = 0; close() {} })
  })

  afterEach(() => vi.useRealTimers())

  function renderNotice() {
    const app = appWrapper({ withoutAuth: true })

    return render(<Polled state="connected" />, {
      wrapper: ({ children }: { children: ReactNode }) => (
        <app.wrapper><WebSocketProvider><StaleDataNotice />{children}</WebSocketProvider></app.wrapper>
      ),
    })
  }

  it("stays empty while data is fresh and names the age once it is stale", async () => {
    let up = true
    controller.route("GET", "/v1/preferences", () => json({ muted_events: [], quiet_hours_start: null, quiet_hours_end: null }))
    controller.route("GET", "/v1/health", () => up ? json({ status: "ok" }) : failure(502))
    renderNotice()
    await advance(0)
    // The notice renders before the page, ahead of the top-bar status.
    const [notice] = screen.getAllByRole("status")
    expect(notice).toBeEmptyDOMElement()
    up = false
    await advance(STALE_AFTER_MS + 1_000)
    expect(notice).toHaveTextContent("The controller API is not responding.")
    expect(notice).toHaveTextContent("Updated 16s ago.")
  })
})
