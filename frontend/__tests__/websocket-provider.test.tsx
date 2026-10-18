import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, cleanup, renderHook } from "@testing-library/react"
import type { ReactNode } from "react"

const mocks = vi.hoisted(() => ({
  mutate: vi.fn<(key: string | ((key: unknown) => boolean)) => void>(),
  preferences: {
    muted_events: [] as string[],
    quiet_hours_start: null as number | null,
    quiet_hours_end: null as number | null,
  },
  toast: { error: vi.fn(), warning: vi.fn(), success: vi.fn(), info: vi.fn() },
}))

vi.mock("swr", () => ({
  default: () => ({ data: mocks.preferences }),
  useSWRConfig: () => ({ mutate: mocks.mutate }),
}))

vi.mock("sonner", () => ({ toast: mocks.toast }))

vi.mock("@/lib/api", () => ({ getNotificationPreferences: vi.fn() }))

import { WebSocketProvider, useWebSocketContext } from "@/components/websocket-provider"

class MockWebSocket {
  static OPEN = 1
  static instances: MockWebSocket[] = []
  readyState = 0
  onopen: (() => void) | null = null
  onmessage: ((event: MessageEvent<string>) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null

  constructor(readonly url: string) {
    MockWebSocket.instances.push(this)
  }

  open() {
    this.readyState = MockWebSocket.OPEN
    this.onopen?.()
  }

  receive(frame: unknown) {
    this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(frame) }))
  }

  close() {
    this.readyState = 3
    this.onclose?.()
  }
}

const mitigation = {
  mitigation_id: "1edfe148-cd2b-4d39-a190-fce21092549e",
  status: "active",
  customer_id: null,
  victim_ip: "203.0.113.10",
  vector: "udp_flood",
  action_type: "police",
  rate_bps: 8000000,
  created_at: "2026-10-18T00:00:00Z",
  expires_at: "2026-10-18T00:05:00Z",
  scope_hash: "test-scope",
}

const cacheKeys = [
  "mitigations",
  ["mitigations", { status: "active" }],
  "events",
  ["events", { source: "detector" }],
  "stats",
  "dashboard",
  ["signal-groups", { status: "open" }],
  "notification-preferences",
  "settings",
]

function invalidatedKeys() {
  return cacheKeys.filter((key) => mocks.mutate.mock.calls.some(([selector]) =>
    typeof selector === "function" ? selector(key) : selector === key
  ))
}

function mountProvider() {
  const hook = renderHook(() => useWebSocketContext(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <WebSocketProvider>{children}</WebSocketProvider>
    ),
  })

  const socket = MockWebSocket.instances[0]

  if (!socket) throw new Error("provider did not open a WebSocket")
  act(() => socket.open())

  return { ...hook, socket }
}

describe("WebSocketProvider server frames", () => {
  beforeEach(() => {
    vi.clearAllMocks()
    MockWebSocket.instances = []
    mocks.preferences.muted_events = []
    mocks.preferences.quiet_hours_start = null
    mocks.preferences.quiet_hours_end = null
    vi.stubGlobal("WebSocket", MockWebSocket)
  })

  afterEach(() => {
    cleanup()
    vi.unstubAllGlobals()
  })

  it.each([
    ["mitigation_created", { mitigation }, "error", "Mitigation Created: 203.0.113.10"],
    ["mitigation_updated", { mitigation }, "warning", "Mitigation Updated: 203.0.113.10"],
    ["mitigation_expired", { mitigation_id: mitigation.mitigation_id }, "info", "Mitigation Expired"],
    ["mitigation_withdrawn", { mitigation_id: mitigation.mitigation_id }, "success", "Mitigation Withdrawn"],
  ] as const)("refreshes mitigation caches for %s", (type, payload, toastKind, title) => {
    const { socket, result } = mountProvider()
    const frame = { type, ...payload }
    act(() => socket.receive(frame))

    expect(result.current.lastMessage).toEqual(frame)
    expect(invalidatedKeys()).toEqual([cacheKeys[0], cacheKeys[1], "stats"])
    expect(mocks.toast[toastKind]).toHaveBeenCalledWith(title, expect.any(Object))
  })

  it("refreshes event caches for the backend EventResponse frame", () => {
    const { socket } = mountProvider()
    act(() => socket.receive({
      type: "event_ingested",
      event: {
        event_id: "2f585b3f-6878-4bde-a908-37739846b4a3",
        external_event_id: "detector-1",
        status: "accepted",
        mitigation_id: mitigation.mitigation_id,
      },
    }))

    expect(invalidatedKeys()).toEqual([cacheKeys[2], cacheKeys[3], "stats"])
  })

  it("refreshes live caches after a payload-free resync frame", () => {
    const { socket } = mountProvider()
    act(() => socket.receive({ type: "resync_required" }))

    expect(invalidatedKeys()).toEqual(cacheKeys.slice(0, 7))
    expect(mocks.toast.info).toHaveBeenCalledWith("Refreshing live data after missed updates")
  })

  it.each([
    [{ type: "mitigation_created", mitigation }, "mitigation.created"],
    [{ type: "mitigation_expired", mitigation_id: mitigation.mitigation_id }, "mitigation.expired"],
    [{ type: "resync_required" }, "config.reloaded"],
  ] as const)("keeps refresh active when notifications are muted: %j", (frame, mutedEvent) => {
    mocks.preferences.muted_events = [mutedEvent]
    const { socket } = mountProvider()
    act(() => socket.receive(frame))

    expect(mocks.mutate).toHaveBeenCalled()

    for (const show of Object.values(mocks.toast)) expect(show).not.toHaveBeenCalled()
  })
})
