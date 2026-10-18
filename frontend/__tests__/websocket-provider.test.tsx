import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { act, renderHook, screen, waitFor } from "@testing-library/react"
import type { ReactNode } from "react"
import useSWR, { type Key } from "swr"
import { WebSocketProvider, useWebSocketContext } from "@/components/websocket-provider"
import type { WsMessage } from "@/hooks/use-websocket-types"
import type { NotificationPreferences } from "@/lib/api"
import { appWrapper, json, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

class FakeWebSocket {
  static OPEN = 1
  static instances: FakeWebSocket[] = []
  readyState = 0
  onopen: (() => void) | null = null
  onmessage: ((event: MessageEvent<string>) => void) | null = null
  onclose: (() => void) | null = null
  onerror: (() => void) | null = null

  constructor(readonly url: string) {
    FakeWebSocket.instances.push(this)
  }

  open() {
    this.readyState = FakeWebSocket.OPEN
    this.onopen?.()
  }

  receive(frame: WsMessage) {
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

/** Cache keys shaped like the dashboard hooks' keys; the provider's own preferences key is fetched from the API. */
const cacheKeys: Key[] = [
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

/** The provider's own hook fetches "notification-preferences"; probing it too would replace its fetcher. */
const probedKeys = cacheKeys.filter((key) => key !== "notification-preferences")

let preferences: NotificationPreferences
const fetches = new Map<string, number>()

function CacheProbe({ swrKey }: { swrKey: Key }) {
  const name = JSON.stringify(swrKey)

  useSWR(swrKey, () => {
    fetches.set(name, (fetches.get(name) ?? 0) + 1)

    return name
  })

  return null
}

/** Keys refetched since the frame was sent. The provider owns "notification-preferences", so its refetch goes to the API. */
function invalidatedKeys(preferenceReads: number) {
  return cacheKeys.filter((key) => key === "notification-preferences"
    ? controller.calls("GET", "/v1/preferences").length > preferenceReads
    : (fetches.get(JSON.stringify(key)) ?? 0) > 0)
}

async function mountProvider() {
  const app = appWrapper({ withoutAuth: true })

  const hook = renderHook(() => useWebSocketContext(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <app.wrapper>
        <WebSocketProvider>
          {probedKeys.map((key) => <CacheProbe key={JSON.stringify(key)} swrKey={key} />)}
          {children}
        </WebSocketProvider>
      </app.wrapper>
    ),
  })

  const socket = FakeWebSocket.instances[0]

  if (!socket) throw new Error("provider did not open a WebSocket")
  act(() => socket.open())
  await waitFor(() => expect(controller.calls("GET", "/v1/preferences")).toHaveLength(1))
  await waitFor(() => expect(fetches.size).toBe(probedKeys.length))
  await settle()
  fetches.clear()

  return { ...hook, socket, preferenceReads: controller.calls("GET", "/v1/preferences").length }
}

function toasts() {
  return [...document.querySelectorAll("[data-sonner-toast]")]
}

describe("WebSocketProvider server frames", () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    fetches.clear()
    preferences = { muted_events: [], quiet_hours_start: null, quiet_hours_end: null }
    controller.route("GET", "/v1/preferences", () => json(preferences))
    vi.stubGlobal("WebSocket", FakeWebSocket)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it.each([
    ["mitigation_created", { mitigation }, "error", "Mitigation Created: 203.0.113.10"],
    ["mitigation_updated", { mitigation }, "warning", "Mitigation Updated: 203.0.113.10"],
    ["mitigation_expired", { mitigation_id: mitigation.mitigation_id }, "info", "Mitigation Expired"],
    ["mitigation_withdrawn", { mitigation_id: mitigation.mitigation_id }, "success", "Mitigation Withdrawn"],
  ] as const)("refreshes mitigation caches for %s", async (type, payload, toastKind, title) => {
    const { socket, result, preferenceReads } = await mountProvider()
    const frame = { type, ...payload }
    act(() => socket.receive(frame))
    await settle()

    expect(result.current.lastMessage).toEqual(frame)
    expect(invalidatedKeys(preferenceReads)).toEqual([cacheKeys[0], cacheKeys[1], "stats"])
    const toast = await screen.findByText(title)
    expect(toast.closest("[data-sonner-toast]")).toHaveAttribute("data-type", toastKind)
  })

  it("refreshes event caches for the backend EventResponse frame", async () => {
    const { socket, preferenceReads } = await mountProvider()

    // The backend frame carries fields the dashboard does not read.
    const frame = {
      type: "event_ingested",
      event: {
        event_id: "2f585b3f-6878-4bde-a908-37739846b4a3",
        external_event_id: "detector-1",
        status: "accepted",
        mitigation_id: mitigation.mitigation_id,
      },
    } as const

    act(() => socket.receive(frame))
    await settle()

    expect(invalidatedKeys(preferenceReads)).toEqual([cacheKeys[2], cacheKeys[3], "stats"])
  })

  it("refreshes live caches after a payload-free resync frame", async () => {
    const { socket, preferenceReads } = await mountProvider()
    act(() => socket.receive({ type: "resync_required" }))
    await settle()

    expect(invalidatedKeys(preferenceReads)).toEqual(cacheKeys.slice(0, 7))
    const toast = await screen.findByText("Refreshing live data after missed updates")
    expect(toast.closest("[data-sonner-toast]")).toHaveAttribute("data-type", "info")
  })

  it.each([
    [{ type: "mitigation_created", mitigation }, "mitigation.created"],
    [{ type: "mitigation_expired", mitigation_id: mitigation.mitigation_id }, "mitigation.expired"],
    [{ type: "resync_required" }, "config.reloaded"],
  ] as const)("keeps refresh active when notifications are muted: %j", async (frame, mutedEvent) => {
    preferences = { ...preferences, muted_events: [mutedEvent] }
    const { socket, preferenceReads } = await mountProvider()
    act(() => socket.receive(frame))
    await settle()

    expect(invalidatedKeys(preferenceReads).length).toBeGreaterThan(0)
    expect(toasts()).toEqual([])
  })
})
