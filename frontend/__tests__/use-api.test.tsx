import { act, cleanup, renderHook, waitFor } from "@testing-library/react"
import { afterEach, describe, expect, it, vi } from "vitest"
import { useEvents, useMitigation, useMitigations, useSignalGroupDetail, useSignalGroupsPaginated } from "@/hooks/use-api"
import { appWrapper, json, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const wrapper = () => appWrapper({ withoutAuth: true })

function query(method: string, path: string) {
  return controller.calls(method, path).map((request) => Object.fromEntries(request.query))
}

describe("real API hooks", () => {
  afterEach(() => {
    cleanup()
    vi.useRealTimers()
  })

  it("polls mitigations only when the five-second refresh clock advances", async () => {
    controller.route("GET", "/v1/mitigations", () => json({ mitigations: [], count: 0, next_cursor: null, has_more: false }))
    vi.useFakeTimers()
    const view = renderHook(() => useMitigations(), wrapper())

    try {
      await act(() => vi.advanceTimersByTimeAsync(0))
      expect(controller.calls("GET", "/v1/mitigations")).toHaveLength(1)
      await act(() => vi.advanceTimersByTimeAsync(4999))
      expect(controller.calls("GET", "/v1/mitigations")).toHaveLength(1)
      await act(() => vi.advanceTimersByTimeAsync(1))
      expect(controller.calls("GET", "/v1/mitigations")).toHaveLength(2)
    } finally {
      view.unmount()
      vi.clearAllTimers()
      vi.useRealTimers()
    }
  })

  it("forwards mitigation filters to the API", async () => {
    controller.route("GET", "/v1/mitigations", () => json({ mitigations: [], count: 0, next_cursor: null, has_more: false }))
    const filters = { status: ["active"], customer_id: "customer-a", limit: 10 }
    renderHook(() => useMitigations(filters), wrapper())
    await waitFor(() => expect(query("GET", "/v1/mitigations")).toEqual([{ status: "active", customer_id: "customer-a", limit: "10" }]))
  })

  it("forwards event filters to the API", async () => {
    controller.route("GET", "/v1/events", () => json({ events: [], count: 0, next_cursor: null, has_more: false }))
    const filters = { limit: 10, cursor: "event-cursor" }
    renderHook(() => useEvents(filters), wrapper())
    await waitFor(() => expect(query("GET", "/v1/events")).toEqual([{ limit: "10", cursor: "event-cursor" }]))
  })

  it("does not fetch detail records without an identifier", async () => {
    const { result } = renderHook(() => ({ mitigation: useMitigation(null), group: useSignalGroupDetail(null) }), wrapper())
    await settle()
    expect(result.current.mitigation.isLoading).toBe(false)
    expect(result.current.group.isLoading).toBe(false)
    expect(controller.requests).toEqual([])
  })

  it("carries the returned cursor into the next signal-group request", async () => {
    controller.route("GET", "/v1/signal-groups", ({ query: params }) => json({
      groups: [], count: 0, next_cursor: params.get("cursor") ? null : "next-page", has_more: !params.get("cursor"),
    }))
    const { result } = renderHook(() => useSignalGroupsPaginated({ status: "open", limit: 2 }), wrapper())
    await waitFor(() => expect(result.current.data?.length).toBe(1))
    await act(async () => { await result.current.setSize(2) })
    await waitFor(() => expect(result.current.data?.length).toBe(2))
    expect(query("GET", "/v1/signal-groups")).toContainEqual({ status: "open", limit: "2", cursor: "next-page" })
    await act(async () => { await result.current.setSize(3) })
    expect(result.current.data?.length).toBe(2)
  })

  it("polls every loaded signal-group page without a live feed", async () => {
    controller.route("GET", "/v1/signal-groups", ({ query: params }) => json({
      groups: [], count: 0, next_cursor: params.get("cursor") ? null : "next-page", has_more: !params.get("cursor"),
    }))
    vi.useFakeTimers()

    const { result } = renderHook(() => {
      const { data, setSize } = useSignalGroupsPaginated({ limit: 2 })

      return { data, setSize }
    }, wrapper())

    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    await act(async () => { await result.current.setSize(2) })
    expect(result.current.data).toHaveLength(2)
    const before = query("GET", "/v1/signal-groups").length
    await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
    expect(query("GET", "/v1/signal-groups").slice(before)).toEqual([
      { limit: "2" }, { limit: "2", cursor: "next-page" },
    ])
  })
})
