import { act, renderHook, waitFor } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { useEvents, useMitigation, useMitigations, useSignalGroupDetail, useSignalGroupsPaginated } from "@/hooks/use-api"
import { appWrapper, json, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const wrapper = () => appWrapper({ withoutAuth: true })

function query(method: string, path: string) {
  return controller.calls(method, path).map((request) => Object.fromEntries(request.query))
}

describe("real API hooks", () => {
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
})
