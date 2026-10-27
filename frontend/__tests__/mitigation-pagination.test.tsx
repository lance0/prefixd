import { act, fireEvent, screen, waitFor } from "@testing-library/react"
import { useSWRConfig } from "swr"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { getAllMitigations, type Mitigation } from "@/lib/api"
import { failure, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const rows: Mitigation[] = Array.from({ length: 121 }, (_, index) => ({
  mitigation_id: `mitigation-${index + 1}`, scope_hash: `scope-${index + 1}`, status: "active",
  customer_id: index === 120 ? "older-customer" : "acme", service_id: null, pop: index === 120 ? "old-pop" : "iad1",
  victim_ip: `203.0.113.${index + 1}`, vector: "udp_flood", action_type: "discard", rate_bps: null,
  dst_prefix: `203.0.113.${index + 1}/32`, protocol: 17, dst_ports: [],
  created_at: "2026-10-27T10:00:00Z", updated_at: "2026-10-27T10:00:00Z", expires_at: "2026-10-27T11:00:00Z",
  withdrawn_at: null, triggering_event_id: "event-1", last_event_id: "event-1", reason: "flood",
  acknowledged_at: null, acknowledged_by: null,
}))

let served = rows
let failCursor: string | null = null
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  served = rows
  failCursor = null
  signIn(controller, "credentials", operatorResponse("operator"))
  controller.route("GET", "/v1/config/inventory", () => json({ customers: ["acme", "older-customer"].map((customer_id) => ({ customer_id })) }))
  controller.route("GET", "/v1/pops", () => json([{ pop: "iad1" }, { pop: "old-pop" }]))
  controller.route("GET", "/v1/mitigations", ({ query }) => {
    if (failCursor !== null && query.get("cursor") === failCursor) return failure(502)
    const q = query.get("q")?.toLowerCase() ?? ""

    const matching = served.filter((row) =>
      (!query.get("customer_id") || row.customer_id === query.get("customer_id")) &&
      (!query.get("pop") || row.pop === query.get("pop")) &&
      [row.victim_ip, row.vector, row.customer_id ?? "", row.mitigation_id].some((value) => value.toLowerCase().includes(q)))

    const start = Number(query.get("cursor") ?? 0)
    const limit = Number(query.get("limit") ?? 100)
    const page = matching.slice(start, start + limit)
    const hasMore = start + page.length < matching.length

    return json({ mitigations: page, count: page.length, next_cursor: hasMore ? String(start + limit) : null, has_more: hasMore })
  })

  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

async function nextPage(page: number) {
  fireEvent.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByText(`Page ${page}`)
}

describe("complete mitigation navigation", () => {
  it("reaches rows beyond 100 while retaining only one page, and returns through server cursors", async () => {
    let cache: ReturnType<typeof useSWRConfig>["cache"] | undefined

    function CacheProbe() {
      cache = useSWRConfig().cache

      return null
    }

    renderApp(<><MitigationsContentLive /><CacheProbe /></>)
    await screen.findByText("Page 1")

    for (let page = 2; page <= 7; page++) await nextPage(page)
    expect(screen.getByRole("link", { name: "203.0.113.121" })).toBeInTheDocument()
    expect(screen.getAllByRole("row")).toHaveLength(2)
    const retained = [...cache!.keys()].flatMap((key) => cache!.get(key)?.data?.mitigations ?? [])

    expect(retained).toHaveLength(1)
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
    fireEvent.click(screen.getByRole("button", { name: "Previous" }))
    await screen.findByText("Page 6")
    expect(screen.getByRole("link", { name: "203.0.113.101" })).toBeInTheDocument()
    expect(controller.calls("GET", "/v1/mitigations").every((call) => call.query.get("limit") === "20")).toBe(true)
  })

  it("searches and filters on the server, with choices outside the current page", async () => {
    renderApp(<MitigationsContentLive />)
    await screen.findByText("Page 1")
    await nextPage(2)
    fireEvent.change(screen.getByRole("textbox", { name: "Search mitigations" }), { target: { value: "older-customer" } })
    expect(await screen.findByRole("link", { name: "203.0.113.121" })).toBeInTheDocument()
    expect(screen.getByText("Page 1")).toBeInTheDocument()
    expect(controller.calls("GET", "/v1/mitigations").at(-1)?.query.get("cursor")).toBeNull()
    expect(controller.calls("GET", "/v1/mitigations").at(-1)?.query.get("q")).toBe("older-customer")
    fireEvent.change(screen.getByRole("textbox", { name: "Search mitigations" }), { target: { value: "" } })
    await screen.findByRole("link", { name: "203.0.113.1" })
    fireEvent.keyDown(screen.getByRole("combobox", { name: "Customer" }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "older-customer" }))
    expect(await screen.findByRole("link", { name: "203.0.113.121" })).toBeInTheDocument()
    expect(controller.calls("GET", "/v1/mitigations").at(-1)?.query.get("customer_id")).toBe("older-customer")
  })

  it("keeps failed continuation separate from empty results and permits retry or previous navigation", async () => {
    failCursor = "20"
    renderApp(<MitigationsContentLive />)
    await screen.findByText("Page 1")
    fireEvent.click(screen.getByRole("button", { name: "Next" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to load mitigations")
    expect(screen.queryByText("No mitigations with these statuses")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Previous" })).toBeEnabled()
    failCursor = null
    fireEvent.click(screen.getByRole("button", { name: "Retry mitigations" }))
    await screen.findByRole("link", { name: "203.0.113.21" })
    fireEvent.click(screen.getByRole("button", { name: "Previous" }))
    await screen.findByText("Page 1")
  })

  it("clears hidden selections on navigation and backs up when polling empties the last page", async () => {
    served = rows.slice(0, 21)
    vi.useFakeTimers()

    try {
      renderApp(<MitigationsContentLive />)
      await act(() => vi.advanceTimersByTimeAsync(0))
      fireEvent.click(screen.getByRole("checkbox", { name: "Select mitigation 203.0.113.1" }))
      fireEvent.click(screen.getByRole("button", { name: "Next" }))
      await act(() => vi.advanceTimersByTimeAsync(0))
      expect(screen.queryByText("1 selected")).not.toBeInTheDocument()
      served = rows.slice(0, 20)
      await act(() => vi.advanceTimersByTimeAsync(5000))
      await act(() => vi.advanceTimersByTimeAsync(20))
      expect(screen.getByText("Page 1")).toBeInTheDocument()
      expect(screen.getByRole("link", { name: "203.0.113.1" })).toBeInTheDocument()
      expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
    } finally {
      vi.clearAllTimers()
      vi.useRealTimers()
    }
  })

  it("prunes realtime selections by ID while preserving an open bulk confirmation's original scope", async () => {
    served = [rows[0]]
    controller.route("POST", "/v1/mitigations/withdraw", () => failure(500))
    vi.useFakeTimers()

    try {
      renderApp(<MitigationsContentLive />)
      await act(() => vi.advanceTimersByTimeAsync(0))
      fireEvent.click(screen.getByRole("checkbox", { name: "Select all active mitigations on this page" }))
      served = [rows[1]]
      await act(() => vi.advanceTimersByTimeAsync(5000))
      expect(screen.queryByText("1 selected")).not.toBeInTheDocument()
      expect(screen.getByRole("checkbox", { name: "Select all active mitigations on this page" })).not.toBeChecked()
      served = rows.slice(0, 21)
      await act(() => vi.advanceTimersByTimeAsync(5000))
      fireEvent.click(screen.getByRole("button", { name: "Next" }))
      await act(() => vi.advanceTimersByTimeAsync(0))
      fireEvent.click(screen.getByRole("checkbox", { name: "Select mitigation 203.0.113.21" }))
      fireEvent.click(screen.getByRole("button", { name: "Withdraw all" }))
      served = rows.slice(0, 20)
      await act(() => vi.advanceTimersByTimeAsync(5000))
      expect(screen.getByRole("alertdialog")).toHaveTextContent("1 FlowSpec rule")
      expect(screen.getByText("Page 2")).toBeInTheDocument()
      fireEvent.click(screen.getByRole("button", { name: "Withdraw 1" }))
      await act(() => vi.advanceTimersByTimeAsync(0))
      expect(JSON.parse(controller.calls("POST", "/v1/mitigations/withdraw")[0].body!)).toMatchObject({ mitigation_ids: ["mitigation-21"] })
    } finally {
      vi.clearAllTimers()
      vi.useRealTimers()
    }
  })
})

describe("complete CSV input", () => {
  it("walks all matching cursors rather than exporting the visible page", async () => {
    served = Array.from({ length: 1201 }, (_, index) => ({ ...rows[0], mitigation_id: `csv-${index}` }))
    const exported = await getAllMitigations({ q: "udp_flood", pop: "iad1" })
    expect(exported).toHaveLength(1201)
    expect(exported.at(-1)?.mitigation_id).toBe("csv-1200")
    expect(controller.calls("GET", "/v1/mitigations")).toHaveLength(2)
    expect(controller.calls("GET", "/v1/mitigations")[1].query.get("cursor")).toBe("1000")
    expect(controller.calls("GET", "/v1/mitigations")[0].query.get("limit")).toBe("1000")
  })

  it("does not download a partial CSV when a later export page fails", async () => {
    const original = URL.createObjectURL
    URL.createObjectURL = vi.fn(() => "blob:test")
    controller.route("GET", "/v1/mitigations", ({ query }) => query.get("cursor") === "export-next"
      ? failure(502)
      : json({ mitigations: [rows[0]], count: 1, next_cursor: "export-next", has_more: true }))

    try {
      renderApp(<MitigationsContentLive />)
      await screen.findByText("Page 1")
      fireEvent.click(screen.getByRole("button", { name: "Export CSV" }))
      expect(await screen.findByRole("alert")).toHaveTextContent("No file was downloaded")
      expect(URL.createObjectURL).not.toHaveBeenCalled()
      await waitFor(() => expect(screen.getByRole("button", { name: "Export CSV" })).toBeEnabled())
    } finally {
      URL.createObjectURL = original
    }
  })

  it("refuses a failed later page and a repeated or missing continuation", async () => {
    let calls = 0
    controller.route("GET", "/v1/mitigations", () => ++calls === 1
      ? json({ mitigations: [rows[0]], count: 1, next_cursor: "next", has_more: true })
      : failure(502))
    await expect(getAllMitigations({})).rejects.toThrow()

    for (const next_cursor of ["next", null]) {
      controller.route("GET", "/v1/mitigations", () => json({ mitigations: [rows[0]], count: 1, next_cursor, has_more: true }))
      await expect(getAllMitigations({})).rejects.toThrow("Incomplete mitigation export")
    }
  })
})
