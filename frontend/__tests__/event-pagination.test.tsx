import { act, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { SWRConfig } from "swr"
import { SearchParamsContext } from "next/dist/shared/lib/hooks-client-context.shared-runtime"
import EventsPage from "@/app/(dashboard)/events/page"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import { getAllEvents, getEvents, type Event } from "@/lib/api"
import { deferred, failure, json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const rows: Event[] = Array.from({ length: 225 }, (_, index) => ({
  event_id: `00000000-0000-0000-0000-${(225 - index).toString(16).padStart(12, "0")}`,
  external_event_id: null, source: index === 224 ? "All" : "all",
  vector: index === 224 ? "Β_%\\" : "udp_flood", victim_ip: `2001:db8::${index + 1}`,
  event_timestamp: "2026-10-28T00:00:00Z", ingested_at: "2026-10-27T10:00:00Z",
  protocol: 17, bps: 1000, pps: 10, top_dst_ports_json: "[]", confidence: 0.9,
}))

let served = rows
let failedCursor: string | null = null

beforeEach(() => {
  served = rows
  failedCursor = null
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  controller.route("GET", "/v1/events", ({ query }) => {
    if (failedCursor !== null && query.get("cursor") === failedCursor) return failure(502)
    const q = query.get("q")?.toLowerCase() ?? ""

    const matching = served.filter((row) =>
      (!query.has("source") || row.source === query.get("source")) &&
      (!query.has("vector") || row.vector === query.get("vector")) &&
      [row.victim_ip, row.event_id].some((value) => value.toLowerCase().includes(q)))

    const offset = Number(query.get("cursor") ?? 0)
    const limit = Number(query.get("limit") ?? 100)
    const page = matching.slice(offset, offset + limit)
    const hasMore = offset + page.length < matching.length

    return json({ events: page, count: page.length, has_more: hasMore, next_cursor: hasMore ? String(offset + limit) : null })
  })
})

async function next(page: number) {
  fireEvent.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("link", { name: rows[(page - 1) * 20].victim_ip })
  expect(screen.getByText(`Page ${page}`)).toBeInTheDocument()
}

function renderEvents(initialEventId?: string) {
  return renderApp(<SWRConfig value={{ dedupingInterval: 2000 }}><EventsContentLive initialEventId={initialEventId} /></SWRConfig>, { withoutAuth: true, reactStrictMode: true })
}

describe("complete event history", () => {
  it("reaches older than 200 tied rows, renders only 20, and supports a rapid page revisit", async () => {
    renderEvents()
    await screen.findByRole("link", { name: rows[0].victim_ip })
    await next(2)
    fireEvent.click(screen.getByRole("button", { name: "Previous" }))
    await screen.findByRole("link", { name: rows[0].victim_ip })

    for (let page = 2; page <= 12; page++) await next(page)
    expect(screen.getByRole("link", { name: rows[224].victim_ip })).toBeInTheDocument()
    expect(screen.getAllByRole("row")).toHaveLength(6)
    expect(screen.getByText("5 events on this page · Newest received first")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
    expect(screen.queryByRole("button", { name: "Received" })).not.toBeInTheDocument()
    expect(screen.getByRole("columnheader", { name: "Received" })).toHaveAttribute("aria-sort", "descending")
    expect(controller.calls("GET", "/v1/events").every((call) => call.query.get("limit") === "20")).toBe(true)
  })

  it.each(["q", "source", "vector"] as const)("resets the cursor and searches complete history by %s", async (name) => {
    renderEvents()
    await screen.findByRole("link", { name: rows[0].victim_ip })
    await next(2)
    const value = name === "q" ? "DB8::225" : rows[224][name]
    fireEvent.change(screen.getByRole("textbox", { name: name === "q" ? "Search events" : `Exact ${name}` }), { target: { value } })
    await screen.findByRole("link", { name: rows[224].victim_ip })
    expect(screen.getByText("Page 1")).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
    const query = controller.calls("GET", "/v1/events").at(-1)!.query
    expect(query.get(name)).toBe(value)
    expect(query.has("cursor")).toBe(false)
    fireEvent.change(screen.getByRole("textbox", { name: name === "q" ? "Search events" : `Exact ${name}` }), { target: { value: "" } })
    await screen.findByRole("link", { name: rows[0].victim_ip })
  })

  it("preserves failed-page retry and previous navigation", async () => {
    failedCursor = "20"
    renderEvents()
    await screen.findByRole("link", { name: rows[0].victim_ip })
    fireEvent.click(screen.getByRole("button", { name: "Next" }))
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to load events")
    expect(screen.queryByText("No events yet")).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Previous" })).toBeEnabled()
    failedCursor = null
    fireEvent.click(screen.getByRole("button", { name: "Retry events" }))
    await screen.findByRole("link", { name: rows[20].victim_ip })
    fireEvent.click(screen.getByRole("button", { name: "Previous" }))
    await screen.findByRole("link", { name: rows[0].victim_ip })
  })

  it("opens a UUID deep link older than the former cap with keyboard focus", async () => {
    renderEvents(rows[224].event_id)
    const dialog = await screen.findByRole("dialog", { name: "Event details" })
    expect(within(dialog).getByRole("link", { name: rows[224].victim_ip })).toBeInTheDocument()
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Close panel" })).toHaveFocus())
    expect(controller.calls("GET", "/v1/events")[0].query.get("q")).toBe(rows[224].event_id)
    fireEvent.keyDown(document.activeElement!, { key: "Escape" })
    await waitFor(() => expect(screen.getByRole("region", { name: "Events" })).toHaveFocus())
  })

  it("opens an uppercase UUID deep link using the canonical selected ID", async () => {
    const target = rows[211]
    renderEvents(target.event_id.toUpperCase())
    const dialog = await screen.findByRole("dialog", { name: "Event details" })
    expect(within(dialog).getByRole("link", { name: target.victim_ip })).toBeInTheDocument()
    expect(controller.calls("GET", "/v1/events")[0].query.get("q")).toBe(target.event_id.toUpperCase())
  })

  it("opens a different event when client navigation changes the page's id parameter", async () => {
    const page = (id: string) => <SearchParamsContext.Provider value={new URLSearchParams({ id })}><EventsPage /></SearchParamsContext.Provider>
    const view = renderApp(page(rows[0].event_id), { withoutAuth: true })
    let dialog = await screen.findByRole("dialog", { name: "Event details" })
    expect(within(dialog).getByRole("link", { name: rows[0].victim_ip })).toBeInTheDocument()
    view.rerender(page(rows[224].event_id))
    await waitFor(() => {
      dialog = screen.getByRole("dialog", { name: "Event details" })
      expect(within(dialog).getByRole("link", { name: rows[224].victim_ip })).toBeInTheDocument()
    })
    expect(controller.calls("GET", "/v1/events").at(-1)?.query.get("q")).toBe(rows[224].event_id)
  })

  it.each(["Search events", "Exact source", "Exact vector"])("retains valid results for an oversized Unicode %s draft", async (name) => {
    renderEvents()
    await screen.findByRole("link", { name: rows[0].victim_ip })
    const reads = controller.calls("GET", "/v1/events").length
    fireEvent.change(screen.getByRole("textbox", { name }), { target: { value: "β".repeat(129) } })
    await settle()
    expect(controller.calls("GET", "/v1/events")).toHaveLength(reads)
    expect(screen.getByRole("textbox", { name })).toHaveAttribute("aria-invalid", "true")
    expect(screen.getByRole("alert")).toHaveTextContent("256 UTF-8 bytes")
    expect(screen.getByRole("button", { name: "Export CSV" })).toBeDisabled()
    fireEvent.change(screen.getByRole("textbox", { name }), { target: { value: "β".repeat(128) } })
    await screen.findByText("No matching events")
  })

  it("recovers from an empty search and keeps event details usable", async () => {
    renderEvents()
    await screen.findByRole("link", { name: rows[0].victim_ip })
    fireEvent.change(screen.getByRole("textbox", { name: "Search events" }), { target: { value: "missing" } })
    await screen.findByText("No matching events")
    fireEvent.click(screen.getByRole("button", { name: "Clear search and filters" }))
    await screen.findByRole("link", { name: rows[0].victim_ip })
    fireEvent.click(screen.getAllByRole("button", { name: "View event details" })[0])
    await screen.findByRole("dialog")
  })

  it("backs up after retention empties the current page", async () => {
    served = rows.slice(0, 21)
    const view = renderEvents()
    await screen.findByRole("link", { name: rows[0].victim_ip })
    await next(2)
    served = rows.slice(0, 20)
    await act(async () => { await view.mutate()(() => true) })
    await screen.findByRole("link", { name: rows[0].victim_ip })
    expect(screen.getByText("Page 1")).toBeInTheDocument()
  })

  it("does not let an older pending filter overwrite a newer filter", async () => {
    const pending = deferred<Response>()
    controller.route("GET", "/v1/events", ({ query }) => query.get("q") === "older" ? pending.promise : json({ events: [rows[224]], count: 1, has_more: false, next_cursor: null }))
    renderEvents()
    await screen.findByRole("link", { name: rows[224].victim_ip })
    fireEvent.change(screen.getByRole("textbox", { name: "Search events" }), { target: { value: "older" } })
    await waitFor(() => expect(controller.calls("GET", "/v1/events").at(-1)?.query.get("q")).toBe("older"))
    fireEvent.change(screen.getByRole("textbox", { name: "Search events" }), { target: { value: "newer" } })
    await screen.findByRole("link", { name: rows[224].victim_ip })
    pending.resolve(json({ events: [rows[0]], count: 1, has_more: false, next_cursor: null }))
    await settle()
    expect(screen.queryByRole("link", { name: rows[0].victim_ip })).not.toBeInTheDocument()
  })
})

describe("complete event CSV", () => {
  it("walks every matching page beyond 1000 and preserves exact filters", async () => {
    served = Array.from({ length: 1201 }, (_, index) => ({ ...rows[0], event_id: `00000000-0000-0000-0000-${(1201 - index).toString(16).padStart(12, "0")}` }))
    expect(await getAllEvents({ q: "DB8", source: "all", vector: "udp_flood" })).toHaveLength(1201)
    const calls = controller.calls("GET", "/v1/events")
    expect(calls).toHaveLength(2)
    expect(calls[1].query.get("cursor")).toBe("1000")
    expect(calls.every((call) => call.query.get("source") === "all" && call.query.get("q") === "DB8")).toBe(true)
  })

  it("keeps timestamp microseconds when validating descending rows", async () => {
    served = [{ ...rows[224], ingested_at: "2026-10-27T10:00:00.000002Z" }, { ...rows[0], ingested_at: "2026-10-27T10:00:00.000001Z" }]
    expect(await getAllEvents({})).toHaveLength(2)
  })

  it("serializes explicit empty filters for the API to validate", async () => {
    await getEvents({ source: "", vector: "", q: "" })
    expect(Object.fromEntries(controller.calls("GET", "/v1/events")[0].query)).toEqual({ source: "", vector: "", q: "" })
  })

  it.each(["duplicate", "ascending", "repeat", "missing", "empty"])("refuses a %s export continuation", async (kind) => {
    let calls = 0
    controller.route("GET", "/v1/events", () => {
      calls++
      const events = kind === "empty" ? [] : [kind === "ascending" && calls === 1 ? rows[1] : kind === "duplicate" || kind === "ascending" ? rows[0] : rows[Math.min(calls - 1, 224)]]

      return json({ events, count: events.length, has_more: true, next_cursor: kind === "missing" ? null : kind === "repeat" ? "same" : String(calls) })
    })
    await expect(getAllEvents({})).rejects.toThrow("Incomplete event export")
  })

  it("never downloads partial CSV when a later page fails", async () => {
    const original = URL.createObjectURL
    URL.createObjectURL = vi.fn(() => "blob:test")
    controller.route("GET", "/v1/events", ({ query }) => query.has("cursor") ? failure(502) : json({ events: [rows[0]], count: 1, has_more: true, next_cursor: "next" }))

    try {
      renderEvents()
      await screen.findByRole("link", { name: rows[0].victim_ip })
      fireEvent.click(screen.getByRole("button", { name: "Export CSV" }))
      expect(await screen.findByRole("alert")).toHaveTextContent("No file was downloaded")
      expect(URL.createObjectURL).not.toHaveBeenCalled()
      await waitFor(() => expect(screen.getByRole("button", { name: "Export CSV" })).toBeEnabled())
    } finally {
      URL.createObjectURL = original
    }
  })
})
