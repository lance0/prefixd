import { act, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { beforeEach, describe, expect, it, vi } from "vitest"
import { EventsContentLive } from "@/components/dashboard/events-content-live"
import type { Event } from "@/lib/api"
import { json, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const events: Event[] = [1, 2, 3].map((n) => ({
  event_id: `event-${n}`, external_event_id: null, source: "fastnetmon",
  event_timestamp: new Date(Date.UTC(2026, 9, 22, 12) - n * 1000).toISOString(),
  ingested_at: new Date(Date.UTC(2026, 9, 22, 12) - n * 1000).toISOString(),
  victim_ip: `203.0.113.${n}`, vector: "udp_flood", protocol: 17, bps: 1000, pps: 10,
  top_dst_ports_json: "[53]", confidence: 0.9,
}))

let served: Event[] = events

beforeEach(() => {
  served = events
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  controller.route("GET", "/v1/events", () => json({ events: served, count: served.length, next_cursor: null, has_more: false }))
})

/** Keyboard activation of a native button: focus it, then the click Enter or Space dispatches. */
async function openByKeyboard(index: number) {
  const opener = (await screen.findAllByRole("button", { name: "View event details" }))[index]
  opener.focus()
  fireEvent.click(opener)
  await settle()

  return opener
}

describe("event detail dialog", () => {
  it("moves focus into a named modal dialog, contains Tab and restores the opener on Escape", async () => {
    renderApp(<EventsContentLive />, { withoutAuth: true })
    const opener = await openByKeyboard(1)

    const dialog = screen.getByRole("dialog", { name: "Event details" })
    const close = within(dialog).getByRole("button", { name: "Close panel" })
    expect(close).toHaveFocus()
    expect(within(dialog).getByRole("link", { name: "203.0.113.2" })).toBeInTheDocument()
    // The covered background leaves the accessibility tree.
    expect(screen.queryAllByRole("button", { name: "View event details" })).toHaveLength(0)

    const first = within(dialog).getByRole("link", { name: "203.0.113.2" })
    const last = within(dialog).getByRole("link", { name: /View mitigations for 203.0.113.2/ })
    last.focus()
    fireEvent.keyDown(last, { key: "Tab" })
    expect(first).toHaveFocus()
    fireEvent.keyDown(first, { key: "Tab", shiftKey: true })
    expect(last).toHaveFocus()

    fireEvent.keyDown(last, { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    await waitFor(() => expect(opener).toHaveFocus())
  })

  it("keeps the dialog open across live updates of the selected event", async () => {
    const { mutate } = renderApp(<EventsContentLive />, { withoutAuth: true })
    await openByKeyboard(1)
    served = events.map((e) => (e.event_id === "event-2" ? { ...e, bps: 5_000_000_000 } : e))
    await act(async () => { await mutate()(() => true) })

    const dialog = screen.getByRole("dialog", { name: "Event details" })
    expect(within(dialog).getByText(/^5,000,000,000\sbps$/)).toBeInTheDocument()
    expect(within(dialog).getByRole("button", { name: "Close panel" })).toHaveFocus()
  })

  it("closes and returns focus to the events list when the selected event leaves the live list", async () => {
    const { mutate } = renderApp(<EventsContentLive />, { withoutAuth: true })
    await openByKeyboard(1)
    served = events.filter((e) => e.event_id !== "event-2")
    await act(async () => { await mutate()(() => true) })

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole("region", { name: "Events" })).toHaveFocus())
    // The panel does not reopen if the event returns.
    served = events
    await act(async () => { await mutate()(() => true) })
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
  })

  it("opens the linked event as a focused dialog and closes back to the events list", async () => {
    renderApp(<EventsContentLive initialEventId="event-3" />, { withoutAuth: true })

    const dialog = await screen.findByRole("dialog", { name: "Event details" })
    expect(within(dialog).getByRole("link", { name: "203.0.113.3" })).toBeInTheDocument()
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Close panel" })).toHaveFocus())

    fireEvent.keyDown(document.activeElement!, { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    await waitFor(() => expect(screen.getByRole("region", { name: "Events" })).toHaveFocus())
  })
})
