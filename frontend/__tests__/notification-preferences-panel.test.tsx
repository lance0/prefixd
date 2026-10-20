import { afterEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { SWRConfig } from "swr"
import { NotificationPreferencesPanel } from "@/components/dashboard/notification-preferences"

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

// Real Radix form interactions on throttled runners; see CONTRIBUTING.md.
describe("notification preferences with a legacy escalated mute", { timeout: 10_000 }, () => {
  it("hides the escalated option and keeps the saved mute on save", async () => {
    const stored = { muted_events: ["mitigation.escalated"], quiet_hours_start: null, quiet_hours_end: null }

    const fetch = vi.fn(async (_url: string, init?: RequestInit) =>
      new Response(init?.method === "PUT" ? "" : JSON.stringify(stored), { status: 200 }))

    vi.stubGlobal("fetch", fetch)
    render(<SWRConfig value={{ provider: () => new Map() }}><NotificationPreferencesPanel /></SWRConfig>)

    fireEvent.click(await screen.findByLabelText(/Mitigation expired/))
    expect(screen.queryByText(/escalated/i)).toBeNull()
    fireEvent.click(screen.getByRole("button", { name: "Save preferences" }))

    await waitFor(() => expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/v1/preferences"),
      expect.objectContaining({ method: "PUT" }),
    ))
    const put = fetch.mock.calls.find(([, init]) => init?.method === "PUT")

    expect(JSON.parse(String(put?.[1]?.body))).toEqual({
      muted_events: ["mitigation.escalated", "mitigation.expired"],
      quiet_hours_start: null,
      quiet_hours_end: null,
    })
  })
})
