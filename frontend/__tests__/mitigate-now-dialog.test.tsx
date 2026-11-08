import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
import { MitigateNowDialog } from "@/components/dashboard/mitigate-now-dialog"
import { json, renderApp, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

function toastOf(text: string) {
  return screen.getByText(text).closest("[data-sonner-toast]")
}

// Real Radix form interactions on throttled runners; see CONTRIBUTING.md.
describe("manual mitigation creation outcome", { timeout: 10_000 }, () => {
  it.each([
    [" 203.0.113.10 ", "203.0.113.10", "global"],
    [" 2001:db8::10 ", "2001:db8::10", "global"],
    [" 203.0.113.10 ", "203.0.113.10", { ipv4: "TRANSIT", ipv6: "TRANSIT6" }],
    [" 2001:db8::10 ", "2001:db8::10", { ipv4: "TRANSIT", ipv6: "TRANSIT6" }],
  ] as const)("submits validated destination %s as %s for default %j", async (input, expected, defaultScope) => {
    controller.route("GET", "/v1/config/settings", () => json({ settings: { bgp: { default_scope: defaultScope } }, loaded_at: "2026-11-08T12:00:00Z" }))
    controller.route("POST", "/v1/events", () => json({ event_id: "event", mitigation_id: "saved-intent", status: "accepted" }))
    const { router } = renderApp(<MitigateNowDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    fireEvent.change(screen.getByLabelText(/Destination IP/), { target: { value: input } })
    fireEvent.keyDown(screen.getByRole("combobox", { name: /Attack Vector/ }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "UDP Flood" }))
    expect(screen.getByRole("button", { name: "Submit" })).toBeEnabled()
    fireEvent.click(screen.getByRole("button", { name: "Submit" }))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/mitigations/saved-intent"))
    const body = JSON.parse(controller.calls("POST", "/v1/events")[0].body ?? "")

    expect(body).toMatchObject({ victim_ip: expected, vector: "udp_flood", action: "ban" })
    expect(body).not.toHaveProperty("scope")
  })

  it.each([undefined, "unconfirmed"] as const)("opens saved intent and reports request outcome %s", async outcome => {
    controller.route("POST", "/v1/events", () => json({ event_id: "event", mitigation_id: "saved-intent", status: "accepted", announcement_outcome: outcome }))
    const close = vi.fn()
    const { router } = renderApp(<MitigateNowDialog open onOpenChange={close} />, { withoutAuth: true })
    fireEvent.change(screen.getByLabelText(/Destination IP/), { target: { value: "203.0.113.10" } })
    fireEvent.keyDown(screen.getByRole("combobox", { name: /Attack Vector/ }), { key: "Enter" })
    fireEvent.click(await screen.findByRole("option", { name: "UDP Flood" }))
    fireEvent.click(screen.getByRole("button", { name: "Submit" }))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/mitigations/saved-intent"))
    expect(close).toHaveBeenCalledWith(false)
    expect(JSON.parse(controller.calls("POST", "/v1/events")[0].body ?? "")).toEqual(expect.objectContaining({ victim_ip: "203.0.113.10", vector: "udp_flood", action: "ban" }))

    if (outcome === "unconfirmed") {
      await screen.findByText("Mitigation intent saved; announcement unconfirmed")
      expect(toastOf("Mitigation intent saved; announcement unconfirmed")).toHaveAttribute("data-type", "warning")
      expect(toastOf("Mitigation intent saved; announcement unconfirmed")).toHaveTextContent("saved for reconciliation")
      expect(screen.queryByText("Mitigation created")).not.toBeInTheDocument()
    } else {
      await screen.findByText("Mitigation created")
      expect(toastOf("Mitigation created")).toHaveAttribute("data-type", "success")
      expect(screen.queryByText("Mitigation intent saved; announcement unconfirmed")).not.toBeInTheDocument()
    }

    expect(screen.queryByText("Failed to create mitigation")).not.toBeInTheDocument()
  })
})
