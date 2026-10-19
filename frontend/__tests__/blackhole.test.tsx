import { Suspense } from "react"
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { BlackholeDialog } from "@/components/dashboard/blackhole-dialog"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import type { Mitigation } from "@/lib/api"
import { failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const createdAt = new Date(Date.now() - 60_000).toISOString()

const blackhole: Mitigation = {
  mitigation_id: "00000000-0000-4000-8000-000000000066",
  scope_hash: "scope-blackhole",
  status: "active",
  customer_id: null,
  service_id: null,
  pop: "test-pop",
  victim_ip: "203.0.113.10",
  vector: "unknown",
  action_type: "blackhole",
  rate_bps: null,
  dst_prefix: "203.0.113.10/32",
  protocol: null,
  dst_ports: [],
  created_at: createdAt,
  updated_at: createdAt,
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  withdrawn_at: null,
  triggering_event_id: "event-1",
  last_event_id: "event-1",
  reason: "manual blackhole",
  acknowledged_at: null,
  acknowledged_by: null,
  origin_mode: "enforced",
  blackhole: { next_hop: "192.0.2.66", communities: ["64512:7", "65535:666"], large_communities: ["64512:1:2"] },
}

beforeEach(() => {
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({ media, matches: true, addEventListener: vi.fn(), removeEventListener: vi.fn() })))
  vi.stubGlobal("ResizeObserver", class {
    observe = vi.fn()
    unobserve = vi.fn()
    disconnect = vi.fn()
  })
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: createdAt }))
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: [blackhole], count: 1, next_cursor: null, has_more: false }))
  controller.route("GET", `/v1/mitigations/${blackhole.mitigation_id}`, () => json(blackhole))
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe("blackhole action badge", () => {
  it("uses the danger tone like discard, and police stays neutral", () => {
    render(<><ActionBadge actionType="blackhole" /><ActionBadge actionType="discard" /><ActionBadge actionType="police" rateBps={1_000_000} /></>)
    expect(screen.getByText("blackhole")).toHaveAttribute("data-tone", "danger")
    expect(screen.getByText("discard")).toHaveAttribute("data-tone", "danger")
    expect(screen.getByText(/police/)).not.toHaveAttribute("data-tone")
  })
})

describe("blackhole detail", () => {
  it("shows the saved route and that all traffic is dropped, not a FlowSpec rule", async () => {
    signIn(controller, "credentials", operatorResponse("operator"))
    await act(async () => {
      renderApp(
        <Suspense fallback={<p>Loading...</p>}>
          <MitigationDetailPage params={Promise.resolve({ id: blackhole.mitigation_id })} />
        </Suspense>,
        { url: `/mitigations/${blackhole.mitigation_id}` },
      )
    })
    const card = await screen.findByTestId("blackhole-card")
    expect(within(card).getByText("Blackhole route")).toBeInTheDocument()
    expect(within(card).getByRole("note")).toHaveTextContent("All traffic to 203.0.113.10 is dropped")
    expect(within(card).getByRole("note")).toHaveTextContent("not verified here")
    expect(within(card).getByText("192.0.2.66")).toBeInTheDocument()
    expect(within(card).getByText("64512:7 65535:666")).toBeInTheDocument()
    expect(within(card).getByText("64512:1:2")).toBeInTheDocument()
    expect(screen.queryByText("FlowSpec rule")).not.toBeInTheDocument()
    // Withdrawal keeps the existing confirmation.
    expect(screen.getByRole("button", { name: "Withdraw" })).toBeInTheDocument()
  })
})

describe("blackhole creation", () => {
  it.each([
    ["admin", true],
    ["operator", false],
    ["viewer", false],
  ] as const)("shows the blackhole control to %s only: %s", async (role, visible) => {
    signIn(controller, "credentials", operatorResponse(role))
    await act(async () => {
      renderApp(<MitigationsContentLive />, { url: "/mitigations" })
    })
    await settle()
    await screen.findByText("203.0.113.10")
    await waitFor(() => expect(controller.calls("GET", "/v1/auth/me").length).toBeGreaterThan(0))
    await settle()
    expect(screen.queryByRole("button", { name: "Blackhole a host" }) !== null).toBe(visible)

    // Mitigate now stays the event path for operators, with no blackhole option.
    if (role === "operator") expect(screen.getByRole("button", { name: "Mitigate now" })).toBeInTheDocument()
  })

  function fill(label: RegExp, value: string) {
    fireEvent.change(screen.getByLabelText(label), { target: { value } })
  }

  it("keeps submission disabled until the typed confirmation matches exactly", async () => {
    renderApp(<BlackholeDialog open onOpenChange={vi.fn()} />, { withoutAuth: true })
    const submit = screen.getByRole("button", { name: /Blackhole/ })
    fill(/^Victim IP/, "203.0.113.10")
    fill(/^Reason/, "attack")
    expect(submit).toBeDisabled()
    fill(/to confirm/, "203.0.113.1")
    expect(screen.getByText("Does not match the victim IP.")).toBeInTheDocument()
    expect(screen.getByLabelText(/to confirm/)).toHaveAttribute("aria-invalid", "true")
    expect(submit).toBeDisabled()
    // Submitting the form (Enter) with a mismatch sends nothing.
    fireEvent.submit(submit.closest("form")!)
    fill(/to confirm/, "203.0.113.10 ")
    expect(submit).toBeDisabled()
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
    fill(/to confirm/, "203.0.113.10")
    expect(screen.queryByText("Does not match the victim IP.")).not.toBeInTheDocument()
    expect(submit).toBeEnabled()
    expect(submit).toHaveTextContent("Blackhole 203.0.113.10")
  })

  it("completes from the keyboard and posts the confirmation to the controller", async () => {
    controller.route("POST", "/v1/mitigations", () => json({ ...blackhole }, 201))
    signIn(controller, "credentials", operatorResponse("admin"))
    let router: ReturnType<typeof renderApp>["router"] | undefined
    await act(async () => {
      router = renderApp(<MitigationsContentLive />, { url: "/mitigations" }).router
    })
    const trigger = await screen.findByRole("button", { name: "Blackhole a host" })
    act(() => trigger.focus())
    fireEvent.click(trigger)
    const dialog = await screen.findByRole("dialog", { name: "Blackhole a host" })
    // Focus moves into the dialog, and every control is reachable in reading order.
    await waitFor(() => expect(within(dialog).getByLabelText(/^Victim IP/)).toHaveFocus())
    const order = Array.from(dialog.querySelectorAll<HTMLElement>("input, button")).filter((element) => element.tabIndex >= 0)
    expect(order.map((element) => element.getAttribute("id") ?? element.textContent?.trim())).toEqual([
      "bh-ip", "bh-ttl", "bh-reason", "bh-confirm", "Cancel", "Blackhole host", "Close",
    ])
    fill(/^Victim IP/, "203.0.113.10")
    fill(/^Reason/, "volumetric attack")
    fill(/to confirm/, "203.0.113.10")
    // Enter in the confirmation field submits the form.
    fireEvent.submit(within(dialog).getByLabelText(/to confirm/).closest("form")!)
    await waitFor(() => expect(router?.push).toHaveBeenCalledWith(`/mitigations/${blackhole.mitigation_id}`))
    expect(JSON.parse(controller.calls("POST", "/v1/mitigations")[0].body ?? "")).toEqual({
      victim_ip: "203.0.113.10",
      confirm_victim_ip: "203.0.113.10",
      reason: "volumetric attack",
      ttl_seconds: 600,
      action: "blackhole",
    })
    await screen.findByText("Blackhole created")
  })

  it("shows the controller's refusal and keeps the dialog open", async () => {
    controller.route("POST", "/v1/mitigations", () => failure(403, "forbidden"))
    const close = vi.fn()
    renderApp(<BlackholeDialog open onOpenChange={close} />, { withoutAuth: true })
    fill(/^Victim IP/, "203.0.113.10")
    fill(/^Reason/, "attack")
    fill(/to confirm/, "203.0.113.10")
    fireEvent.click(screen.getByRole("button", { name: /Blackhole/ }))
    expect(await screen.findByRole("alert")).toHaveTextContent("API error 403")
    expect(close).not.toHaveBeenCalled()
  })

  it("closes on Escape without sending", async () => {
    const close = vi.fn()
    renderApp(<BlackholeDialog open onOpenChange={close} />, { withoutAuth: true })
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" })
    await waitFor(() => expect(close).toHaveBeenCalledWith(false))
    expect(controller.calls("POST", "/v1/mitigations")).toHaveLength(0)
  })
})
