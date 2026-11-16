import { act, cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { AlertingConfigPanel } from "@/components/dashboard/alerting-config-panel"
import type { AlertingDestination } from "@/lib/api"
import { deferred, settle, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  signIn(controller, "credentials", operatorResponse("admin"))

  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
})

afterEach(() => {
  cleanup()

  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

const destinations: AlertingDestination[] = [
  { type: "pagerduty", routing_key: "***", events_url: "https://example.net/pagerduty" },
  { type: "slack", webhook_url: "***", channel: "#alerts" },
]

/** The row that holds a destination's name, summary and test result. */
function destinationRow(label: string) {
  return screen.getByText(label).parentElement!.parentElement!
}

describe("alerting panel test results", () => {
  it("puts a result on the destination its configuration index names", async () => {
    controller.route("GET", "/v1/config/alerting", () => json({ destinations, events: [] }))
    // Two destinations, one result. The result array position is 0, and the
    // matching destination's configuration position is 1.
    controller.route("POST", "/v1/config/alerting/test", () =>
      json({ results: [{ index: 1, destination: "slack", status: "error", error: "slack returned 404" }] }),
    )
    renderApp(<AlertingConfigPanel />)

    fireEvent.click(await screen.findByRole("button", { name: "Test" }))

    await waitFor(() => expect(controller.calls("POST", "/v1/config/alerting/test")).toHaveLength(1))
    expect(await within(destinationRow("Slack")).findByText("slack returned 404")).toBeVisible()
    // Negative control: the old position-based match showed it on the first card.
    expect(within(destinationRow("PagerDuty")).queryByText("slack returned 404")).toBeNull()
  })
})

it("matches edit-mode results to the saved destination each card came from", async () => {
  controller.route("GET", "/v1/config/alerting", () => json({ destinations, events: [] }))
  // Test runs the saved configuration, so results name saved positions.
  controller.route("POST", "/v1/config/alerting/test", () =>
    json({
      results: [
        { index: 0, destination: "pagerduty", status: "error", error: "pagerduty test failure" },
        { index: 1, destination: "slack", status: "error", error: "slack test failure" },
      ],
    }),
  )
  renderApp(<AlertingConfigPanel />)
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }))
  fireEvent.click(screen.getByRole("button", { name: "Remove PagerDuty destination 1" }))
  fireEvent.keyDown(screen.getByRole("combobox"), { key: "Enter" })
  fireEvent.click(await screen.findByRole("option", { name: "Discord" }))
  fireEvent.click(screen.getByRole("button", { name: "Done" }))

  fireEvent.click(screen.getByRole("button", { name: "Test" }))

  // Slack is now draft card 0 and still saved destination 1.
  expect(await within(destinationRow("Slack")).findByText("slack test failure")).toBeVisible()
  // Negative controls: draft-position matching put saved destination 0's
  // result on Slack and saved destination 1's on the added Discord card.
  expect(screen.queryByText("pagerduty test failure")).toBeNull()
  expect(within(destinationRow("Discord")).queryByText("slack test failure")).toBeNull()
  expect(within(destinationRow("Discord")).queryByText(/test failure/)).toBeNull()
})

it("shows no result on draft cards after the saved configuration changes under the draft", async () => {
  let saved = destinations
  controller.route("GET", "/v1/config/alerting", () => json({ destinations: saved, events: [] }))
  // The saved configuration now holds only Slack, at index 0.
  controller.route("POST", "/v1/config/alerting/test", () =>
    json({ results: [{ index: 0, destination: "slack", status: "error", error: "slack test failure" }] }),
  )
  const app = renderApp(<AlertingConfigPanel />)
  fireEvent.click(await screen.findByRole("button", { name: "Edit" }))
  // Another operator removes PagerDuty while this draft is open.
  saved = [destinations[1]!]
  await act(async () => {
    await app.mutate()("alerting-config")
  })
  await waitFor(() => expect(controller.calls("GET", "/v1/config/alerting")).toHaveLength(2))

  fireEvent.click(screen.getByRole("button", { name: "Test" }))
  await waitFor(() => expect(controller.calls("POST", "/v1/config/alerting/test")).toHaveLength(1))
  await settle()

  // The draft still holds both cards, and neither saved position is trusted:
  // the PagerDuty card's old index 0 now names Slack.
  expect(within(destinationRow("PagerDuty")).queryByText("slack test failure")).toBeNull()
  expect(screen.queryByText("slack test failure")).toBeNull()
})

it("discards an in-flight test result when configuration is saved", async () => {
  const pending = deferred<Response>()
  controller.route("GET", "/v1/config/alerting", () => json({ destinations, events: [] }))
  controller.route("PUT", "/v1/config/alerting", () => json({ destinations, events: [] }))
  controller.route("POST", "/v1/config/alerting/test", () => pending.promise)
  renderApp(<AlertingConfigPanel />)
  fireEvent.click(await screen.findByRole("button", { name: "Test" }))
  await waitFor(() => expect(controller.calls("POST", "/v1/config/alerting/test")).toHaveLength(1))
  fireEvent.click(screen.getByRole("button", { name: "Edit" }))
  fireEvent.click(screen.getByRole("checkbox", { name: "mitigation.created" }))
  fireEvent.click(screen.getByRole("button", { name: "Save" }))
  await screen.findByRole("button", { name: "Edit" })
  pending.resolve(json({ results: [{ index: 1, destination: "slack", status: "error", error: "obsolete test failure" }] }))
  await settle()
  expect(screen.queryByText("obsolete test failure")).toBeNull()
})

describe("alerting panel options", () => {
  it("offers only the events prefixd sends", async () => {
    controller.route("GET", "/v1/config/alerting", () => json({ destinations, events: [] }))
    renderApp(<AlertingConfigPanel />)

    fireEvent.click(await screen.findByRole("button", { name: "Edit" }))

    expect(screen.getByRole("checkbox", { name: "mitigation.created" })).toBeVisible()
    expect(screen.getByRole("checkbox", { name: "mitigation.withdrawn" })).toBeVisible()
    expect(screen.getByRole("checkbox", { name: "mitigation.expired" })).toBeVisible()
    expect(screen.queryByRole("checkbox", { name: "config.reloaded" })).toBeNull()
    expect(screen.queryByRole("checkbox", { name: "guardrail.rejected" })).toBeNull()
  })

  it("labels the Slack channel as legacy-only with an explanation", async () => {
    controller.route("GET", "/v1/config/alerting", () => json({ destinations, events: [] }))
    renderApp(<AlertingConfigPanel />)

    fireEvent.click(await screen.findByRole("button", { name: "Edit" }))
    fireEvent.click(screen.getByRole("button", { name: "Edit Slack destination 2" }))

    const channel = screen.getByLabelText("Channel (legacy only)", { exact: true })
    expect(channel).toHaveValue("#alerts")
    expect(channel).toHaveAccessibleDescription(
      "Kept for legacy Slack integrations. An app's incoming webhook always posts to the channel it was created for and ignores this.",
    )
  })
})
