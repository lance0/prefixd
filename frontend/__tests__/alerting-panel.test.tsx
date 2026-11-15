import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import { AlertingConfigPanel } from "@/components/dashboard/alerting-config-panel"
import type { AlertingDestination } from "@/lib/api"
import { json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

beforeEach(() => {
  signIn(controller, "credentials", operatorResponse("admin"))
})

afterEach(() => {
  cleanup()
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
