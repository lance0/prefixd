import { describe, expect, it } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
import { MitigationActivityChart } from "@/components/dashboard/mitigation-activity-chart"
import { deferred, failure, json, renderApp, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const render = () => renderApp(<MitigationActivityChart />, { withoutAuth: true })

describe("overview activity states", () => {
  it("reports initial loading without claiming the range is empty", async () => {
    controller.route("GET", "/v1/stats/timeseries", () => deferred<Response>().promise)
    render()
    await waitFor(() => expect(controller.calls("GET", "/v1/stats/timeseries")).toHaveLength(2))
    expect(screen.getByRole("status", { name: "Loading activity" })).toHaveTextContent("Loading activity")
    expect(screen.queryByText(/No activity in the last/)).not.toBeInTheDocument()
  })

  it("reports a failed initial request rather than loading forever", async () => {
    controller.route("GET", "/v1/stats/timeseries", () => failure(503, "offline"))
    render()
    expect(await screen.findByRole("alert")).toHaveTextContent("Unable to load activity chart")
    expect(screen.queryByText(/Loading activity/)).not.toBeInTheDocument()
    const retry = screen.getByRole("button", { name: "Retry activity" })
    const before = controller.calls("GET", "/v1/stats/timeseries").length
    fireEvent.click(retry)
    await waitFor(() => expect(controller.calls("GET", "/v1/stats/timeseries").length).toBe(before + 2))
  })

  it("provides a next action only after a successful empty result", async () => {
    controller.route("GET", "/v1/stats/timeseries", () => json({ buckets: [] }))
    render()
    expect(await screen.findByText("No activity in the last 24h")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Review events" })).toHaveAttribute("href", "/events")
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })
})
