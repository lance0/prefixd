import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { MitigationActivityChart } from "@/components/dashboard/mitigation-activity-chart"

const mock = vi.hoisted(() => ({
  data: undefined as { buckets: { bucket: string; count: number }[] } | undefined,
  error: undefined as Error | undefined,
  retry: vi.fn(),
}))

vi.mock("@/hooks/use-api", () => ({
  useTimeseries: () => ({ data: mock.data, error: mock.error, mutate: mock.retry }),
}))

afterEach(cleanup)

beforeEach(() => { mock.data = undefined; mock.error = undefined; mock.retry.mockReset() })

describe("overview activity states", () => {
  it("reports initial loading without claiming the range is empty", () => {
    render(<MitigationActivityChart />)
    expect(screen.getByRole("status")).toHaveTextContent("Loading activity")
    expect(screen.queryByText(/No activity in the last/)).not.toBeInTheDocument()
  })

  it("reports a failed initial request rather than loading forever", () => {
    mock.error = new Error("offline")
    render(<MitigationActivityChart />)
    expect(screen.getByRole("alert")).toHaveTextContent("Unable to load activity chart")
    expect(screen.queryByText(/Loading activity/)).not.toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Retry activity" })).toBeInTheDocument()
  })

  it("provides a next action only after a successful empty result", () => {
    mock.data = { buckets: [] }
    render(<MitigationActivityChart />)
    expect(screen.getByText("No activity in the last 24h")).toBeInTheDocument()
    expect(screen.getByRole("link", { name: "Review events" })).toHaveAttribute("href", "/events")
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  })
})
