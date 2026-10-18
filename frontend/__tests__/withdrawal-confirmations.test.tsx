import { Suspense, type ReactNode } from "react"
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import type { BulkWithdrawResponse, Mitigation } from "@/lib/api"

const mocks = vi.hoisted(() => ({
  useMitigations: vi.fn(),
  useMitigation: vi.fn(),
  withdraw: vi.fn(),
  bulkWithdraw: vi.fn(),
  mutate: vi.fn(),
}))

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: vi.fn(), back: vi.fn() }) }))
vi.mock("next/link", () => ({
  default: ({ children, href, ...props }: { children: ReactNode; href: string }) => (
    <a href={href} {...props}>{children}</a>
  ),
}))
vi.mock("@/hooks/use-api", () => ({
  useMitigations: mocks.useMitigations,
  useMitigation: mocks.useMitigation,
  useConfigInventory: () => ({ data: null }),
  useSignalGroupDetail: () => ({ data: null, isLoading: false }),
}))
vi.mock("@/hooks/use-permissions", () => ({
  usePermissions: () => ({ settled: true, canWithdraw: true }),
}))
vi.mock("@/lib/api", () => ({
  withdrawMitigation: mocks.withdraw,
  bulkWithdrawMitigations: mocks.bulkWithdraw,
  getIncidentReport: vi.fn(),
}))
vi.mock("@/components/dashboard/dashboard-layout", () => ({
  DashboardLayout: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}))
vi.mock("@/components/dashboard/mitigate-now-dialog", () => ({ MitigateNowDialog: () => null }))
vi.mock("@/components/dashboard/incident-report-dialog", () => ({ IncidentReportDialog: () => null }))

import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"

const createdAt = new Date(Date.now() - 60_000).toISOString()
const targets: Mitigation[] = [10, 11].map((suffix) => ({
  mitigation_id: `00000000-0000-4000-8000-0000000000${suffix}`,
  scope_hash: `scope-${suffix}`,
  status: "active",
  customer_id: null,
  service_id: null,
  pop: "test-pop",
  victim_ip: `203.0.113.${suffix}`,
  vector: "udp_flood",
  action_type: "discard",
  rate_bps: null,
  dst_prefix: `203.0.113.${suffix}/32`,
  protocol: 17,
  dst_ports: [53],
  created_at: createdAt,
  updated_at: createdAt,
  expires_at: new Date(Date.now() + 600_000).toISOString(),
  withdrawn_at: null,
  triggering_event_id: "event-1",
  last_event_id: "event-1",
  reason: "test mitigation",
  acknowledged_at: null,
  acknowledged_by: null,
}))

function deferred<T>() {
  let resolve!: (value: T) => void
  let reject!: (reason: Error) => void
  const promise = new Promise<T>((res, rej) => { resolve = res; reject = rej })
  return { promise, resolve, reject }
}

async function renderView(view: "list" | "detail") {
  const params = Promise.resolve({ id: targets[0].mitigation_id })
  const content = () => view === "list" ? <MitigationsContentLive /> : (
    <Suspense fallback={<p>Loading...</p>}>
      <MitigationDetailPage params={params} />
    </Suspense>
  )
  let rendered!: ReturnType<typeof render>
  await act(async () => {
    rendered = render(content())
  })
  return () => rendered.rerender(content())
}

async function openSingle(view: "list" | "detail") {
  const trigger = view === "list"
    ? (await screen.findAllByRole("button", { name: "Withdraw mitigation" }))[0]
    : await screen.findByRole("button", { name: "Withdraw" })
  act(() => trigger.focus())
  fireEvent.click(trigger)
  const dialog = await screen.findByRole("alertdialog", { name: "Withdraw Mitigation" })
  return { trigger, dialog }
}

async function openBulk() {
  fireEvent.click(screen.getByRole("checkbox", { name: "Select all active mitigations" }))
  const trigger = screen.getByRole("button", { name: "Withdraw all" })
  act(() => trigger.focus())
  fireEvent.click(trigger)
  const dialog = await screen.findByRole("alertdialog", { name: "Bulk Withdraw Mitigations" })
  return { trigger, dialog }
}

function bulkSuccess(ids: string[]): BulkWithdrawResponse {
  return {
    withdrawn: ids.length,
    failed: 0,
    results: ids.map((mitigation_id) => ({ mitigation_id, status: "withdrawn" })),
  }
}

beforeEach(() => {
  vi.resetAllMocks()
  vi.stubGlobal("matchMedia", vi.fn((media: string) => ({
    media,
    matches: true,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  })))
  vi.stubGlobal("ResizeObserver", class {
    observe = vi.fn()
    unobserve = vi.fn()
    disconnect = vi.fn()
  })
  mocks.mutate.mockResolvedValue(undefined)
  mocks.useMitigations.mockReturnValue({ data: { mitigations: targets }, mutate: mocks.mutate })
  mocks.useMitigation.mockReturnValue({ data: targets[0], mutate: mocks.mutate })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

describe.each(["list", "detail"] as const)("%s single withdrawal confirmation", (view) => {
  it("stays open while pending, blocks duplicates and dismissal, then closes on local completion", async () => {
    const pending = deferred<void>()
    mocks.withdraw.mockReturnValue(pending.promise)
    await renderView(view)
    const { dialog } = await openSingle(view)
    expect(dialog).toHaveTextContent("Router convergence and traffic filtering are not verified here")
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "attack resolved" } })
    const submit = within(dialog).getByRole("button", { name: "Withdraw" })
    fireEvent.click(submit)
    fireEvent.click(submit)
    expect(mocks.withdraw).toHaveBeenCalledTimes(1)
    expect(dialog).toBeVisible()
    expect(submit).toBeDisabled()
    expect(reason).toBeDisabled()
    const cancel = within(dialog).getByRole("button", { name: "Cancel" })
    expect(cancel).toBeDisabled()
    expect(within(dialog).getByRole("status")).toHaveTextContent("Waiting for local withdrawal completion")
    fireEvent.click(cancel)
    fireEvent.keyDown(dialog, { key: "Escape" })
    expect(dialog).toBeVisible()
    await act(async () => pending.resolve())
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    const stableTarget = view === "list"
      ? screen.getByPlaceholderText("Search IP, vector or ID…")
      : screen.getByRole("link", { name: targets[0].victim_ip })
    await waitFor(() => expect(stableTarget).toHaveFocus())
    expect(mocks.mutate).toHaveBeenCalledTimes(1)
  })

  it("announces rejection and preserves the reason for a retry", async () => {
    const pending = deferred<void>()
    mocks.withdraw.mockReturnValueOnce(pending.promise).mockResolvedValueOnce(undefined)
    await renderView(view)
    const { dialog } = await openSingle(view)
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "false positive" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await act(async () => pending.reject(new Error("Speaker reply lost")))
    expect(dialog).toBeVisible()
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Speaker reply lost")
    expect(within(dialog).getByRole("alert")).toHaveTextContent("Cleanup may still be pending")
    expect(reason).toHaveValue("false positive")
    expect(reason).toBeEnabled()
    expect(mocks.mutate).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(mocks.withdraw.mock.calls).toEqual([
      [targets[0].mitigation_id, "false positive", "dashboard"],
      [targets[0].mitigation_id, "false positive", "dashboard"],
    ])
  })

  it.each(["Cancel", "Escape"])("allows explicit %s before submission and restores focus", async (action) => {
    await renderView(view)
    const { trigger, dialog } = await openSingle(view)
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus())
    fireEvent.change(within(dialog).getByLabelText("Reason (optional)"), { target: { value: "cancelled reason" } })
    if (action === "Cancel") fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))
    else fireEvent.keyDown(dialog, { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    await waitFor(() => expect(trigger).toHaveFocus())
    expect(mocks.withdraw).not.toHaveBeenCalled()
    const reopened = await openSingle(view)
    expect(within(reopened.dialog).getByLabelText("Reason (optional)")).toHaveValue("")
  })

  it("restores focus to a stable control when completion removes the opener", async () => {
    const pending = deferred<void>()
    mocks.withdraw.mockReturnValue(pending.promise)
    await renderView(view)
    const { trigger, dialog } = await openSingle(view)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    mocks.useMitigations.mockReturnValue({ data: { mitigations: [] }, mutate: mocks.mutate })
    mocks.useMitigation.mockReturnValue({ data: { ...targets[0], status: "withdrawn" }, mutate: mocks.mutate })
    await act(async () => pending.resolve())
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(trigger).not.toBeInTheDocument()
    const fallback = view === "list"
      ? screen.getByPlaceholderText("Search IP, vector or ID…")
      : screen.getByRole("link", { name: targets[0].victim_ip })
    await waitFor(() => expect(fallback).toHaveFocus())
  })

  it("keeps focus stable when refreshed data removes the opener after closure", async () => {
    const pending = deferred<void>()
    const refresh = deferred<void>()
    mocks.withdraw.mockReturnValue(pending.promise)
    const rerender = await renderView(view)
    mocks.mutate.mockImplementationOnce(() => refresh.promise.then(() => {
      mocks.useMitigations.mockReturnValue({ data: { mitigations: [] }, mutate: mocks.mutate })
      mocks.useMitigation.mockReturnValue({ data: { ...targets[0], status: "withdrawn" }, mutate: mocks.mutate })
      rerender()
    }))
    const { trigger, dialog } = await openSingle(view)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await act(async () => pending.resolve())
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(trigger).toBeInTheDocument()
    expect(mocks.mutate).toHaveBeenCalledTimes(1)
    const stableTarget = view === "list"
      ? screen.getByPlaceholderText("Search IP, vector or ID…")
      : screen.getByRole("link", { name: targets[0].victim_ip })
    await waitFor(() => expect([trigger, stableTarget]).toContain(document.activeElement))
    await act(async () => refresh.resolve())
    expect(trigger).not.toBeInTheDocument()
    await waitFor(() => expect(stableTarget).toHaveFocus())
  })
})

describe("bulk withdrawal confirmation", () => {
  it("preserves partial results and reason, retries only failures, and blocks duplicate pending requests", async () => {
    const pending = deferred<BulkWithdrawResponse>()
    mocks.bulkWithdraw.mockReturnValueOnce(pending.promise)
      .mockResolvedValueOnce(bulkSuccess([targets[1].mitigation_id]))
    await renderView("list")
    const { dialog } = await openBulk()
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "incident resolved" } })
    const submit = within(dialog).getByRole("button", { name: "Withdraw 2" })
    fireEvent.click(submit)
    fireEvent.click(submit)
    expect(mocks.bulkWithdraw).toHaveBeenCalledTimes(1)
    expect(dialog).toBeVisible()
    expect(submit).toBeDisabled()
    expect(reason).toBeDisabled()
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeDisabled()
    fireEvent.keyDown(dialog, { key: "Escape" })
    expect(dialog).toBeVisible()
    await act(async () => pending.resolve({
      withdrawn: 1,
      failed: 1,
      results: [
        { mitigation_id: targets[0].mitigation_id, status: "withdrawn" },
        { mitigation_id: targets[1].mitigation_id, status: "error", error: "speaker withdrawal failed" },
      ],
    }))
    expect(dialog).toBeVisible()
    expect(reason).toHaveValue("incident resolved")
    expect(within(dialog).getByRole("alert")).toHaveTextContent("1 completed locally, 1 failed")
    const results = within(dialog).getByRole("list", { name: "Withdrawal results" })
    expect(results).toHaveTextContent(`${targets[0].mitigation_id}: Completed locally`)
    expect(results).toHaveTextContent(`${targets[1].mitigation_id}: speaker withdrawal failed`)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw 1" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(mocks.bulkWithdraw.mock.calls).toEqual([
      [targets.map((target) => target.mitigation_id), "incident resolved", "dashboard"],
      [[targets[1].mitigation_id], "incident resolved", "dashboard"],
    ])
    expect(mocks.mutate).toHaveBeenCalledTimes(2)
    await waitFor(() => expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toHaveFocus())
  })

  it("keeps all selected targets and the reason after a rejected request", async () => {
    mocks.bulkWithdraw.mockRejectedValueOnce(new Error("Request failed"))
      .mockResolvedValueOnce(bulkSuccess(targets.map((target) => target.mitigation_id)))
    await renderView("list")
    const { dialog } = await openBulk()
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "retry whole request" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw 2" }))
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Request failed")
    expect(reason).toHaveValue("retry whole request")
    expect(mocks.mutate).not.toHaveBeenCalled()
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw 2" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(mocks.bulkWithdraw.mock.calls).toEqual([
      [targets.map((target) => target.mitigation_id), "retry whole request", "dashboard"],
      [targets.map((target) => target.mitigation_id), "retry whole request", "dashboard"],
    ])
  })

  it.each(["Cancel", "Escape"])("allows explicit %s and returns focus without submitting", async (action) => {
    await renderView("list")
    const { trigger, dialog } = await openBulk()
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus())
    if (action === "Cancel") fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))
    else fireEvent.keyDown(dialog, { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    await waitFor(() => expect(trigger).toHaveFocus())
    expect(mocks.bulkWithdraw).not.toHaveBeenCalled()
  })
})
