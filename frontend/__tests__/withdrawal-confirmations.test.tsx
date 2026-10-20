import { Suspense } from "react"
import { act, fireEvent, screen, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import MitigationDetailPage from "@/app/(dashboard)/mitigations/[id]/page"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import type { BulkWithdrawResponse, Mitigation } from "@/lib/api"
import { deferred, json, operatorResponse, renderApp, settle, signIn, useFakeController, type ApiHandler } from "./support/fake-controller"

const controller = useFakeController()

/** Flush UI timers without letting slow wall-clock execution trigger a 5 s SWR poll. */
async function waitFor<T>(read: () => T): Promise<T> {
  // Advance 20 ms per wait, never once per assertion retry: a missing
  // mutation refresh must not become a successful background poll.
  await act(() => vi.advanceTimersByTimeAsync(20))

  return vi.waitFor(async () => {
    await act(() => vi.advanceTimersByTimeAsync(0))

    return read()
  }, { interval: 0 })
}

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

const detailPath = `/v1/mitigations/${targets[0].mitigation_id}`

/** Serves the mitigations an operator sees: the list and the first target's detail. */
function serveMitigations(list: Mitigation[], detail: Mitigation) {
  controller.route("GET", "/v1/mitigations", () => json({ mitigations: list, count: list.length, next_cursor: null, has_more: false }))
  controller.route("GET", detailPath, () => json(detail))
}

/** Serves the withdrawn state once `refresh` lets the next read answer. */
function serveWithdrawnAfter(refresh: Promise<void>) {
  controller.route("GET", "/v1/mitigations", () => refresh.then(() => json({ mitigations: [], count: 0, next_cursor: null, has_more: false })))
  controller.route("GET", detailPath, () => refresh.then(() => json({ ...targets[0], status: "withdrawn" })))
}

/** Answers single withdrawals in order: each handler serves one request; the last repeats. */
function withdrawals(...handlers: ApiHandler[]) {
  controller.route("POST", `/v1/mitigations/${targets[0].mitigation_id}/withdraw`, (request) => (handlers.length > 1 ? handlers.shift()! : handlers[0])(request))
}

function bulkWithdrawals(...handlers: ApiHandler[]) {
  controller.route("POST", "/v1/mitigations/withdraw", (request) => (handlers.length > 1 ? handlers.shift()! : handlers[0])(request))
}

const completed = () => new Response("", { status: 200 })

function bodies(method: string, path: string) {
  return controller.calls(method, path).map((request) => JSON.parse(request.body ?? ""))
}

const readPath = (view: "list" | "detail") => view === "list" ? "/v1/mitigations" : detailPath

/** Reads of the view's mitigation data since it first loaded. */
function refreshes(view: "list" | "detail") {
  return controller.calls("GET", readPath(view)).length - 1
}

async function renderView(view: "list" | "detail") {
  const params = Promise.resolve({ id: targets[0].mitigation_id })

  const content = view === "list" ? <MitigationsContentLive /> : (
    <Suspense fallback={<p>Loading...</p>}>
      <MitigationDetailPage params={params} />
    </Suspense>
  )

  await act(async () => {
    renderApp(content, { url: view === "list" ? "/mitigations" : `/mitigations/${targets[0].mitigation_id}` })
  })
  await waitFor(() => expect(controller.calls("GET", readPath(view))).toHaveLength(1))
  await settle()
}

async function openSingle(view: "list" | "detail") {
  const trigger = view === "list"
    ? (await waitFor(() => screen.getAllByRole("button", { name: "Withdraw mitigation" })))[0]
    : await waitFor(() => screen.getByRole("button", { name: "Withdraw" }))

  act(() => trigger.focus())
  fireEvent.click(trigger)
  const dialog = await waitFor(() => screen.getByRole("alertdialog", { name: "Withdraw Mitigation" }))

  return { trigger, dialog }
}

async function openBulk() {
  fireEvent.click(screen.getByRole("checkbox", { name: "Select all active mitigations" }))
  const trigger = screen.getByRole("button", { name: "Withdraw all" })
  act(() => trigger.focus())
  fireEvent.click(trigger)
  const dialog = await waitFor(() => screen.getByRole("alertdialog", { name: "Bulk Withdraw Mitigations" }))

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
  vi.useFakeTimers()
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
  signIn(controller, "credentials", operatorResponse("operator"))
  controller.route("GET", "/v1/config/inventory", () => json({ customers: [], total_customers: 0, total_services: 0, total_assets: 0, loaded_at: createdAt }))
  serveMitigations(targets, targets[0])
})

afterEach(async () => {
  // Radix defers focus-scope cleanup until after the tree unmounts.
  await act(() => vi.advanceTimersByTimeAsync(0))
  vi.clearAllTimers()
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

// Full-page integration budget on throttled runners; see CONTRIBUTING.md.
describe.each(["list", "detail"] as const)("%s single withdrawal confirmation", { timeout: 10_000 }, (view) => {
  it("stays open while pending, blocks duplicates and dismissal, then closes on local completion", async () => {
    const pending = deferred<void>()
    withdrawals(() => pending.promise.then(() => completed()))
    await renderView(view)
    const { dialog } = await openSingle(view)
    expect(dialog).toHaveTextContent("Router convergence and traffic filtering are not verified here")
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "attack resolved" } })
    const submit = within(dialog).getByRole("button", { name: "Withdraw" })
    fireEvent.click(submit)
    fireEvent.click(submit)
    await waitFor(() => expect(bodies("POST", `/v1/mitigations/${targets[0].mitigation_id}/withdraw`)).toHaveLength(1))
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
    await waitFor(() => expect(refreshes(view)).toBe(1))
    expect(bodies("POST", `/v1/mitigations/${targets[0].mitigation_id}/withdraw`)).toHaveLength(1)
  })

  it("announces rejection and preserves the reason for a retry", async () => {
    const pending = deferred<void>()
    withdrawals(() => pending.promise.then(() => completed()), completed)
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
    expect(refreshes(view)).toBe(0)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(bodies("POST", `/v1/mitigations/${targets[0].mitigation_id}/withdraw`)).toEqual([
      { reason: "false positive", operator_id: "dashboard" },
      { reason: "false positive", operator_id: "dashboard" },
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
    expect(bodies("POST", `/v1/mitigations/${targets[0].mitigation_id}/withdraw`)).toEqual([])
    const reopened = await openSingle(view)
    expect(within(reopened.dialog).getByLabelText("Reason (optional)")).toHaveValue("")
  })

  it("restores focus to a stable control when completion removes the opener", async () => {
    const pending = deferred<void>()
    withdrawals(() => pending.promise.then(() => completed()))
    await renderView(view)
    const { trigger, dialog } = await openSingle(view)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    serveWithdrawnAfter(Promise.resolve())
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
    withdrawals(() => pending.promise.then(() => completed()))
    await renderView(view)
    serveWithdrawnAfter(refresh.promise)
    const { trigger, dialog } = await openSingle(view)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await act(async () => pending.resolve())
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(trigger).toBeInTheDocument()
    await waitFor(() => expect(refreshes(view)).toBe(1))

    const stableTarget = view === "list"
      ? screen.getByPlaceholderText("Search IP, vector or ID…")
      : screen.getByRole("link", { name: targets[0].victim_ip })

    await waitFor(() => expect([trigger, stableTarget]).toContain(document.activeElement))
    await act(async () => refresh.resolve())
    await waitFor(() => expect(trigger).not.toBeInTheDocument())
    await waitFor(() => expect(stableTarget).toHaveFocus())
  })
})

describe("bulk withdrawal confirmation", { timeout: 10_000 }, () => {
  it("preserves partial results and reason, retries only failures, and blocks duplicate pending requests", async () => {
    const pending = deferred<BulkWithdrawResponse>()
    bulkWithdrawals(() => pending.promise.then(json), () => json(bulkSuccess([targets[1].mitigation_id])))
    await renderView("list")
    const { dialog } = await openBulk()
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "incident resolved" } })
    const submit = within(dialog).getByRole("button", { name: "Withdraw 2" })
    fireEvent.click(submit)
    fireEvent.click(submit)
    await waitFor(() => expect(bodies("POST", "/v1/mitigations/withdraw")).toHaveLength(1))
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
    expect(bodies("POST", "/v1/mitigations/withdraw")).toEqual([
      { mitigation_ids: targets.map((target) => target.mitigation_id), reason: "incident resolved", operator_id: "dashboard" },
      { mitigation_ids: [targets[1].mitigation_id], reason: "incident resolved", operator_id: "dashboard" },
    ])
    await waitFor(() => expect(refreshes("list")).toBe(2))
    await waitFor(() => expect(screen.getByPlaceholderText("Search IP, vector or ID…")).toHaveFocus())
  })

  it("keeps all selected targets and the reason after a rejected request", async () => {
    bulkWithdrawals(() => new Response("Request failed", { status: 500 }), () => json(bulkSuccess(targets.map((target) => target.mitigation_id))))
    await renderView("list")
    const { dialog } = await openBulk()
    const reason = within(dialog).getByLabelText("Reason (optional)")
    fireEvent.change(reason, { target: { value: "retry whole request" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw 2" }))
    expect(await waitFor(() => within(dialog).getByRole("alert"))).toHaveTextContent("Request failed")
    expect(reason).toHaveValue("retry whole request")
    expect(refreshes("list")).toBe(0)
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw 2" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(bodies("POST", "/v1/mitigations/withdraw")).toEqual([
      { mitigation_ids: targets.map((target) => target.mitigation_id), reason: "retry whole request", operator_id: "dashboard" },
      { mitigation_ids: targets.map((target) => target.mitigation_id), reason: "retry whole request", operator_id: "dashboard" },
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
    expect(bodies("POST", "/v1/mitigations/withdraw")).toEqual([])
  })
})
