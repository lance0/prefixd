import { describe, expect, it } from "vitest"
import { screen, waitFor, within } from "@testing-library/react"
import type { ReactElement } from "react"
import type { OperatorRole } from "@/lib/auth"
import AdminPage from "@/app/(dashboard)/admin/page"
import { ActivityFeedLive } from "@/components/dashboard/activity-feed-live"
import { AuditLogContentLive } from "@/components/dashboard/audit-log-content-live"
import { CacheTab } from "@/components/dashboard/correlation/cache-tab"
import { json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

// The controller's read gates: GET /v1/audit needs operator; operators and the corroborator cache need admin.
const AUDIT = "/v1/audit"
const OPERATORS = "/v1/operators"
const CACHE = "/v1/signals/corroborator/cache"

const emptyAudit = { entries: [], count: 0, next_cursor: null, has_more: false }

async function renderAs(role: OperatorRole, ui: ReactElement, url = "/") {
  signIn(controller, "credentials", operatorResponse(role))
  controller.route("GET", "/v1/events", () => json({ events: [], count: 0, next_cursor: null, has_more: false }))
  controller.route("GET", AUDIT, () => json(emptyAudit))
  controller.route("GET", OPERATORS, () => json({ operators: [], count: 0 }))
  controller.route("GET", CACHE, () => json({ total: 0, by_source: [], signals: [] }))
  renderApp(ui, { url })
  await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))
  await settle()
  await settle()
}

describe("overview recent activity", () => {
  it("shows a viewer events only, without requesting the audit or reporting an error", async () => {
    await renderAs("viewer", <ActivityFeedLive />)
    const feed = await screen.findByRole("region", { name: "Recent activity" })

    expect(await within(feed).findByText(/needs the operator role/)).toBeInTheDocument()
    expect(controller.calls("GET", AUDIT)).toHaveLength(0)
    expect(controller.calls("GET", "/v1/events").length).toBeGreaterThan(0)
    expect(within(feed).queryByRole("alert")).not.toBeInTheDocument()
    expect(within(feed).queryByRole("link", { name: "View audit log" })).not.toBeInTheDocument()
  })

  it.each(["operator", "admin"] as const)("requests the audit for %s", async (role) => {
    await renderAs(role, <ActivityFeedLive />)

    await waitFor(() => expect(controller.calls("GET", AUDIT).length).toBeGreaterThan(0))
    expect(await screen.findByRole("link", { name: "View audit log" })).toHaveAttribute("href", "/audit-log")
  })
})

describe("audit log page", () => {
  it("explains the role limit to a viewer instead of a raw API error", async () => {
    await renderAs("viewer", <AuditLogContentLive />, "/audit-log")

    expect(await screen.findByText("The audit log needs the operator role")).toBeInTheDocument()
    expect(controller.calls("GET", AUDIT)).toHaveLength(0)
    expect(screen.queryByRole("alert")).not.toBeInTheDocument()
    expect(screen.queryByText(/API error/)).not.toBeInTheDocument()
  })

  it.each(["operator", "admin"] as const)("loads the audit for %s", async (role) => {
    await renderAs(role, <AuditLogContentLive />, "/audit-log")

    await waitFor(() => expect(controller.calls("GET", AUDIT)).toHaveLength(1))
    expect(screen.queryByText("The audit log needs the operator role")).not.toBeInTheDocument()
  })
})

describe("administration page", () => {
  it.each(["viewer", "operator"] as const)("does not list operator accounts for %s", async (role) => {
    await renderAs(role, <AdminPage />, "/admin")

    expect(controller.calls("GET", OPERATORS)).toHaveLength(0)
    expect(screen.queryByRole("tab", { name: /Users/ })).not.toBeInTheDocument()
  })

  it("lists operator accounts for an admin", async () => {
    await renderAs("admin", <AdminPage />, "/admin?tab=users")

    await waitFor(() => expect(controller.calls("GET", OPERATORS)).toHaveLength(1))
    expect(await screen.findByText("No operators configured")).toBeInTheDocument()
  })
})

describe("corroborator cache tab", () => {
  it.each(["viewer", "operator"] as const)("explains the role limit to %s without requesting the cache", async (role) => {
    await renderAs(role, <CacheTab />, "/correlation?tab=cache")

    expect(await screen.findByText("The corroborator cache needs the admin role")).toBeInTheDocument()
    expect(controller.calls("GET", CACHE)).toHaveLength(0)
  })

  it("loads the cache for an admin", async () => {
    await renderAs("admin", <CacheTab />, "/correlation?tab=cache")

    await waitFor(() => expect(controller.calls("GET", CACHE)).toHaveLength(1))
    expect(await screen.findByText("No corroborator signals cached")).toBeInTheDocument()
  })
})
