import { act } from "react"
import { describe, expect, it } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
import { TimeZoneProvider } from "@/components/time-zone-provider"
import { RequireAuth } from "@/components/require-auth"
import { UserMenu } from "@/components/user-menu"
import { deferred, failure, json, operatorResponse, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

/** Routes the session: a mode, a pending or failed health check, and alice signed in unless `operator` is false. */
function session({ mode = "credentials", health = "ok", auth = "ok", operator = true }: {
  mode?: string
  health?: "ok" | "pending" | "failed"
  auth?: "ok" | "pending"
  operator?: boolean
}) {
  controller.route("GET", "/v1/health", () => health === "pending"
    ? deferred<Response>().promise
    : health === "failed" ? failure(503) : json({ status: "ok", version: "test", auth_mode: mode }))
  controller.route("GET", "/v1/auth/me", () => auth === "pending"
    ? deferred<Response>().promise
    : operator ? json(operatorResponse("admin", "alice")) : failure(401, "unauthorized"))
  controller.route("POST", "/v1/auth/logout", () => new Response(null, { status: 204 }))
  controller.route("GET", "/v1/preferences", () => json({ muted_events: [], quiet_hours_start: null, quiet_hours_end: null }))
}

async function openMenu() {
  fireEvent.keyDown(await screen.findByRole("button", { name: "Operator menu for alice" }), { key: "Enter" })
}

describe("operator menu authentication mode", () => {
  it.each([
    { pending: "health", mode: "credentials" },
    { pending: "auth", mode: "credentials" },
    { pending: "health", mode: "none" },
    { pending: "auth", mode: "none" },
  ])("waits for $pending before showing the resolved $mode menu", async ({ pending, mode }) => {
    session({ mode })
    const response = deferred<Response>()
    controller.route("GET", pending === "health" ? "/v1/health" : "/v1/auth/me", () => response.promise)
    renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    await settle()
    expect(screen.getByRole("status", { name: "Loading operator menu" })).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Preferences" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Operator menu for alice" })).not.toBeInTheDocument()
    expect(controller.calls("GET", "/v1/preferences")).toHaveLength(0)

    await act(async () => response.resolve(pending === "health"
      ? json({ status: "ok", version: "test", auth_mode: mode })
      : json(operatorResponse("admin", "alice"))))
    expect(await screen.findByRole("button", {
      name: mode === "none" ? "Preferences" : "Operator menu for alice",
    })).toBeInTheDocument()
    expect(screen.queryByRole("status", { name: "Loading operator menu" })).not.toBeInTheDocument()
  })

  it.each([
    { label: "mode is none", mode: "none", health: "ok", auth: "ok" },
    { label: "health is loading", mode: undefined, health: "pending", auth: "ok" },
    { label: "health failed", mode: undefined, health: "failed", auth: "ok" },
    { label: "auth is loading", mode: "credentials", health: "ok", auth: "pending" },
  ] as const)("hides a retained named operator when $label", async ({ mode, health, auth }) => {
    session({ mode, health, auth })
    renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    await waitFor(() => expect(controller.calls("GET", "/v1/health")).toHaveLength(1))
    await settle()
    expect(screen.queryByRole("button", { name: "Operator menu for alice" })).not.toBeInTheDocument()
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
    expect(screen.queryByText("Sign out")).not.toBeInTheDocument()
    expect(screen.queryByText("Quiet hours (UTC)")).not.toBeInTheDocument()
  })

  it("removes account preferences but keeps browser display settings when mode becomes none", async () => {
    session({})
    const { mutate } = renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    await openMenu()
    fireEvent.click(await screen.findByRole("menuitem", { name: "Preferences" }))
    expect(await screen.findByRole("dialog", { name: "Preferences" })).toBeInTheDocument()
    expect(await screen.findByText("Quiet hours (UTC)")).toBeInTheDocument()
    controller.route("GET", "/v1/health", () => json({ status: "ok", version: "test", auth_mode: "none" }))
    await act(() => mutate()("health"))
    await waitFor(() => expect(screen.queryByText("Quiet hours (UTC)")).not.toBeInTheDocument())
    expect(screen.getByRole("dialog", { name: "Preferences" })).toBeInTheDocument()
    expect(screen.getByLabelText("Display timezone")).toBeInTheDocument()
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/auth/logout")).toHaveLength(0)
  })

  it("preserves named sign out in credentials mode", async () => {
    session({ mode: "credentials" })
    const { router } = renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    await openMenu()
    fireEvent.click(await screen.findByRole("menuitem", { name: "Sign out" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/auth/logout")).toHaveLength(1))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/login"))
  })

  it("restores focus to the named menu after closing preferences", async () => {
    session({})
    renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    await openMenu()
    fireEvent.click(await screen.findByRole("menuitem", { name: "Preferences" }))
    expect(await screen.findByText("Quiet hours (UTC)")).toBeInTheDocument()
    fireEvent.keyDown(screen.getByRole("dialog", { name: "Preferences" }), { key: "Escape" })
    await waitFor(() => expect(screen.getByRole("button", { name: "Operator menu for alice" })).toHaveFocus())
  })

  it("keeps browser preferences available after health fails", async () => {
    session({ health: "failed" })
    renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    const trigger = await screen.findByRole("button", { name: "Preferences" })
    fireEvent.click(trigger)
    expect(await screen.findByRole("dialog", { name: "Preferences" })).toBeInTheDocument()
    expect(screen.getByRole("combobox", { name: "Display timezone" })).toBeInTheDocument()
    expect(screen.queryByText("Quiet hours (UTC)")).not.toBeInTheDocument()
    expect(controller.calls("GET", "/v1/preferences")).toHaveLength(0)
  })

  it.each([false, true])("keeps dashboard preferences mounted while retrying failed health (recovered: %s)", async (recovered) => {
    session({ health: "failed" })
    const { mutate } = renderApp(<TimeZoneProvider><RequireAuth><UserMenu /></RequireAuth></TimeZoneProvider>)
    fireEvent.click(await screen.findByRole("button", { name: "Preferences" }))
    const dialog = await screen.findByRole("dialog", { name: "Preferences" })
    const timeZone = screen.getByRole("combobox", { name: "Display timezone" })
    timeZone.focus()

    const response = deferred<Response>()
    controller.route("GET", "/v1/health", () => response.promise)
    let revalidation: Promise<unknown> | undefined
    await act(async () => { revalidation = mutate()("health") })
    await waitFor(() => expect(controller.calls("GET", "/v1/health")).toHaveLength(2))
    expect(screen.getByRole("dialog", { name: "Preferences" })).toBe(dialog)
    expect(screen.getByRole("combobox", { name: "Display timezone" })).toBe(timeZone)
    expect(timeZone).toBeEnabled()
    expect(timeZone).toHaveFocus()
    expect(screen.queryByRole("status", { name: "Loading operator menu" })).not.toBeInTheDocument()

    await act(async () => {
      response.resolve(recovered
        ? json({ status: "ok", version: "test", auth_mode: "credentials" })
        : failure(503))
      await revalidation
    })
    expect(screen.getByRole("dialog", { name: "Preferences" })).toBe(dialog)
    expect(screen.getByRole("combobox", { name: "Display timezone" })).toBe(timeZone)
    expect(timeZone).toHaveFocus()
    fireEvent.keyDown(dialog, { key: "Escape" })
    await waitFor(() => expect(screen.getByRole("button", {
      name: recovered ? "Operator menu for alice" : "Preferences",
    })).toHaveFocus())
  })

  it("does not grant dashboard access to an anonymous user after health fails or retries", async () => {
    session({ health: "failed", operator: false })
    const { router, mutate } = renderApp(<RequireAuth><UserMenu /></RequireAuth>)
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/login"))
    expect(screen.queryByRole("button", { name: "Preferences" })).not.toBeInTheDocument()
    const response = deferred<Response>()
    controller.route("GET", "/v1/health", () => response.promise)
    let revalidation: Promise<unknown> | undefined
    await act(async () => { revalidation = mutate()("health") })
    await waitFor(() => expect(controller.calls("GET", "/v1/health")).toHaveLength(2))
    expect(screen.queryByRole("button", { name: "Preferences" })).not.toBeInTheDocument()
    await act(async () => {
      response.resolve(failure(503))
      await revalidation
    })
    expect(screen.queryByRole("button", { name: "Preferences" })).not.toBeInTheDocument()
  })

  it("has no named controls without an authenticated operator", async () => {
    session({ operator: false })
    renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))
    await settle()
    expect(screen.getByRole("button", { name: "Preferences" })).toBeInTheDocument()
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
  })

  it.each(["none", "mtls"])("offers browser preferences without an account in %s mode", async (mode) => {
    session({ mode, operator: false })
    renderApp(<TimeZoneProvider><UserMenu /></TimeZoneProvider>)
    const trigger = await screen.findByRole("button", { name: "Preferences" })
    fireEvent.click(trigger)
    expect(await screen.findByRole("dialog", { name: "Preferences" })).toBeInTheDocument()
    expect(screen.getByRole("combobox", { name: "Display timezone" })).toBeInTheDocument()
    expect(screen.queryByText("Quiet hours (UTC)")).not.toBeInTheDocument()
    expect(controller.calls("GET", "/v1/preferences")).toHaveLength(0)
    expect(screen.queryByText("Sign out")).not.toBeInTheDocument()
    fireEvent.keyDown(screen.getByRole("dialog", { name: "Preferences" }), { key: "Escape" })
    await waitFor(() => expect(trigger).toHaveFocus())
  })
})
