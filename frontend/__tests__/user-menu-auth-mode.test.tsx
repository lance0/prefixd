import { act } from "react"
import { describe, expect, it } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
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
    { label: "mode is none", mode: "none", health: "ok", auth: "ok" },
    { label: "health is loading", mode: undefined, health: "pending", auth: "ok" },
    { label: "health failed", mode: undefined, health: "failed", auth: "ok" },
    { label: "auth is loading", mode: "credentials", health: "ok", auth: "pending" },
  ] as const)("hides a retained named operator when $label", async ({ mode, health, auth }) => {
    session({ mode, health, auth })
    renderApp(<UserMenu />)
    await waitFor(() => expect(controller.calls("GET", "/v1/health")).toHaveLength(1))
    await settle()
    expect(screen.queryByRole("button", { name: "Operator menu for alice" })).not.toBeInTheDocument()
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
    expect(screen.queryByText("Sign out")).not.toBeInTheDocument()
    expect(screen.queryByText("Quiet hours (UTC)")).not.toBeInTheDocument()
  })

  it("removes an open named preferences dialog when mode becomes none", async () => {
    session({})
    const { mutate } = renderApp(<UserMenu />)
    await openMenu()
    fireEvent.click(await screen.findByRole("menuitem", { name: "Notifications" }))
    expect(await screen.findByRole("dialog", { name: "Notification preferences" })).toBeInTheDocument()
    expect(await screen.findByText("Quiet hours (UTC)")).toBeInTheDocument()
    controller.route("GET", "/v1/health", () => json({ status: "ok", version: "test", auth_mode: "none" }))
    await act(() => mutate()("health"))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(screen.queryByText("alice")).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/auth/logout")).toHaveLength(0)
  })

  it.each(["credentials", "bearer"])("preserves named sign out in %s mode", async (mode) => {
    session({ mode })
    const { router } = renderApp(<UserMenu />)
    await openMenu()
    fireEvent.click(await screen.findByRole("menuitem", { name: "Sign out" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/auth/logout")).toHaveLength(1))
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/login"))
  })

  it("has no named controls without an authenticated operator", async () => {
    session({ operator: false })
    renderApp(<UserMenu />)
    await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))
    await settle()
    expect(screen.queryByRole("button")).not.toBeInTheDocument()
  })
})
