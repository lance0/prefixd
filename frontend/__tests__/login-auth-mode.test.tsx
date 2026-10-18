import { describe, expect, it } from "vitest"
import { fireEvent, screen, waitFor } from "@testing-library/react"
import LoginPage from "@/app/login/page"
import { deferred, failure, json, operatorResponse, renderApp, settle, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

/** Routes /v1/health and /v1/auth/me: a mode, a pending or failed health check, and a retained operator. */
function session({ mode, health = "ok", auth = "ok", authenticated = false }: {
  mode?: string
  health?: "ok" | "pending" | "failed"
  auth?: "ok" | "pending"
  authenticated?: boolean
}) {
  controller.route("GET", "/v1/health", () => health === "pending"
    ? deferred<Response>().promise
    : health === "failed" ? failure(503) : json({ status: "ok", version: "test", auth_mode: mode }))
  controller.route("GET", "/v1/auth/me", () => auth === "pending"
    ? deferred<Response>().promise
    : authenticated ? json(operatorResponse("admin")) : failure(401, "unauthorized"))
  controller.route("POST", "/v1/auth/login", () => json(operatorResponse("admin")))
}

describe("login authentication mode", () => {
  it.each([
    { label: "health is loading", health: "pending", auth: "ok", status: "Checking authentication…" },
    { label: "health failed", health: "failed", auth: "ok", status: "Unable to determine authentication mode" },
    { label: "auth is loading in credentials mode", health: "ok", auth: "pending", status: "Checking authentication…" },
  ] as const)("has no actionable form while $label", async ({ health, auth, status }) => {
    session({ mode: health === "ok" ? "credentials" : undefined, health, auth })
    const { router } = renderApp(<LoginPage />)
    await waitFor(() => expect(controller.calls("GET", "/v1/health")).toHaveLength(1))
    await settle()
    expect(screen.getByRole("status")).toHaveTextContent(status)
    expect(screen.queryByRole("textbox", { name: "Username" })).not.toBeInTheDocument()
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/auth/login")).toHaveLength(0)
    expect(router.push).not.toHaveBeenCalled()
  })

  it.each([false, true])("redirects anonymous mode without showing a form (retained login=%s)", async (authenticated) => {
    session({ mode: "none", authenticated })
    const { router } = renderApp(<LoginPage />)
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/"))
    expect(screen.queryByLabelText("Username")).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/auth/login")).toHaveLength(0)
  })

  it.each(["credentials", "bearer"])("preserves password sign in for %s mode", async (mode) => {
    session({ mode })
    const { router } = renderApp(<LoginPage />)
    fireEvent.change(await screen.findByRole("textbox", { name: "Username" }), { target: { value: "alice" } })
    fireEvent.change(screen.getByLabelText("Password"), { target: { value: "correct-password" } })
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/auth/login")).toHaveLength(1))
    expect(JSON.parse(controller.calls("POST", "/v1/auth/login")[0].body ?? "")).toEqual({ username: "alice", password: "correct-password" })
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/"))
  })

  it("keeps the form hidden until a known mode resolves, even with a retained operator", async () => {
    session({ health: "failed", authenticated: true })
    const { router } = renderApp(<LoginPage />)
    await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Unable to determine authentication mode"))
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
    expect(router.push).not.toHaveBeenCalled()
  })

  it("preserves the already authenticated credentials redirect", async () => {
    session({ mode: "credentials", authenticated: true })
    const { router } = renderApp(<LoginPage />)
    await waitFor(() => expect(router.push).toHaveBeenCalledWith("/"))
    expect(screen.queryByRole("button", { name: "Sign in" })).not.toBeInTheDocument()
  })
})
