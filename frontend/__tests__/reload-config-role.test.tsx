import { describe, expect, it } from "vitest"
import { act, fireEvent, screen, waitFor } from "@testing-library/react"
import type { OperatorRole } from "@/lib/auth"
import { usePermissions } from "@/hooks/use-permissions"
import AdminPage from "@/app/(dashboard)/admin/page"
import { deferred, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
const reloadButton = { name: "Reload configuration" }

function PermissionProbe() {
  const { settled, role } = usePermissions()

  return <output aria-label="Resolved role">{settled ? role : "loading"}</output>
}

function renderAdmin() {
  controller.route("GET", "/v1/operators", () => json({ operators: [], count: 0 }))

  return renderApp(<><PermissionProbe /><AdminPage /></>, { url: "/admin" })
}

async function renderAs(role: OperatorRole) {
  signIn(controller, "credentials", operatorResponse(role))
  const app = renderAdmin()
  await waitFor(() => expect(screen.getByLabelText("Resolved role")).toHaveTextContent(role))

  return app
}

describe("administration page reload configuration", () => {
  it.each(["viewer", "operator"] as const)("hides the reload button for %s", async (role) => {
    await renderAs(role)

    expect(screen.queryByRole("button", reloadButton)).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/config/reload")).toHaveLength(0)
  })

  it("waits for authentication before showing the admin reload button", async () => {
    const session = deferred<Response>()
    signIn(controller, "credentials", operatorResponse("admin"))
    controller.route("GET", "/v1/auth/me", () => session.promise)
    renderAdmin()
    await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))

    expect(screen.queryByRole("button", reloadButton)).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/config/reload")).toHaveLength(0)

    await act(async () => session.resolve(json(operatorResponse("admin"))))
    expect(await screen.findByRole("button", reloadButton)).toBeEnabled()
  })

  it("prevents duplicate admin reloads and allows retry after a failed request", async () => {
    await renderAs("admin")
    const pending = deferred<Response>()
    controller.route("POST", "/v1/config/reload", () => pending.promise)
    const button = screen.getByRole("button", reloadButton)
    fireEvent.click(button)
    expect(button).toBeDisabled()
    fireEvent.click(button)
    expect(controller.calls("POST", "/v1/config/reload")).toHaveLength(1)

    await act(async () => pending.resolve(json({ error: "reload failed: invalid configuration" }, 422)))
    expect(await screen.findByText("Reload failed: invalid configuration")).toBeVisible()
    expect(button).toBeEnabled()

    controller.route("POST", "/v1/config/reload", () => json({
      reloaded: ["inventory"], restart_required: ["http.listen"], timestamp: "2026-11-15T00:00:00Z",
    }))
    fireEvent.click(button)
    expect(await screen.findByText("Reloaded; restart required for http.listen")).toBeVisible()
    expect(screen.queryByText("Reload failed: invalid configuration")).not.toBeInTheDocument()
    expect(button).toBeEnabled()
    expect(controller.calls("POST", "/v1/config/reload")).toHaveLength(2)
  })

  it("removes the reload button when the admin session expires", async () => {
    const app = await renderAs("admin")
    expect(screen.getByRole("button", reloadButton)).toBeEnabled()

    act(() => window.dispatchEvent(new Event("prefixd:auth-expired")))

    expect(screen.queryByRole("button", reloadButton)).not.toBeInTheDocument()
    expect(app.router.push).toHaveBeenCalledWith("/login")
    expect(controller.calls("POST", "/v1/config/reload")).toHaveLength(0)
  })
})
