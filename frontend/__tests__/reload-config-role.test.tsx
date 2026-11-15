import { describe, expect, it } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import type { OperatorRole } from "@/lib/auth"
import AdminPage from "@/app/(dashboard)/admin/page"
import { json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

async function renderAs(role: OperatorRole) {
  signIn(controller, "credentials", operatorResponse(role))
  controller.route("GET", "/v1/operators", () => json({ operators: [], count: 0 }))
  renderApp(<AdminPage />, { url: "/admin" })
  await waitFor(() => expect(controller.calls("GET", "/v1/auth/me")).toHaveLength(1))
  await settle()
  await settle()
}

describe("administration page reload configuration", () => {
  it.each(["viewer", "operator"] as const)("hides the reload button for %s", async (role) => {
    await renderAs(role)

    expect(screen.queryByRole("button", { name: "Reload configuration" })).not.toBeInTheDocument()
  })

  it("shows the reload button for an admin", async () => {
    await renderAs("admin")

    expect(await screen.findByRole("button", { name: "Reload configuration" })).toBeEnabled()
  })
})
