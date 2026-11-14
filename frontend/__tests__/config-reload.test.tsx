import { cleanup, fireEvent, screen } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it } from "vitest"
import AdminPage from "@/app/(dashboard)/admin/page"
import ConfigPage from "@/app/(dashboard)/config/page"
import { json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const restartRequired = "Reloaded; restart required for http.listen, timers.reconciliation_interval_seconds"
const invalid = "Reload failed: prefixd.yaml is invalid; running configuration unchanged; see controller log"

beforeEach(() => signIn(controller, "credentials", operatorResponse("admin")))

afterEach(cleanup)

async function reload(button: string, response: Response, expected: string) {
  controller.route("POST", "/v1/config/reload", () => response)
  fireEvent.click(await screen.findByRole("button", { name: button }))

  return screen.findByText(expected)
}

/** Before the controller returned a body, both pages reported success or a bare "Reload failed". */
async function expectReloadStatus(button: string) {
  const warning = await reload(button, json({
    reloaded: ["inventory", "playbooks"],
    restart_required: ["http.listen", "timers.reconciliation_interval_seconds"],
    timestamp: "2026-11-14T00:00:00Z",
  }), restartRequired)

  expect(warning).toHaveAttribute("role", "status")
  expect(warning).toHaveClass("text-warning")

  const failure = await reload(button, json({
    error: "reload failed: prefixd.yaml is invalid; running configuration unchanged; see controller log",
  }, 422), invalid)

  expect(failure).toHaveAttribute("role", "status")
  expect(failure).toHaveClass("text-destructive")
  expect(screen.queryByText(restartRequired)).toBeNull()
}

describe("configuration reload status", () => {
  it("config page shows restart-required keys and the controller's failure reason", async () => {
    renderApp(<ConfigPage />, { url: "/config" })
    await expectReloadStatus("Reload")
  })

  it("admin page shows restart-required keys and the controller's failure reason", async () => {
    renderApp(<AdminPage />, { url: "/admin" })
    await expectReloadStatus("Reload configuration")
  })
})
