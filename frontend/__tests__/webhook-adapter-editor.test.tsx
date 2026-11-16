import { fireEvent, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { WebhookAdaptersEditor } from "@/components/dashboard/correlation/webhook-adapters"
import type { CorrelationConfig } from "@/lib/api"
import { act } from "react"
import { deferred, json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

const correlation: CorrelationConfig = {
  enabled: true, window_seconds: 60, min_sources: 1, confidence_threshold: 0.5,
  default_weight: 1, sources: {}, webhook_adapters: [],
}

const refusal = "webhook_adapter 'radware': auth.secret_env PREFIXD_WEBHOOK_RADWARE_SECRET must hold at least 32 bytes"

beforeEach(() => {
  signIn(controller, "credentials", operatorResponse("admin"))
  controller.route("GET", "/v1/config/correlation", () => json({ config: correlation, loaded_at: "2026-11-16T00:00:00Z" }))
})

afterEach(() => {
  vi.restoreAllMocks()
})

async function draft() {
  renderApp(<WebhookAdaptersEditor />)
  fireEvent.click(await screen.findByRole("button", { name: "Add adapter" }))
  const dialog = within(await screen.findByRole("dialog", { name: "New webhook adapter" }))
  fireEvent.change(dialog.getByRole("textbox", { name: "Name" }), { target: { value: "radware" } })

  return dialog
}

describe("webhook adapter editor", () => {
  it("names the secret namespace and size, and refuses an out-of-namespace variable before saving", async () => {
    const dialog = await draft()
    const secret = dialog.getByRole("textbox", { name: "Secret env var" })
    expect(secret).toHaveAccessibleDescription(/starting with PREFIXD_WEBHOOK_, holding at least 32 bytes/)
    expect(dialog.getByRole("textbox", { name: "source_id" })).toHaveAccessibleDescription(/Required on an HMAC adapter that maps action or is named in blackhole.detector_sources/)
    fireEvent.change(secret, { target: { value: "RADWARE_SECRET" } })
    expect(dialog.getByText("auth.secret_env must start with PREFIXD_WEBHOOK_")).toBeInTheDocument()
    expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled()
  })

  it("keeps the editor open with the controller's 400 reasons", async () => {
    controller.route("PUT", "/v1/config/correlation", () => json({ errors: [refusal] }, 400))
    const dialog = await draft()
    fireEvent.change(dialog.getByRole("textbox", { name: "Secret env var" }), { target: { value: "PREFIXD_WEBHOOK_RADWARE_SECRET" } })
    fireEvent.click(dialog.getByRole("button", { name: "Save" }))

    expect(await dialog.findByRole("alert")).toHaveTextContent(refusal)
    expect(dialog.getByRole("alert")).not.toHaveTextContent("API error")
    expect(screen.getByRole("dialog", { name: "New webhook adapter" })).toBeInTheDocument()
    expect(dialog.getByRole("textbox", { name: "Name" })).toHaveValue("radware")
  })

  it("keeps the editor until its save lands, so a late completion cannot close another draft", async () => {
    const save = deferred<Response>()
    controller.route("PUT", "/v1/config/correlation", () => save.promise)
    const dialog = await draft()
    fireEvent.change(dialog.getByRole("textbox", { name: "Secret env var" }), { target: { value: "PREFIXD_WEBHOOK_RADWARE_SECRET" } })
    fireEvent.click(dialog.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(controller.calls("PUT", "/v1/config/correlation")).toHaveLength(1))

    expect(dialog.getByRole("button", { name: "Cancel" })).toBeDisabled()
    fireEvent.keyDown(dialog.getByRole("textbox", { name: "Name" }), { key: "Escape" })
    expect(screen.getByRole("dialog", { name: "New webhook adapter" })).toBeInTheDocument()
    expect(dialog.getByRole("textbox", { name: "Name" })).toHaveValue("radware")

    await act(async () => { save.resolve(json({ config: correlation, loaded_at: "2026-11-16T00:00:00Z" })) })
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "New webhook adapter" })).not.toBeInTheDocument())
  })

  it("closes once the controller accepts the adapter", async () => {
    controller.route("PUT", "/v1/config/correlation", (request) => json({ config: JSON.parse(request.body ?? "{}"), loaded_at: "2026-11-16T00:00:00Z" }))
    const dialog = await draft()
    fireEvent.change(dialog.getByRole("textbox", { name: "Secret env var" }), { target: { value: "PREFIXD_WEBHOOK_RADWARE_SECRET" } })
    fireEvent.click(dialog.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "New webhook adapter" })).not.toBeInTheDocument())
    expect(JSON.parse(controller.calls("PUT", "/v1/config/correlation")[0].body ?? "").webhook_adapters[0]).toMatchObject({ name: "radware", auth: { secret_env: "PREFIXD_WEBHOOK_RADWARE_SECRET" } })
  })
})
