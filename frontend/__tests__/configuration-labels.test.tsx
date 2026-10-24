import { cleanup, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import AdminPage from "@/app/(dashboard)/admin/page"
import { AlertingConfigPanel } from "@/components/dashboard/alerting-config-panel"
import { ConfigTab } from "@/components/dashboard/correlation/config-tab"
import { WebhookAdaptersEditor } from "@/components/dashboard/correlation/webhook-adapters"
import { NotificationPreferencesPanel } from "@/components/dashboard/notification-preferences"
import { PlaybookEditor } from "@/components/dashboard/playbook-editor"
import type { AlertingDestination, ConfigPlaybook, CorrelationConfig } from "@/lib/api"
import { json, operatorResponse, renderApp, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

const correlation: CorrelationConfig = {
  enabled: true, window_seconds: 60, min_sources: 1, confidence_threshold: 0.5,
  default_weight: 1, sources: {}, webhook_adapters: [],
}

beforeEach(() => {
  signIn(controller, "credentials", operatorResponse("admin"))
  controller.route("GET", "/v1/config/correlation", () => json({ config: correlation, loaded_at: "2026-10-24T00:00:00Z" }))

  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
})

afterEach(() => {
  cleanup()

  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

async function choose(trigger: HTMLElement, option: string) {
  fireEvent.keyDown(trigger, { key: "ArrowDown" })
  fireEvent.click(await screen.findByRole("option", { name: option }))
}

function expectUniqueIds() {
  const ids = Array.from(document.querySelectorAll("[id]"), (element) => element.id)
  expect(new Set(ids).size).toBe(ids.length)
}

describe("operator configuration accessible names", () => {
  it("keeps webhook names, conditional controls and field descriptions associated as validation changes", async () => {
    renderApp(<WebhookAdaptersEditor />)
    fireEvent.click(await screen.findByRole("button", { name: "Add adapter" }))
    const dialog = within(await screen.findByRole("dialog", { name: "New webhook adapter" }))
    const name = dialog.getByRole("textbox", { name: "Name" })
    const nameId = name.id
    expect(name).toHaveAttribute("aria-invalid", "true")
    expect(name).toHaveAccessibleDescription("Must match [a-z0-9-]{1,64}")
    fireEvent.change(name, { target: { value: "provider-alerts" } })
    expect(name.id).toBe(nameId)
    expect(name).toHaveAttribute("aria-invalid", "false")
    expect(name).toHaveAccessibleDescription("URL path segment, [a-z0-9-]{1,64}")
    fireEvent.change(name, { target: { value: "Invalid Name" } })
    expect(name).toHaveAccessibleDescription("Must match [a-z0-9-]{1,64}")

    for (const label of ["Description", "Secret env var", "Header", "victim_ip *", "vector", "timestamp", "bps", "pps", "confidence", "source_id", "top_dst_ports", "top_src_ports", "action", "root_path", "default_vector", "confidence_scale", "source_id_prefix"]) {
      expect(dialog.getByRole("textbox", { name: label })).toBeVisible()
    }

    expect(dialog.getByRole("textbox", { name: "Secret env var" })).toHaveAccessibleDescription("Name of the env var holding the HMAC secret (value never sent)")
    expect(dialog.getByRole("textbox", { name: "victim_ip *" })).toHaveAccessibleDescription('REQUIRED; e.g. "$.target.ip"')
    expect(dialog.getByRole("textbox", { name: /^vector_map/ })).toBeVisible()
    const authentication = dialog.getByRole("combobox", { name: "Authentication" })
    expect(authentication).toHaveTextContent("HMAC-SHA256")
    await choose(authentication, "Bearer token")
    expect(dialog.getByRole("combobox", { name: "Authentication" })).toHaveTextContent("Bearer token")
    expect(dialog.queryByRole("textbox", { name: "Secret env var" })).toBeNull()
    expectUniqueIds()
  })

  it("names source settings even after selecting corroborating mode", async () => {
    renderApp(<ConfigTab />)
    fireEvent.click(await screen.findByRole("button", { name: "Add source" }))
    const dialog = within(await screen.findByRole("dialog", { name: "Add signal source" }))
    expect(dialog.getByRole("textbox", { name: "Name" })).toBeVisible()
    expect(dialog.getByRole("spinbutton", { name: "Weight" })).toHaveValue(1)
    expect(dialog.getByRole("combobox", { name: "Type" })).toHaveTextContent("Detector")
    await choose(dialog.getByRole("combobox", { name: "Mode" }), "Corroborating (strengthens other sources only)")
    expect(dialog.getByRole("combobox", { name: "Mode" })).toHaveTextContent("Corroborating")
    expect(dialog.getByRole("button", { name: "customer_id" })).toBeVisible()
  })

  const destinations: Array<{ destination: AlertingDestination; label: string; fields: string[] }> = [
    { destination: { type: "slack", webhook_url: "***", channel: "#alerts" }, label: "Slack", fields: ["Webhook URL", "Channel (optional)"] },
    { destination: { type: "discord", webhook_url: "***" }, label: "Discord", fields: ["Webhook URL"] },
    { destination: { type: "teams", webhook_url: "***" }, label: "Microsoft Teams", fields: ["Webhook URL"] },
    { destination: { type: "telegram", bot_token: "***", chat_id: "123" }, label: "Telegram", fields: ["Bot token", "Chat ID"] },
    { destination: { type: "pagerduty", routing_key: "***", events_url: "https://events.pagerduty.com/v2/enqueue" }, label: "PagerDuty", fields: ["Routing key", "Events URL"] },
    { destination: { type: "opsgenie", api_key: "***", region: "eu" }, label: "OpsGenie", fields: ["API Key"] },
    { destination: { type: "generic", url: "https://example.net/hook", secret: "***" }, label: "Generic webhook", fields: ["URL", "HMAC Secret (optional)"] },
  ]

  it.each(destinations)("associates every conditional $label destination field without exposing masked values", async ({ destination, label, fields }) => {
    controller.route("GET", "/v1/config/alerting", () => json({ destinations: [destination], events: [] }))
    renderApp(<AlertingConfigPanel />)
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }))
    fireEvent.click(screen.getByRole("button", { name: `Edit ${label} destination 1` }))

    for (const field of fields) expect(screen.getByLabelText(field, { exact: true })).toBeVisible()
    const masked = fields.map((field) => screen.getByLabelText(field, { exact: true })).filter((element) => element instanceof HTMLInputElement && element.value === "***")
    expect(masked).toHaveLength(1)
    expect(masked[0]).toHaveAttribute("type", "password")

    if (destination.type === "opsgenie") expect(screen.getByRole("combobox", { name: "Region" })).toHaveTextContent("EU")
    expect(screen.getByRole("button", { name: `Remove ${label} destination 1` })).toBeVisible()
    expectUniqueIds()
  })

  it("distinguishes two same-type destinations and preserves each label target through edits and save", async () => {
    const destinations: AlertingDestination[] = [
      { type: "pagerduty", routing_key: "***", events_url: "https://example.net/first" },
      { type: "pagerduty", routing_key: "***", events_url: "https://example.net/second" },
    ]

    controller.route("GET", "/v1/config/alerting", () => json({ destinations, events: [] }))
    controller.route("PUT", "/v1/config/alerting", () => json({ destinations, events: [] }))
    renderApp(<AlertingConfigPanel />)
    fireEvent.click(await screen.findByRole("button", { name: "Edit" }))
    fireEvent.click(screen.getByRole("button", { name: "Edit PagerDuty destination 1" }))
    const first = screen.getByRole("textbox", { name: "Events URL" })
    const firstId = first.id
    expect(first).toHaveValue("https://example.net/first")
    fireEvent.change(first, { target: { value: "https://example.net/changed" } })
    expect(screen.getByRole("textbox", { name: "Events URL" }).id).toBe(firstId)
    fireEvent.click(screen.getByRole("button", { name: "Done" }))
    fireEvent.click(screen.getByRole("button", { name: "Edit PagerDuty destination 2" }))
    const second = screen.getByRole("textbox", { name: "Events URL" })
    expect(second).toHaveValue("https://example.net/second")
    expect(second.id).not.toBe(firstId)
    const label = Array.from(document.querySelectorAll("label")).find((element) => element.htmlFor === second.id)
    expect(label?.control).toBe(second)
    expectUniqueIds()
    fireEvent.click(screen.getByRole("button", { name: "Save" }))
    await waitFor(() => expect(controller.calls("PUT", "/v1/config/alerting")).toHaveLength(1))
    expect(JSON.parse(controller.calls("PUT", "/v1/config/alerting")[0]!.body!)).toEqual({ destinations: [{ ...destinations[0], events_url: "https://example.net/changed" }, destinations[1]], events: [] })
  })

  it("keeps user and self-password controls associated with their visible labels", async () => {
    controller.route("GET", "/v1/operators", () => json({ operators: [{ ...operatorResponse("admin"), created_at: "2026-10-24T00:00:00Z", created_by: null, last_login_at: null }], count: 1 }))
    renderApp(<AdminPage />, { url: "/admin?tab=users" })
    fireEvent.click(await screen.findByRole("button", { name: "Add user" }))
    const create = within(await screen.findByRole("dialog", { name: "Create operator" }))
    expect(create.getByLabelText("Username", { exact: true })).toBeVisible()
    expect(create.getByLabelText("Password", { exact: true })).toHaveAttribute("type", "password")
    expect(create.getByRole("combobox", { name: "Role" })).toHaveTextContent("Operator")
    fireEvent.click(create.getByRole("button", { name: "Cancel" }))
    fireEvent.click(screen.getByRole("button", { name: "Change password for alice" }))
    const password = within(await screen.findByRole("dialog", { name: "Change password" }))
    expect(password.getByLabelText("Current password", { exact: true })).toHaveAttribute("type", "password")
    expect(password.getByLabelText("New password", { exact: true })).toHaveAttribute("type", "password")
    expectUniqueIds()
  })

  it("keeps safelist inputs named after typing replaces their placeholders", async () => {
    controller.route("GET", "/v1/safelist", () => json({ entries: [] }))
    renderApp(<AdminPage />, { url: "/admin?tab=safelist" })
    const prefix = await screen.findByRole("textbox", { name: "Safelist prefix" })
    fireEvent.change(prefix, { target: { value: "192.0.2.0/24" } })
    expect(screen.getByRole("textbox", { name: "Safelist prefix" })).toHaveValue("192.0.2.0/24")
    expect(screen.getByRole("textbox", { name: "Safelist reason (optional)" })).toBeVisible()
  })

  it("associates playbook metadata and every editable step parameter", () => {
    const playbooks: ConfigPlaybook[] = [{ name: "udp", match: { vector: "udp_flood" }, steps: [
      { action: "police", rate_bps: 5_000_000, ttl_seconds: 300 },
      { action: "police", rate_bps: 1_000_000, ttl_seconds: 600, require_confidence_at_least: 0.8, require_persistence_seconds: 30 },
    ] }]

    renderApp(<PlaybookEditor playbooks={playbooks} onSave={vi.fn()} saving={false} />)
    fireEvent.click(screen.getByRole("button", { name: "Edit playbook udp" }))
    expect(screen.getByRole("textbox", { name: "Name" })).toHaveValue("udp")
    expect(screen.getByRole("combobox", { name: "Vector" })).toHaveTextContent("udp_flood")
    expect(screen.getAllByRole("spinbutton", { name: "Rate (bps)" })).toHaveLength(2)
    expect(screen.getByRole("spinbutton", { name: "Min confidence" })).toHaveValue(0.8)
    expect(screen.getByRole("spinbutton", { name: "Min persist (s)" })).toHaveValue(30)
    expect(screen.getAllByLabelText("Action")).toHaveLength(2)
    expect(screen.getAllByLabelText("TTL (seconds)")).toHaveLength(2)
    expectUniqueIds()
  })

  it("keeps quiet-hour purposes named with Off and selected times", async () => {
    controller.route("GET", "/v1/preferences", () => json({ muted_events: [], quiet_hours_start: null, quiet_hours_end: null }))
    renderApp(<NotificationPreferencesPanel />)
    const start = await screen.findByRole("combobox", { name: "Quiet hours start (UTC)" })
    const startId = start.id
    expect(start).toHaveTextContent("Off")
    await choose(start, "22:00")
    expect(screen.getByRole("combobox", { name: "Quiet hours start (UTC)" })).toHaveTextContent("22:00")
    expect(screen.getByRole("combobox", { name: "Quiet hours start (UTC)" }).id).toBe(startId)
    expect(screen.getByRole("combobox", { name: "Quiet hours end (UTC)" })).toHaveTextContent("08:00")
    expectUniqueIds()
  })
})
