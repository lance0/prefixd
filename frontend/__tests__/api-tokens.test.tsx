import { act, fireEvent, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import AdminPage from "@/app/(dashboard)/admin/page"
import { tokenSnippets } from "@/components/dashboard/api-tokens"
import type { ApiToken } from "@/lib/api"
import { failure, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()
const SECRET = "prefixd_SEEDEDsecretSEEDEDsecretSEEDEDsecret0"
const created = "2026-11-16T08:00:00Z"

function token(name: string, overrides: Partial<ApiToken> = {}): ApiToken {
  return {
    token_id: `${name}-id`, name, scope: "ingest", source: "fastnetmon", pop: null, created_at: created,
    created_by: "alice", expires_at: null, last_used_at: null, revoked_at: null, revoked_by: null, ...overrides,
  }
}

let tokens: ApiToken[]

// jsdom lacks the pointer-capture and scrolling APIs Radix Select calls while opening.
const pointerApis = ["hasPointerCapture", "releasePointerCapture", "scrollIntoView"] as const
const originals = new Map(pointerApis.map((name) => [name, Object.getOwnPropertyDescriptor(Element.prototype, name)]))

beforeEach(() => {
  for (const name of pointerApis) Object.defineProperty(Element.prototype, name, { configurable: true, value: vi.fn(() => false) })
  tokens = [
    token("old-fnm", { revoked_at: created, revoked_by: "alice" }),
    token("fnm-pop1", { last_used_at: created, pop: "pop1" }),
    token("ci-deploy", { scope: "operator", source: null, created_by: "bob" }),
  ]
  controller.route("GET", "/v1/tokens", () => json({ tokens, count: tokens.length }))
  controller.route("GET", "/v1/operators", () => json({ operators: [{ operator_id: "alice-id", username: "alice", role: "admin", created_at: created, created_by: null, last_login_at: null }], count: 1 }))
  controller.route("GET", "/v1/config/correlation", () => json({
    config: {
      enabled: true, window_seconds: 60, min_sources: 1, confidence_threshold: 0.5, default_weight: 1,
      sources: { radware: { weight: 1, type: "detector", confidence_mapping: {} } },
      webhook_adapters: [{ name: "kentik", description: "", enabled: true, auth: { type: "bearer" }, fields: { victim_ip: "$.ip" } }],
    },
    loaded_at: created,
  }))
})

afterEach(() => {
  for (const [name, descriptor] of originals) {
    if (descriptor) Object.defineProperty(Element.prototype, name, descriptor)
    else Reflect.deleteProperty(Element.prototype, name)
  }
})

async function renderAdmin(mode: string, role: "admin" | "operator" | "viewer" | null, url = "/admin?tab=tokens") {
  signIn(controller, mode, role ? operatorResponse(role) : null)
  await act(async () => { renderApp(<AdminPage />, { url }) })
  await waitFor(() => expect(controller.calls("GET", "/v1/auth/me").length).toBeGreaterThan(0))
  await settle()
  await settle()
}

async function choose(trigger: HTMLElement, option: string) {
  fireEvent.keyDown(trigger, { key: "Enter" })
  fireEvent.click(await screen.findByRole("option", { name: option }))
}

function secretVisible() {
  return document.body.innerHTML.includes(SECRET)
}

describe("API tokens tab", { timeout: 10_000 }, () => {
  it("lists active tokens first, without a secret, for an Admin session", async () => {
    await renderAdmin("credentials", "admin")
    expect(screen.getByRole("tab", { name: "API tokens" })).toHaveAttribute("aria-selected", "true")
    const rows = await screen.findAllByRole("row")
    // Header, then ci-deploy and fnm-pop1 (active, by name), then the revoked token.
    expect(rows.map((row) => within(row).queryAllByRole("cell")[0]?.textContent ?? "header")).toEqual(["header", "ci-deploy", "fnm-pop1", "old-fnm"])
    expect(within(rows[2]).getByText("pop1")).toBeInTheDocument()
    expect(within(rows[3]).getByText("Revoked by alice")).toBeInTheDocument()
    expect(within(rows[3]).queryByRole("button", { name: /Revoke/ })).not.toBeInTheDocument()
  })

  it.each([
    ["credentials", "operator"],
    ["credentials", "viewer"],
    ["none", null],
    ["mtls", null],
  ] as const)("is absent in %s mode for %s, and the list is never requested", async (mode, role) => {
    await renderAdmin(mode, role)
    expect(screen.queryByRole("tab", { name: "API tokens" })).not.toBeInTheDocument()
    expect(screen.getByRole("tab", { name: "Status" })).toHaveAttribute("aria-selected", "true")
    expect(controller.calls("GET", "/v1/tokens")).toHaveLength(0)
  })

  it("shows the secret once with snippets, then forgets it when the dialog closes", async () => {
    const log = vi.spyOn(console, "log")
    const error = vi.spyOn(console, "error")
    controller.route("POST", "/v1/tokens", () => json({ ...token("fnm-pop2", { pop: "pop2" }), token: SECRET }, 201))
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: vi.fn(async () => {}) } })
    vi.stubGlobal("isSecureContext", true)
    await renderAdmin("credentials", "admin")
    await screen.findByText("fnm-pop1")
    const listReads = controller.calls("GET", "/v1/tokens").length

    fireEvent.click(screen.getByRole("button", { name: "Create token" }))
    let dialog = within(await screen.findByRole("dialog", { name: "Create API token" }))
    fireEvent.change(dialog.getByLabelText("Name"), { target: { value: "fnm-pop2" } })
    fireEvent.change(dialog.getByLabelText("Source"), { target: { value: "fastnetmon" } })
    fireEvent.change(dialog.getByLabelText("POP (optional)"), { target: { value: "pop2" } })
    fireEvent.click(dialog.getByRole("button", { name: "Create token" }))

    dialog = within(await screen.findByRole("dialog", { name: "Token fnm-pop2 created" }))
    expect(JSON.parse(controller.calls("POST", "/v1/tokens")[0].body ?? "")).toEqual({ name: "fnm-pop2", scope: "ingest", source: "fastnetmon", pop: "pop2" })
    expect(dialog.getByLabelText("Token")).toHaveValue(SECRET)
    // Focus moves into the new view, so the secret and its copy action are announced.
    await waitFor(() => expect(dialog.getByRole("button", { name: "Copy token" })).toHaveFocus())
    // The snippets read the token from a file and keep it off curl's command line.
    const snippets = dialog.getAllByText((_, element) => element?.tagName === "PRE").map((pre) => pre.textContent ?? "")
    expect(snippets.join("\n")).toContain('PREFIXD_TOKEN_FILE="/etc/prefixd/fnm-pop2.token"')
    expect(snippets.join("\n")).toContain("curl -K -")
    expect(snippets.join("\n")).not.toContain(SECRET)
    // The list is refetched; the create response is not written into it.
    await waitFor(() => expect(controller.calls("GET", "/v1/tokens").length).toBeGreaterThan(listReads))

    fireEvent.click(dialog.getByRole("button", { name: "Copy token" }))
    await waitFor(() => expect(navigator.clipboard.writeText).toHaveBeenCalledWith(SECRET))
    fireEvent.click(dialog.getByRole("button", { name: "Done" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(secretVisible()).toBe(false)

    // Reopening starts from an empty form: the secret was not kept in state.
    fireEvent.click(screen.getByRole("button", { name: "Create token" }))
    dialog = within(await screen.findByRole("dialog", { name: "Create API token" }))
    expect(dialog.getByLabelText("Name")).toHaveValue("")
    expect(secretVisible()).toBe(false)

    const stored = [...Object.values(localStorage), ...Object.values(sessionStorage)].join("\n")
    expect(stored).not.toContain(SECRET)
    expect(window.location.href).not.toContain(SECRET)

    for (const call of [...log.mock.calls, ...error.mock.calls]) expect(JSON.stringify(call)).not.toContain(SECRET)
  })

  it("asks before closing with an uncopied secret", async () => {
    controller.route("POST", "/v1/tokens", () => json({ ...token("am-1", { source: "alertmanager" }), token: SECRET }, 201))
    await renderAdmin("credentials", "admin")
    fireEvent.click(await screen.findByRole("button", { name: "Create token" }))
    let dialog = within(await screen.findByRole("dialog", { name: "Create API token" }))
    fireEvent.change(dialog.getByLabelText("Name"), { target: { value: "am-1" } })
    fireEvent.change(dialog.getByLabelText("Source"), { target: { value: "alertmanager" } })
    fireEvent.click(dialog.getByRole("button", { name: "Create token" }))
    dialog = within(await screen.findByRole("dialog", { name: "Token am-1 created" }))
    expect(dialog.getByText("Alertmanager receiver")).toBeInTheDocument()

    fireEvent.click(dialog.getByRole("button", { name: "Done" }))
    expect(dialog.getByRole("alert")).toHaveTextContent("has not been copied")
    expect(dialog.getByLabelText("Token")).toHaveValue(SECRET)
    fireEvent.keyDown(dialog.getByLabelText("Token"), { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
    expect(secretVisible()).toBe(false)
  })

  it("shows the controller's refusal and keeps the form", async () => {
    controller.route("POST", "/v1/tokens", () => json({ error: "name already used; names are never reused" }, 409))
    await renderAdmin("credentials", "admin")
    fireEvent.click(await screen.findByRole("button", { name: "Create token" }))
    const dialog = within(await screen.findByRole("dialog", { name: "Create API token" }))
    fireEvent.change(dialog.getByLabelText("Name"), { target: { value: "old-fnm" } })
    await choose(dialog.getByRole("combobox", { name: "Scope" }), "operator")
    expect(dialog.queryByLabelText("Source")).not.toBeInTheDocument()
    fireEvent.click(dialog.getByRole("button", { name: "Create token" }))
    expect(await dialog.findByRole("alert")).toHaveTextContent("name already used; names are never reused")
    expect(JSON.parse(controller.calls("POST", "/v1/tokens")[0].body ?? "")).toEqual({ name: "old-fnm", scope: "operator" })
    expect(dialog.getByLabelText("Name")).toHaveValue("old-fnm")
  })

  it("refuses an ingest token without a source before asking the controller", async () => {
    await renderAdmin("credentials", "admin")
    fireEvent.click(await screen.findByRole("button", { name: "Create token" }))
    const dialog = within(await screen.findByRole("dialog", { name: "Create API token" }))
    fireEvent.change(dialog.getByLabelText("Name"), { target: { value: "fnm-pop3" } })
    fireEvent.click(dialog.getByRole("button", { name: "Create token" }))
    expect(dialog.getByLabelText("Source")).toHaveAccessibleDescription(/needs a source/)
    expect(controller.calls("POST", "/v1/tokens")).toHaveLength(0)
  })

  it("revokes only after a confirmation that names the token, its source and last use", async () => {
    controller.route("POST", "/v1/tokens/fnm-pop1/revoke", () => {
      tokens = tokens.map((entry) => entry.name === "fnm-pop1" ? { ...entry, revoked_at: created, revoked_by: "alice" } : entry)

      return json(tokens[1])
    })
    await renderAdmin("credentials", "admin")
    fireEvent.click(await screen.findByRole("button", { name: "Revoke fnm-pop1" }))
    let confirm = within(await screen.findByRole("alertdialog", { name: "Revoke fnm-pop1?" }))
    expect(confirm.getByText("fastnetmon")).toBeInTheDocument()
    expect(confirm.getByText(/Last used/).querySelector("time")).toHaveAttribute("dateTime", created)
    fireEvent.click(confirm.getByRole("button", { name: "Cancel" }))
    await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
    expect(controller.calls("POST", "/v1/tokens/fnm-pop1/revoke")).toHaveLength(0)

    fireEvent.click(screen.getByRole("button", { name: "Revoke fnm-pop1" }))
    confirm = within(await screen.findByRole("alertdialog", { name: "Revoke fnm-pop1?" }))
    fireEvent.click(confirm.getByRole("button", { name: "Revoke" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/tokens/fnm-pop1/revoke")).toHaveLength(1))
    await waitFor(() => expect(screen.queryByRole("button", { name: "Revoke fnm-pop1" })).not.toBeInTheDocument())
    // The revoked row's button is gone, so focus lands on the next action rather than the page.
    await waitFor(() => expect(screen.getByRole("button", { name: "Create token" })).toHaveFocus())
  })

  it("filters by a creator named like the Anyone option", async () => {
    tokens = [token("by-all", { created_by: "all" }), token("by-alice")]
    await renderAdmin("credentials", "admin")
    await screen.findByText("by-all")
    await choose(screen.getByRole("combobox", { name: "Created by" }), "all")
    await waitFor(() => expect(screen.queryByText("by-alice")).not.toBeInTheDocument())
    expect(screen.getByText("by-all")).toBeInTheDocument()
    await choose(screen.getByRole("combobox", { name: "Created by" }), "Anyone")
    expect(await screen.findByText("by-alice")).toBeInTheDocument()
  })

  it("keeps the confirmation open with the controller's reason when a revoke fails", async () => {
    controller.route("POST", "/v1/tokens/fnm-pop1/revoke", () => failure(503, "controller is in standby"))
    await renderAdmin("credentials", "admin")
    fireEvent.click(await screen.findByRole("button", { name: "Revoke fnm-pop1" }))
    const confirm = within(await screen.findByRole("alertdialog", { name: "Revoke fnm-pop1?" }))
    fireEvent.click(confirm.getByRole("button", { name: "Revoke" }))
    expect(await confirm.findByRole("alert")).toHaveTextContent("controller is in standby")
  })
})

describe("operator accounts without a session", () => {
  it.each(["none", "mtls"])("lists accounts in %s mode but offers no identity changes", async (mode) => {
    await renderAdmin(mode, null, "/admin?tab=users")
    expect(await screen.findByText("alice")).toBeInTheDocument()
    expect(screen.getByText(/need a signed-in Admin session/)).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Add user" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Change password/ })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /^Delete/ })).not.toBeInTheDocument()
    expect(screen.queryByRole("tab", { name: "API tokens" })).not.toBeInTheDocument()
  })

  it("lists accounts read-only in mtls mode for a signed-in Admin too", async () => {
    await renderAdmin("mtls", "admin", "/admin?tab=users")
    expect(await screen.findByText("alice")).toBeInTheDocument()
    expect(screen.queryByRole("button", { name: "Add user" })).not.toBeInTheDocument()
    expect(screen.queryByRole("button", { name: /Change password/ })).not.toBeInTheDocument()
  })

  it("offers identity changes to an Admin session", async () => {
    await renderAdmin("credentials", "admin", "/admin?tab=users")
    expect(await screen.findByRole("button", { name: "Add user" })).toBeInTheDocument()
    expect(screen.getByRole("button", { name: "Change password for alice" })).toBeInTheDocument()
  })
})

describe("token snippets", () => {
  const origin = "https://prefixd.example.net"

  function fileSetup(snippets: { title: string; text: string }[]) {
    return snippets[0].text.split("\n")
  }

  it("covers each client from a token file, never the secret", () => {
    const fastnetmon = tokenSnippets({ name: "fnm-pop1", scope: "ingest", source: "fastnetmon" }, origin)
    expect(fastnetmon.map((snippet) => snippet.title)).toEqual(["Token file", "FastNetMon notify script (/etc/default/prefixd)", "Test with curl"])
    expect(fastnetmon[1].text).toBe(`PREFIXD_API="${origin}"\nPREFIXD_TOKEN_FILE="/etc/prefixd/fnm-pop1.token"`)

    const hostgroup = tokenSnippets({ name: "fnm-hg", scope: "ingest", source: "fastnetmon-hostgroup" }, origin)
    expect(hostgroup[1].title).toBe("Hostgroup shim, one event per attacked network")
    expect(hostgroup[1].text).toContain('"source": "fastnetmon-hostgroup"')
    expect(hostgroup[1].text).toContain(`$(cat /etc/prefixd/fnm-hg.token)`)
    expect(hostgroup[1].text).toContain(`curl -K - -X POST "${origin}/v1/events"`)

    const alertmanager = tokenSnippets({ name: "am", scope: "ingest", source: "alertmanager" }, origin)
    expect(alertmanager[1].text).toContain(`url: "${origin}/v1/signals/alertmanager"`)
    expect(alertmanager[1].text).toContain("credentials_file: /etc/prefixd/am.token")

    const webhook = tokenSnippets({ name: "kentik-1", scope: "ingest", source: "kentik" }, origin, ["kentik"])
    expect(webhook[1].text).toContain(`${origin}/v1/signals/webhook/kentik`)
    expect(tokenSnippets({ name: "k", scope: "ingest", source: "kentik" }, origin, [])).toHaveLength(2)

    const operator = tokenSnippets({ name: "ci", scope: "operator", source: null }, origin)
    expect(operator.map((snippet) => snippet.title)).toEqual(["Token file", "prefixdctl", "Test with curl"])
    expect(operator[2].text).toContain(`curl -K - --fail-with-body ${origin}/v1/health/detail`)

    for (const snippet of [...fastnetmon, ...hostgroup, ...alertmanager, ...webhook, ...operator]) {
      expect(snippet.text).not.toMatch(/prefixd_[A-Za-z0-9_-]{43}/)
      expect(snippet.text).not.toMatch(/curl[^|\n]* -H ['"]?Authorization/)
    }
  })

  it.each([
    [{ name: "fnm-pop1", scope: "ingest", source: "fastnetmon" }, "fastnetmon"],
    [{ name: "fnm-hg", scope: "ingest", source: "fastnetmon-hostgroup" }, "fastnetmon"],
    [{ name: "am", scope: "ingest", source: "alertmanager" }, "alertmanager"],
    [{ name: "kentik-1", scope: "ingest", source: "kentik" }, "<the client's account>"],
    [{ name: "ci", scope: "operator", source: null }, "<the client's account>"],
  ] as const)("makes the token file %j private to %s", (token, user) => {
    const file = `/etc/prefixd/${token.name}.token`
    const lines = fileSetup(tokenSnippets(token, origin))
    const commands = lines.filter((line) => !line.startsWith("#"))

    // The directory exists, the file is created private, then handed to the client and made read-only.
    expect(commands).toEqual([
      `CLIENT_USER="${user}"`,
      "sudo install -d -m 0755 /etc/prefixd",
      `sudo sh -c 'umask 077 && cat > ${file}'`,
      `sudo chown "$CLIENT_USER" ${file}`,
      `sudo chmod 0400 ${file}`,
    ])
    expect(lines.join("\n")).not.toMatch(/chmod (0?[0-7][0-7][1-7]|[ao]\+r)/)

    // The test reads the client's file through sudo, as a login user cannot.
    const test = tokenSnippets(token, origin).at(-1)?.text ?? ""
    expect(test).toContain(`"$(sudo cat ${file})"`)
  })

  it("says where Alertmanager runs and how to mount the file into a container", () => {
    const text = fileSetup(tokenSnippets({ name: "am", scope: "ingest", source: "alertmanager" }, origin)).join("\n")
    expect(text).toContain("prometheus on Debian and Ubuntu packages")
    expect(text).toMatch(/In a container, mount the file read-only/)
    expect(text).toContain("never make it world-readable")
  })
})
