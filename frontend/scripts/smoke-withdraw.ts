/**
 * Run from frontend with Bun: bun scripts/smoke-withdraw.ts
 * Required environment: PREFIXD_SMOKE_URL (literal loopback HTTP origin),
 * PREFIXD_SMOKE_USERNAME, PREFIXD_SMOKE_PASSWORD, PREFIXD_SMOKE_MITIGATION_ID,
 * PREFIXD_SMOKE_OUTPUT_DIR (new directory), PREFIXD_SMOKE_UI_SOURCE (UI revision
 * and whether candidate-local or published). Uses installed system Chrome.
 * The caller owns the isolated stack, account, active fixture, and cleanup.
 * This withdraws that fixture once; it never creates or retries a mitigation.
 */
import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { createHash, randomUUID } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { resolve } from "node:path"
import { chromium, type Browser, type BrowserContext, type Page } from "playwright"
import type { AuditDetails, AuditResponse, Mitigation } from "../lib/api"

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
const timeout = 15_000
let stage = "validate inputs"
let outputDir: string | undefined
let browser: Browser | undefined
let context: BrowserContext | undefined
let page: Page | undefined
let releaseResponse = () => {}

/** The run record written to receipt.json, filled in as each stage completes. */
interface SmokeReceipt {
  started_at: string
  origin?: string
  mitigation_id?: string
  ui_source_supplied_by_caller?: string
  script_revision?: string
  script_sha256?: string
  reason?: string
  browser_version?: string
  anonymous_audit_status?: number
  operator?: { username: string; role: string }
  withdraw_http_status?: number
  pending_dialog_verified?: boolean
  operation_id?: string
  status?: "passed" | "failed"
  failed_stage?: string
  error_name?: string
  assertion_code?: string
  assertion_message?: string
  finished_at?: string
}

const receipt: SmokeReceipt = { started_at: new Date().toISOString() }

function required(name: string): string {
  const value = process.env[`PREFIXD_SMOKE_${name}`]
  assert(value, `PREFIXD_SMOKE_${name} is required`)

  return value
}

async function save<T>(name: string, value: T) {
  assert(outputDir)
  await writeFile(resolve(outputDir, name), JSON.stringify(value, null, 2) + "\n", { mode: 0o600 })
}

async function run() {
  const suppliedUrl = required("URL")
  // Require the literal form: URL normalization must not admit remote hostnames.
  assert(/^http:\/\/(127\.0\.0\.1|\[::1\])(?::[0-9]+)?\/?$/.test(suppliedUrl))
  const origin = new URL(suppliedUrl).origin
  const username = required("USERNAME")
  const password = required("PASSWORD")
  const mitigationId = required("MITIGATION_ID").toLowerCase()
  assert(uuid.test(mitigationId), "mitigation ID must be a UUID")
  const requestedDir = resolve(required("OUTPUT_DIR"))
  const uiSource = required("UI_SOURCE")
  await mkdir(requestedDir, { mode: 0o700 }) // Fail if receipts already exist.
  outputDir = requestedDir
  Object.assign(receipt, {
    origin, mitigation_id: mitigationId, ui_source_supplied_by_caller: uiSource,
    script_revision: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
    script_sha256: createHash("sha256").update(await readFile(new URL(import.meta.url))).digest("hex"),
  })
  const api = `${origin}/api/prefixd/v1`
  const detailPath = `/mitigations/${mitigationId}`
  const withdrawUrl = `${api}${detailPath}/withdraw`
  const reason = `browser-smoke-${randomUUID()}`
  receipt.reason = reason

  stage = "launch Chrome"
  browser = await chromium.launch({ channel: "chrome", headless: true, timeout })
  receipt.browser_version = browser.version()
  context = await browser.newContext({ viewport: { width: 1440, height: 1080 }, serviceWorkers: "block" })
  context.setDefaultTimeout(timeout)
  context.setDefaultNavigationTimeout(timeout)
  page = await context.newPage()
  const request = context.request

  async function read<T>(path: string): Promise<T> {
    const response = await request.get(`${api}${path}`, { timeout, maxRedirects: 0 })
    assert.equal(response.status(), 200, `GET ${path} failed`)

    // SAFETY: T is the documented response type; callers assert every field they rely on.
    return response.json() as Promise<T>
  }

  async function activeFixture() {
    const mitigation = await read<Mitigation>(detailPath)
    assert.equal(mitigation.mitigation_id, mitigationId)
    assert.equal(mitigation.status, "active")
    assert(Date.parse(mitigation.expires_at) > Date.now(), "fixture already expired")

    return mitigation
  }

  stage = "prove credentials boundary"
  assert.equal((await read<{ auth_mode: string }>("/health")).auth_mode, "credentials")
  const anonymousAudit = await request.get(`${api}/audit`, { timeout, maxRedirects: 0 })
  assert.equal(anonymousAudit.status(), 401)
  await page.goto(`${origin}${detailPath}`)
  await page.waitForURL((url) => url.origin === origin && url.pathname === "/login")
  receipt.anonymous_audit_status = anonymousAudit.status()

  stage = "log in through browser"
  await page.getByLabel("Username", { exact: true }).fill(username)
  await page.getByLabel("Password", { exact: true }).fill(password)

  const [login] = await Promise.all([
    page.waitForResponse((response) => response.url() === `${api}/auth/login` && response.request().method() === "POST"),
    page.getByRole("button", { name: "Sign in", exact: true }).click(),
  ])

  assert.equal(login.status(), 200)
  await page.waitForURL((url) => url.origin === origin && url.pathname === "/")
  const operator = await read<{ username: string; role: string }>("/auth/me")
  assert.equal(operator.username, username)
  assert(["admin", "operator"].includes(operator.role), "fixture account cannot withdraw")
  receipt.operator = { username: operator.username, role: operator.role }
  await page.getByRole("main").waitFor()
  await page.screenshot({ path: resolve(outputDir, "overview.png"), fullPage: true })

  stage = "verify active fixture"
  const fixture = await activeFixture()
  await page.goto(`${origin}${detailPath}`)
  const main = page.getByRole("main")
  await main.locator(`a[href="/ip-history?ip=${encodeURIComponent(fixture.victim_ip)}"]`).waitFor()
  await main.getByText("active", { exact: true }).waitFor()
  const withdraw = main.getByRole("button", { name: "Withdraw", exact: true })
  assert(await withdraw.isEnabled())
  await save("active.json", {
    mitigation_id: fixture.mitigation_id, status: fixture.status,
    victim_ip: fixture.victim_ip, expires_at: fixture.expires_at,
  })
  await page.screenshot({ path: resolve(outputDir, "active.png"), fullPage: true })
  await withdraw.click()
  const dialog = page.getByRole("alertdialog", { name: "Withdraw Mitigation", exact: true })
  await dialog.waitFor()
  await dialog.getByLabel("Reason (optional)", { exact: true }).fill(reason)
  await activeFixture()

  // Forward the real request once. Hold its real response until the pending UI
  // has been observed, then deliver it unchanged. No fabricated response body.
  stage = "withdraw and verify pending dialog"
  const release = new Promise<void>((resolve) => { releaseResponse = resolve })
  const arrived = Promise.withResolvers<void>()

  // Attach a handler immediately so a network failure cannot become unhandled.
  void arrived.promise.catch(() => {})
  await page.route(withdrawUrl, async (route) => {
    try {
      assert.equal(route.request().method(), "POST")
      const response = await route.fetch({ timeout, maxRedirects: 0, maxRetries: 0 })
      receipt.withdraw_http_status = response.status()
      arrived.resolve()
      await release
      await route.fulfill({ response })
    } catch (error) {
      arrived.reject(error)
      await route.abort().catch(() => {})
    }
  }, { times: 1 })
  const responsePromise = page.waitForResponse((response) => response.url() === withdrawUrl && response.request().method() === "POST")
  void responsePromise.catch(() => {})
  await dialog.getByRole("button", { name: "Withdraw", exact: true }).click()
  await arrived.promise
  await dialog.waitFor()
  // Radix keeps a closed dialog visible during its exit animation.
  assert.equal(await dialog.getAttribute("data-state"), "open", "pending dialog must remain open")
  const pending = dialog.getByRole("button", { name: "Withdrawing...", exact: true })
  await pending.waitFor()
  assert(await pending.isDisabled(), "pending confirmation must be disabled")
  assert(await dialog.getByRole("button", { name: "Cancel", exact: true }).isDisabled())
  await page.screenshot({ path: resolve(outputDir, "pending.png"), fullPage: true })
  receipt.pending_dialog_verified = true
  releaseResponse()
  const response = await responsePromise
  assert.equal(response.status(), 200, "withdrawal did not complete")
  // SAFETY: only mitigation_id and status are read, and both are asserted below.
  const result = await response.json() as Mitigation
  assert.equal(result.mitigation_id, mitigationId)
  assert.equal(result.status, "withdrawn")
  await dialog.waitFor({ state: "hidden" })
  await main.getByText("withdrawn", { exact: true }).waitFor()
  await page.screenshot({ path: resolve(outputDir, "withdrawn.png"), fullPage: true })

  stage = "verify persisted withdrawal and audit"
  const persisted = await read<Mitigation>(detailPath)
  assert.equal(persisted.mitigation_id, mitigationId)
  assert.equal(persisted.status, "withdrawn")
  const audit = await read<AuditResponse>("/audit?limit=200")
  const matches = audit.entries.filter((entry) => entry.action === "withdraw" && entry.target_type === "mitigation" && entry.target_id === mitigationId)
  assert.equal(matches.length, 1, "expected one persisted withdrawal audit row")
  const entry = matches[0]
  assert.equal(entry.actor_type, "operator")
  assert.equal(entry.actor_id, username)
  assert.equal(entry.details.reason, `${username}: ${reason}`)
  assert.match(entry.details.operation_id ?? "", uuid)
  await save("audit.json", {
    audit_id: entry.audit_id, timestamp: entry.timestamp, actor_type: entry.actor_type,
    actor_id: entry.actor_id, action: entry.action, target_type: entry.target_type,
    target_id: entry.target_id,
    details: { reason: entry.details.reason, operation_id: entry.details.operation_id },
  })

  stage = "verify rendered audit row"
  await page.goto(`${origin}/audit-log`)
  await main.getByPlaceholder("Search target or details…", { exact: true }).fill(mitigationId)
  const row = main.locator("tr").filter({ has: page.locator(`a[href="${detailPath}"]`) }).filter({ has: page.getByText("withdraw", { exact: true }) })
  await row.waitFor()
  assert.equal(await row.count(), 1)
  await row.getByText(username, { exact: true }).waitFor()
  await row.locator("td").first().click()
  const details = row.locator("xpath=following-sibling::tr[1]").locator("pre")
  await details.waitFor()
  // SAFETY: the audit log renders entry.details as JSON; both fields read are asserted below.
  const rendered = JSON.parse(await details.innerText()) as AuditDetails
  assert.equal(rendered.reason, entry.details.reason)
  assert.equal(rendered.operation_id, entry.details.operation_id)
  await page.screenshot({ path: resolve(outputDir, "audit.png"), fullPage: true })
  receipt.operation_id = entry.details.operation_id
}

let deadline: ReturnType<typeof setTimeout> | undefined

try {
  await Promise.race([
    run(),
    new Promise<never>((_, reject) => {
      deadline = setTimeout(() => reject(new Error("smoke deadline exceeded")), 120_000)
    }),
  ])
  receipt.status = "passed"
} catch (error) {
  // Do not print Playwright errors: request bodies or filled passwords can be
  // included in diagnostics. Keep a safe stage and mask password screenshots.
  receipt.status = "failed"
  receipt.failed_stage = stage
  receipt.error_name = error instanceof Error ? error.name : "UnknownError"

  if (error instanceof assert.AssertionError) {
    receipt.assertion_code = error.code
    receipt.assertion_message = error.generatedMessage ? "Assertion failed" : error.message
  }

  if (page && outputDir) {
    await page.screenshot({
      path: resolve(outputDir, "failure.png"), fullPage: true, timeout: 5_000,
      mask: [page.locator('input[type="password"]')],
    }).catch(() => {})
  }

  console.error(`Withdrawal browser smoke failed at: ${stage}`)
  process.exitCode = 1
} finally {
  if (deadline) clearTimeout(deadline)
  releaseResponse()
  // Closing also interrupts outstanding operations after the overall deadline.
  await context?.close().catch(() => {})
  await browser?.close().catch(() => {})
  receipt.finished_at = new Date().toISOString()

  if (outputDir) await save("receipt.json", receipt)
}

if (receipt.status === "passed") console.log("Withdrawal browser smoke passed")
