import { act, fireEvent, screen, waitFor } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { ScrubbersContent } from "@/components/dashboard/scrubbers-content"
import type { DiversionPreview } from "@/lib/api"
import { deferred, json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

function result(dryRun = false): DiversionPreview {
  return {
    candidate: {
      id: "operation-1", profile: { id: "a", revision: "v1" },
      rule: { nlri: { dst_prefix: "203.0.113.20/32", src_prefix: "198.51.100.0/24", protocol: 6, dst_ports: [443] }, target: "192.0.2.99", owner: "profile-owner", revision: 1 },
      expires_at: "2030-01-01T00:00:00Z", status: dryRun ? "simulated" : "pending", dry_run: dryRun, withdrawal_reason: null, last_error: null,
    },
    confirmation: "exact-full-match-and-target-v1", readiness: { armed: !dryRun, ready: !dryRun, observed_at: null, latch_reason: null },
    evidence: "Preview only; no reservation or speaker mutation. Withdrawal returns traffic to ordinary routing.",
  }
}

async function setup(dryRun = false) {
  signIn(controller, "credentials", operatorResponse("admin"))
  controller.route("GET", "/v1/scrubbers", () => json({ enabled: true, profiles: { a: { armed: !dryRun, ready: !dryRun, readiness: dryRun ? "unknown" : "ready", observed_at: null, latch_reason: null } }, configuration: [{ id: "a", revision: "v1", ipv4_target: "192.0.2.99", ipv6_target: null }] }))
  controller.route("GET", "/v1/diversions", () => json([]))
  controller.route("POST", "/v1/diversions/preview", () => json(result(dryRun)))
  controller.route("POST", "/v1/diversions", () => json({ ...result(dryRun).candidate, status: dryRun ? "simulated" : "active" }, 202))
  renderApp(<ScrubbersContent />, { url: "/scrubbers" })
  await screen.findByText("New diversion")
  fireEvent.change(screen.getByRole("combobox", { name: "Profile" }), { target: { value: "a" } })
  fireEvent.change(screen.getByLabelText("Victim host CIDR"), { target: { value: "203.0.113.20/32" } })
  fireEvent.change(screen.getByLabelText("Source prefix (optional)"), { target: { value: "198.51.100.0/24" } })
  fireEvent.change(screen.getByLabelText("Destination ports (optional)"), { target: { value: "443" } })
  fireEvent.change(screen.getByLabelText("Reason"), { target: { value: "Investigated attack" } })
}

describe("manual scrubber workflow", () => {
  it("requires explicit match/target confirmation and preserves the source selector", async () => {
    await setup()
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    const confirm = await screen.findByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })

    expect(screen.getByRole("button", { name: "Create diversion" })).toBeDisabled()
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
    fireEvent.click(confirm)
    fireEvent.click(screen.getByRole("button", { name: "Create diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions")).toHaveLength(1))
    const sent = JSON.parse(controller.calls("POST", "/v1/diversions")[0].body ?? "{}")

    expect(sent).toMatchObject({ profile: "a", scope: { dst_prefix: "203.0.113.20/32", src_prefix: "198.51.100.0/24", protocol: 6, dst_ports: [443] }, confirmation: result().confirmation })
    expect(sent).not.toHaveProperty("target")
    expect(sent).not.toHaveProperty("owner")
  })

  it("discards a preview that completes after the form changes", async () => {
    await setup()
    const pending = deferred<Response>()

    controller.route("POST", "/v1/diversions/preview", () => pending.promise)
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    await waitFor(() => expect(controller.calls("POST", "/v1/diversions/preview")).toHaveLength(1))
    fireEvent.change(screen.getByLabelText("Victim host CIDR"), { target: { value: "203.0.113.21/32" } })
    await act(async () => { pending.resolve(json(result())) })
    await settle()
    expect(screen.queryByRole("checkbox", { name: "I confirm this traffic match and scrubber target." })).not.toBeInTheDocument()
    expect(controller.calls("POST", "/v1/diversions")).toHaveLength(0)
  })

  it("records a dry-run without requiring an armed or ready profile", async () => {
    await setup(true)
    fireEvent.click(screen.getByRole("button", { name: "Preview diversion" }))
    fireEvent.click(await screen.findByRole("checkbox", { name: "I confirm this traffic match and scrubber target." }))
    expect(screen.getByRole("button", { name: "Record simulation" })).toBeEnabled()
    fireEvent.click(screen.getByRole("button", { name: "Record simulation" }))
    await screen.findByText("Simulation recorded; no speaker mutation sent.")
    expect(controller.calls("POST", "/v1/scrubbers/a/arm")).toHaveLength(0)
  })
})
