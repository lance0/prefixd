import { describe, expect, it } from "vitest"
import { screen, waitFor } from "@testing-library/react"
import { Sidebar } from "@/components/dashboard/sidebar"
import { Dialog } from "@/components/ui/dialog"
import { json, operatorResponse, renderApp, settle, signIn, useFakeController } from "./support/fake-controller"

const controller = useFakeController()

async function renderSidebar(counts: { mitigations: number; groups: number }, collapsed?: boolean) {
  signIn(controller, "credentials", operatorResponse("viewer"))
  controller.route("GET", "/v1/stats", () => json({ total_active: counts.mitigations, total_mitigations: 0, total_events: 0, pops: [] }))
  controller.route("GET", "/v1/signal-groups", () => json({ groups: [], count: counts.groups, next_cursor: null, has_more: false }))
  renderApp(<Dialog><Sidebar isCollapsed={collapsed} /></Dialog>)
  await waitFor(() => expect(controller.calls("GET", "/v1/stats")).toHaveLength(1))
  await waitFor(() => expect(controller.calls("GET", "/v1/signal-groups")).toHaveLength(1))
  await settle()
}

describe("sidebar accessible counts", () => {
  it.each([
    { mitigations: 3, groups: 7, mitigationName: "Mitigations (3)", groupName: "Correlation (7)", mitigationBadge: "3", groupBadge: "7" },
    { mitigations: 0, groups: 0, mitigationName: "Mitigations", groupName: "Correlation", mitigationBadge: "", groupBadge: "" },
    { mitigations: 99, groups: 1, mitigationName: "Mitigations (99)", groupName: "Correlation (1)", mitigationBadge: "99", groupBadge: "1" },
    { mitigations: 100, groups: 500, mitigationName: "Mitigations (99+)", groupName: "Correlation (99+)", mitigationBadge: "99+", groupBadge: "99+" },
  ])("includes the displayed counts when collapsed ($mitigations mitigations, $groups groups)", async ({ mitigations, groups, mitigationName, groupName, mitigationBadge, groupBadge }) => {
    await renderSidebar({ mitigations, groups }, true)
    const mitigationLink = screen.getByRole("link", { name: mitigationName })
    const groupLink = screen.getByRole("link", { name: groupName })
    expect(mitigationLink.textContent).toBe(mitigationBadge)
    expect(groupLink.textContent).toBe(groupBadge)
  })

  it("preserves the expanded links' visible label and count as their accessible names", async () => {
    await renderSidebar({ mitigations: 3, groups: 7 })
    expect(screen.getByRole("link", { name: /^Mitigations\s*3$/ })).toHaveAttribute("href", "/mitigations")
    expect(screen.getByRole("link", { name: /^Correlation\s*7$/ })).toHaveAttribute("href", "/correlation")
  })
})
