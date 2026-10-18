import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { Sidebar } from "@/components/dashboard/sidebar"
import { Dialog } from "@/components/ui/dialog"

const mock = vi.hoisted(() => ({ mitigations: 0, groups: 0 }))

vi.mock("next/navigation", () => ({ usePathname: () => "/" }))

vi.mock("@/hooks/use-permissions", () => ({
  usePermissions: () => ({ isAdmin: false, authDisabled: false }),
}))

vi.mock("@/hooks/use-api", () => ({
  useStats: () => ({ data: { total_active: mock.mitigations } }),
  useOpenSignalGroupCount: () => mock.groups,
}))

afterEach(cleanup)

beforeEach(() => { mock.mitigations = 0; mock.groups = 0 })

describe("sidebar accessible counts", () => {
  it.each([
    { mitigations: 3, groups: 7, mitigationName: "Mitigations (3)", groupName: "Correlation (7)", mitigationBadge: "3", groupBadge: "7" },
    { mitigations: 0, groups: 0, mitigationName: "Mitigations", groupName: "Correlation", mitigationBadge: "", groupBadge: "" },
    { mitigations: 99, groups: 1, mitigationName: "Mitigations (99)", groupName: "Correlation (1)", mitigationBadge: "99", groupBadge: "1" },
    { mitigations: 100, groups: 500, mitigationName: "Mitigations (99+)", groupName: "Correlation (99+)", mitigationBadge: "99+", groupBadge: "99+" },
  ])("includes the displayed counts when collapsed ($mitigations mitigations, $groups groups)", ({ mitigations, groups, mitigationName, groupName, mitigationBadge, groupBadge }) => {
    mock.mitigations = mitigations
    mock.groups = groups
    render(<Dialog><Sidebar isCollapsed /></Dialog>)
    const mitigationLink = screen.getByRole("link", { name: mitigationName })
    const groupLink = screen.getByRole("link", { name: groupName })
    expect(mitigationLink.textContent).toBe(mitigationBadge)
    expect(groupLink.textContent).toBe(groupBadge)
  })

  it("preserves the expanded links' visible label and count as their accessible names", () => {
    mock.mitigations = 3
    mock.groups = 7
    render(<Dialog><Sidebar /></Dialog>)
    expect(screen.getByRole("link", { name: /^Mitigations\s*3$/ })).toHaveAttribute("href", "/mitigations")
    expect(screen.getByRole("link", { name: /^Correlation\s*7$/ })).toHaveAttribute("href", "/correlation")
  })
})
