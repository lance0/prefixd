import { render, screen } from "@testing-library/react"
import { describe, expect, it } from "vitest"
import { StatusPill, auditActionTone, healthTone, mitigationTone, signalGroupTone } from "@/components/dashboard/status-pill"
import { StatusBadge } from "@/components/dashboard/status-badge"

describe("status tones", () => {
  it.each([
    ["active", "success"],
    ["pending", "warning"],
    ["escalated", "danger"],
    ["rejected", "danger"],
    ["expired", "neutral"],
    ["withdrawn", "neutral"],
    ["something-new", "neutral"],
  ])("maps mitigation %s to %s", (status, tone) => {
    expect(mitigationTone(status)).toBe(tone)
  })

  it.each([
    ["healthy", "success"],
    ["ok", "success"],
    ["established", "success"],
    ["up", "success"],
    ["stale", "warning"],
    ["down", "danger"],
    ["no peers", "neutral"],
    ["degraded", "warning"],
    ["connecting", "warning"],
    ["error", "danger"],
    ["idle", "danger"],
    // BGP "active" means still trying to connect, not healthy.
    ["active", "danger"],
    ["unsupported", "neutral"],
    ["unobserved", "neutral"],
    ["", "neutral"],
  ])("maps health %s to %s", (state, tone) => {
    expect(healthTone(state)).toBe(tone)
  })

  it("maps signal groups: open is info, corroborated open is success, closed is neutral", () => {
    expect(signalGroupTone("open")).toBe("info")
    expect(signalGroupTone("open", true)).toBe("success")
    expect(signalGroupTone("resolved", true)).toBe("neutral")
    expect(signalGroupTone("expired")).toBe("neutral")
  })
})

describe("audit action tones", () => {
  it("flags only rejections and escalations", () => {
    expect(auditActionTone("reject")).toBe("danger")
    expect(auditActionTone("ESCALATE")).toBe("danger")
    expect(auditActionTone("withdraw")).toBe("neutral")
    expect(auditActionTone("safelist_add")).toBe("neutral")
  })
})

describe("StatusPill", () => {
  it("pairs the hue with a visible text label and a decorative dot", () => {
    const { container } = render(<StatusPill tone="danger">escalated</StatusPill>)
    const pill = screen.getByText("escalated")
    expect(pill).toHaveAttribute("data-tone", "danger")
    expect(pill.className).toContain("text-destructive")
    expect(container.querySelector('[aria-hidden="true"]')).not.toBeNull()
  })

  it("keeps the raw mitigation status as StatusBadge text", () => {
    render(<StatusBadge status="active" />)
    expect(screen.getByText("active", { exact: true })).toHaveAttribute("data-tone", "success")
  })
})
