import type { ReactNode } from "react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { MitigateNowDialog } from "@/components/dashboard/mitigate-now-dialog"

const mock = vi.hoisted(() => ({
  ingest: vi.fn(), push: vi.fn(), close: vi.fn(),
  success: vi.fn(), warning: vi.fn(), error: vi.fn(), info: vi.fn(),
}))

vi.mock("@/lib/api", () => ({ ingestEvent: mock.ingest }))

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: mock.push }) }))

vi.mock("sonner", () => ({ toast: { success: mock.success, warning: mock.warning, error: mock.error, info: mock.info } }))

vi.mock("@/components/ui/dialog", () => ({
  Dialog: ({ children }: { children: ReactNode }) => <>{children}</>,
  DialogContent: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DialogHeader: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DialogTitle: ({ children }: { children: ReactNode }) => <div>{children}</div>,
  DialogDescription: ({ children }: { children: ReactNode }) => <div>{children}</div>,
}))

vi.mock("@/components/ui/select", () => ({
  Select: ({ value, onValueChange, children }: { value: string; onValueChange: (value: string) => void; children: ReactNode }) =>
    <select aria-label="Attack Vector" value={value} onChange={event => onValueChange(event.target.value)}><option value="" />{children}</select>,
  SelectContent: ({ children }: { children: ReactNode }) => <>{children}</>,
  SelectItem: ({ value, children }: { value: string; children: ReactNode }) => <option value={value}>{children}</option>,
  SelectTrigger: () => null,
  SelectValue: () => null,
}))

afterEach(cleanup)

beforeEach(() => { vi.clearAllMocks() })

describe("manual mitigation creation outcome", () => {
  it.each([undefined, "unconfirmed"] as const)("opens saved intent and reports request outcome %s", async outcome => {
    mock.ingest.mockResolvedValue({ event_id: "event", mitigation_id: "saved-intent", status: "accepted", announcement_outcome: outcome })
    render(<MitigateNowDialog open onOpenChange={mock.close} />)
    fireEvent.change(screen.getByLabelText(/Destination IP/), { target: { value: "203.0.113.10" } })
    fireEvent.change(screen.getByRole("combobox", { name: "Attack Vector" }), { target: { value: "udp_flood" } })
    fireEvent.click(screen.getByRole("button", { name: "Submit" }))
    await waitFor(() => expect(mock.push).toHaveBeenCalledWith("/mitigations/saved-intent"))
    expect(mock.close).toHaveBeenCalledWith(false)
    expect(mock.ingest).toHaveBeenCalledWith(expect.objectContaining({ victim_ip: "203.0.113.10", vector: "udp_flood", action: "ban" }))

    if (outcome === "unconfirmed") {
      expect(mock.warning).toHaveBeenCalledWith("Mitigation intent saved; announcement unconfirmed", expect.objectContaining({ description: expect.stringContaining("saved for reconciliation") }))
      expect(mock.success).not.toHaveBeenCalled()
    } else {
      expect(mock.success).toHaveBeenCalledWith("Mitigation created", expect.any(Object))
      expect(mock.warning).not.toHaveBeenCalled()
    }

    expect(mock.error).not.toHaveBeenCalled()
  })
})
