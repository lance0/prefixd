import { useRef, useState, type ReactNode } from "react"
import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { describe, expect, it, vi } from "vitest"
import { WithdrawConfirmDialog } from "@/components/dashboard/withdraw-confirm-dialog"
import { deferred } from "./support/fake-controller"

type TriggerState = "present" | "removed" | "disabled"

interface HarnessProps {
  onConfirm: (reason: string) => Promise<boolean>
  onClose?: () => void
  trigger?: TriggerState
  error?: string
  errorDetail?: string
  submitLabel?: string
  children?: ReactNode
}

function Harness({ onConfirm, onClose, trigger = "present", ...rest }: HarnessProps) {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement | null>(null)
  const fallback = useRef<HTMLHeadingElement | null>(null)

  return <>
    <h1 ref={fallback} tabIndex={-1}>Fallback</h1>
    {trigger !== "removed" && <button ref={triggerRef} disabled={trigger === "disabled"} onClick={() => setOpen(true)}>Open</button>}
    <WithdrawConfirmDialog
      open={open}
      onClose={() => { onClose?.(); setOpen(false) }}
      title="Withdraw mitigation"
      description="Request withdrawal for 203.0.113.10/32."
      reasonPlaceholder="e.g., Attack subsided"
      pendingStatus="Waiting for the controller..."
      onConfirm={onConfirm}
      trigger={triggerRef}
      fallback={fallback}
      {...rest}
    />
  </>
}

function setup(props: HarnessProps) {
  const view = render(<Harness {...props} />)

  return { ...view, rerender: (next: Partial<HarnessProps>) => view.rerender(<Harness {...props} {...next} />) }
}

async function open() {
  fireEvent.click(screen.getByRole("button", { name: "Open" }))

  return screen.findByRole("alertdialog", { name: "Withdraw mitigation" })
}

function reason(dialog: HTMLElement) {
  return within(dialog).getByLabelText("Withdrawal reason (optional)")
}

function escape() {
  fireEvent.keyDown(document.activeElement ?? document.body, { key: "Escape" })
}

async function closed() {
  await waitFor(() => expect(screen.queryByRole("alertdialog")).not.toBeInTheDocument())
}

describe("WithdrawConfirmDialog", () => {
  it("sends one confirmation and cannot be dismissed while it is pending", async () => {
    const pending = deferred<boolean>()
    const onConfirm = vi.fn(() => pending.promise)
    const onClose = vi.fn()

    setup({ onConfirm, onClose })
    const dialog = await open()

    fireEvent.change(reason(dialog), { target: { value: "Attack subsided" } })
    const submit = within(dialog).getByRole("button", { name: "Withdraw" })

    fireEvent.click(submit)
    fireEvent.click(submit)
    expect(onConfirm).toHaveBeenCalledTimes(1)
    expect(onConfirm).toHaveBeenCalledWith("Attack subsided")
    expect(within(dialog).getByRole("button", { name: "Withdrawing…" })).toBeDisabled()
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeDisabled()
    expect(reason(dialog)).toBeDisabled()
    expect(within(dialog).getByRole("status")).toHaveTextContent("Waiting for the controller...")

    escape()
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))
    await act(async () => {})
    expect(onClose).not.toHaveBeenCalled()
    expect(screen.getByRole("alertdialog")).toBeInTheDocument()

    await act(async () => pending.resolve(true))
    await closed()
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it.each([
    ["resolves false", () => Promise.resolve(false)],
    ["rejects", () => Promise.reject(new Error("network down"))],
  ])("stays open, keeps the reason and re-enables when the confirmation %s", async (_, outcome) => {
    const onConfirm = vi.fn(outcome)
    const onClose = vi.fn()

    setup({ onConfirm, onClose })
    const dialog = await open()

    fireEvent.change(reason(dialog), { target: { value: "False positive" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await waitFor(() => expect(within(dialog).getByRole("button", { name: "Withdraw" })).toBeEnabled())
    expect(screen.getByRole("alertdialog")).toBeInTheDocument()
    expect(onClose).not.toHaveBeenCalled()
    expect(reason(dialog)).toHaveValue("False positive")
    expect(reason(dialog)).toBeEnabled()
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toBeEnabled()
    expect(within(dialog).getByRole("status")).toHaveTextContent("")
  })

  it("closes once on completion, clears the reason and moves focus to the fallback", async () => {
    const onClose = vi.fn()

    setup({ onConfirm: () => Promise.resolve(true), onClose })
    let dialog = await open()

    fireEvent.change(reason(dialog), { target: { value: "Attack subsided" } })
    fireEvent.click(within(dialog).getByRole("button", { name: "Withdraw" }))
    await closed()
    expect(onClose).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.getByRole("heading", { name: "Fallback" })).toHaveFocus())

    // A completed withdrawal does not carry over: the next open starts empty
    // and Cancel returns focus to the opener again.
    dialog = await open()
    expect(reason(dialog)).toHaveValue("")
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))
    await closed()
    await waitFor(() => expect(screen.getByRole("button", { name: "Open" })).toHaveFocus())
  })

  it.each([
    ["Cancel", (dialog: HTMLElement) => fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))],
    ["Escape", () => escape()],
  ])("returns focus to the opener after %s", async (_, dismiss) => {
    const onClose = vi.fn()

    setup({ onConfirm: vi.fn(), onClose })
    const dialog = await open()

    dismiss(dialog)
    await closed()
    expect(onClose).toHaveBeenCalledTimes(1)
    await waitFor(() => expect(screen.getByRole("button", { name: "Open" })).toHaveFocus())
  })

  it.each(["removed", "disabled"] as const)("moves focus to the fallback when the opener is %s", async (state) => {
    const view = setup({ onConfirm: vi.fn() })
    const dialog = await open()

    view.rerender({ trigger: state })
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }))
    await closed()
    await waitFor(() => expect(screen.getByRole("heading", { name: "Fallback" })).toHaveFocus())
  })

  it("announces errors as an alert and renders the submit label and extra content", async () => {
    setup({
      onConfirm: vi.fn(),
      error: "Withdrawal failed.",
      errorDetail: "2 of 3 rules were not withdrawn.",
      submitLabel: "Withdraw 3",
      children: <p>Per-rule results</p>,
    })
    const dialog = await open()
    const alert = within(dialog).getByRole("alert")

    expect(alert).toHaveTextContent("Withdrawal failed.")
    expect(alert).toHaveTextContent("2 of 3 rules were not withdrawn.")
    expect(within(dialog).getByRole("status")).toHaveTextContent("")
    expect(within(dialog).getByRole("button", { name: "Withdraw 3" })).toBeEnabled()
    expect(within(dialog).getByText("Per-rule results")).toBeInTheDocument()
    expect(reason(dialog)).toHaveAttribute("maxLength", "1024")
    expect(reason(dialog)).toHaveAttribute("placeholder", "e.g., Attack subsided")
  })
})
