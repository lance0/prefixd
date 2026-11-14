"use client"

import { useId, useRef, useState, type ReactNode, type RefObject } from "react"
import { Loader2 } from "lucide-react"
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"

interface WithdrawConfirmDialogProps {
  open: boolean
  /** Called on Cancel, Escape or completion; never while a request is in flight. */
  onClose: () => void
  title: string
  description: ReactNode
  reasonPlaceholder: string
  submitLabel?: string
  pendingStatus: string
  /** Sends the withdrawal. Resolve true when it completed and the dialog should close. */
  onConfirm: (reason: string) => Promise<boolean>
  error?: string | null
  errorDetail?: string
  /** The control that opened the dialog; focus returns here after Cancel or Escape. */
  trigger: RefObject<HTMLElement | null>
  /** A control that outlives the row; focus lands here after completion or when the trigger is gone. */
  fallback: RefObject<HTMLElement | null>
  children?: ReactNode
}

/** The one withdrawal confirmation: a request in flight cannot be repeated or dismissed. */
export function WithdrawConfirmDialog({
  open, onClose, title, description, reasonPlaceholder, submitLabel = "Withdraw", pendingStatus,
  onConfirm, error, errorDetail, trigger, fallback, children,
}: WithdrawConfirmDialogProps) {
  const reasonId = useId()
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)
  const inFlight = useRef(false)
  const completed = useRef(false)

  const close = () => {
    setReason("")
    onClose()
  }

  const confirm = async () => {
    if (inFlight.current) return
    inFlight.current = true
    setBusy(true)
    let done = false

    try {
      done = await onConfirm(reason)
    } catch {
      // A rejected request did not complete; keep the dialog open for a retry.
      done = false
    } finally {
      inFlight.current = false
      setBusy(false)
    }

    if (done) {
      completed.current = true
      close()
    }
  }

  return (
    <AlertDialog open={open} onOpenChange={(next) => { if (!next && !inFlight.current) close() }}>
      <AlertDialogContent
        className="max-h-[calc(100dvh-2rem)] overflow-y-auto"
        onOpenAutoFocus={() => { completed.current = false }}
        onCloseAutoFocus={(event) => {
          event.preventDefault()
          const opener = trigger.current
          const usable = !completed.current && opener?.isConnected && !(opener instanceof HTMLButtonElement && opener.disabled)
          const target = usable ? opener : fallback.current
          target?.focus()
        }}
      >
        <AlertDialogHeader>
          <AlertDialogTitle>{title}</AlertDialogTitle>
          <AlertDialogDescription>{description}</AlertDialogDescription>
        </AlertDialogHeader>
        <div className="py-4">
          <Label htmlFor={reasonId}>Withdrawal reason (optional)</Label>
          <Input
            id={reasonId}
            className="mt-2"
            maxLength={1024}
            placeholder={reasonPlaceholder}
            value={reason}
            disabled={busy}
            onChange={(event) => setReason(event.target.value)}
          />
          {error && (
            <div role="alert" className="mt-2 text-sm text-destructive">
              <p>{error}</p>
              {errorDetail && <p>{errorDetail}</p>}
            </div>
          )}
          <p role="status" className="mt-2 text-sm text-muted-foreground">{busy ? pendingStatus : ""}</p>
          {children}
        </div>
        <AlertDialogFooter>
          <AlertDialogCancel disabled={busy}>Cancel</AlertDialogCancel>
          <Button type="button" variant="destructive" onClick={confirm} disabled={busy}>
            {busy && <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" />}
            {busy ? "Withdrawing…" : submitLabel}
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  )
}
