"use client"

import { useState, type FormEvent } from "react"
import { useRouter } from "next/navigation"
import { Ban, RefreshCw } from "lucide-react"
import { toast } from "sonner"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { createBlackhole } from "@/lib/api"

// The controller caps blackholes at blackhole.max_ttl_seconds (3600 by default).
const DEFAULT_TTL_SECONDS = "600"

interface BlackholeDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
}

/**
 * Admin-only manual blackhole (ADR 027). The operator types the victim address a
 * second time; submission stays disabled until both entries match exactly, and the
 * controller rejects a mismatch again with 400.
 */
export function BlackholeDialog({ open, onOpenChange }: BlackholeDialogProps) {
  const router = useRouter()
  const [victimIp, setVictimIp] = useState("")
  const [confirmIp, setConfirmIp] = useState("")
  const [ttl, setTtl] = useState(DEFAULT_TTL_SECONDS)
  const [reason, setReason] = useState("")
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const ttlSeconds = Number(ttl)
  const confirmed = victimIp !== "" && confirmIp === victimIp
  const mismatch = confirmIp !== "" && !confirmed
  const isValid = confirmed && reason.trim() !== "" && Number.isInteger(ttlSeconds) && ttlSeconds > 0

  const reset = () => {
    setVictimIp("")
    setConfirmIp("")
    setTtl(DEFAULT_TTL_SECONDS)
    setReason("")
    setError(null)
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()

    if (!isValid || isSubmitting) return
    setIsSubmitting(true)
    setError(null)

    try {
      const mitigation = await createBlackhole({ victim_ip: victimIp, confirm_victim_ip: confirmIp, reason, ttl_seconds: ttlSeconds })

      if (mitigation.announcement_outcome === "unconfirmed") {
        toast.warning("Blackhole intent saved; announcement unconfirmed", {
          description: "Intent is saved for reconciliation. Check speaker state and mitigation details.",
        })
      } else {
        toast.success("Blackhole created", { description: victimIp })
      }

      reset()
      onOpenChange(false)
      router.push(`/mitigations/${mitigation.mitigation_id}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create blackhole")
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (isSubmitting) return
        onOpenChange(next)

        if (!next) reset()
      }}
    >
      <DialogContent className="bg-card sm:max-w-lg">
        <form onSubmit={handleSubmit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2 text-sm">
              <Ban className="size-4 text-destructive" aria-hidden="true" />
              Blackhole a host
            </DialogTitle>
            <DialogDescription className="text-xs">
              Drops <strong className="text-foreground">all traffic</strong> to the address, including legitimate traffic,
              until it expires or is withdrawn. Router enforcement depends on the router&apos;s blackhole policy and is not verified here.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-1.5">
            <Label htmlFor="bh-ip">Victim IP</Label>
            <Input
              id="bh-ip"
              required
              placeholder="203.0.113.10"
              value={victimIp}
              onChange={(e) => setVictimIp(e.target.value)}
              className="h-9 font-mono"
              spellCheck={false}
              autoComplete="off"
            />
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-[8rem_1fr]">
            <div className="space-y-1.5">
              <Label htmlFor="bh-ttl">TTL (seconds)</Label>
              <Input
                id="bh-ttl"
                required
                type="number"
                min={1}
                step={1}
                value={ttl}
                onChange={(e) => setTtl(e.target.value)}
                className="h-9 font-mono tabular-nums"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bh-reason">Reason</Label>
              <Input
                id="bh-reason"
                required
                placeholder="e.g., volumetric attack saturating transit"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                className="h-9"
              />
            </div>
          </div>

          <div className="space-y-1.5 rounded-md border border-destructive/50 bg-destructive/10 p-3">
            <Label htmlFor="bh-confirm">Type the victim IP again to confirm</Label>
            <Input
              id="bh-confirm"
              required
              value={confirmIp}
              onChange={(e) => setConfirmIp(e.target.value)}
              aria-invalid={mismatch}
              aria-describedby="bh-confirm-hint"
              className="h-9 bg-background font-mono"
              spellCheck={false}
              autoComplete="off"
            />
            <p id="bh-confirm-hint" className={mismatch ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
              {mismatch ? "Does not match the victim IP." : "Must match exactly."}
            </p>
          </div>

          {error && (
            <div role="alert" className="rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">
              {error}
            </div>
          )}

          <DialogFooter>
            <Button type="button" variant="outline" size="sm" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" size="sm" disabled={!isValid || isSubmitting}>
              {isSubmitting ? (
                <>
                  <RefreshCw className="size-3.5 animate-spin" aria-hidden="true" />
                  Submitting…
                </>
              ) : (
                <>
                  <Ban className="size-3.5" aria-hidden="true" />
                  Blackhole {confirmed ? victimIp : "host"}
                </>
              )}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
