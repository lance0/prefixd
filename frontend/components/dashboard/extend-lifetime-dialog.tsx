"use client"

import { useState } from "react"
import { useSWRConfig } from "swr"
import { Clock3, Loader2 } from "lucide-react"
import { toast } from "sonner"
import { useConfigSettings } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { apiErrorStatus, extendMitigation, type JsonValue, type Mitigation } from "@/lib/api"
import { useTimeFormat } from "@/components/time-zone-provider"
import { FlowSpecPreview } from "./flowspec-preview"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"

export function ExtendLifetimeDialog({ mitigation, now, onUpdated }: {
  mitigation: Mitigation
  now: number
  onUpdated: () => Promise<void>
}) {
  const permissions = usePermissions()
  const { data: config } = useConfigSettings()
  const { mutate } = useSWRConfig()
  const { formatTime } = useTimeFormat()
  const [open, setOpen] = useState(false)
  const [ttl, setTtl] = useState(600)
  const [reason, setReason] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const settings = config?.settings

  const object = (value: JsonValue | undefined): { [key: string]: JsonValue } =>
    value instanceof Object && !Array.isArray(value) ? value : {}

  const guardrails = object(settings?.guardrails)
  const timers = object(settings?.timers)

  const nonnegativeInteger = (value: JsonValue | undefined) =>
    Number.isInteger(value) && Number(value) >= 0 ? Number(value) : NaN

  const minimum = Math.max(1, nonnegativeInteger(guardrails.min_ttl_seconds ?? timers.min_ttl_seconds))
  const maximum = nonnegativeInteger(guardrails.max_ttl_seconds ?? timers.max_ttl_seconds)

  const eligible = permissions.isOperator && settings?.mode === "enforced" && settings?.pop === mitigation.pop
    && mitigation.customer_id !== null && mitigation.origin_mode === "enforced" && mitigation.action_type !== "blackhole"
    && (mitigation.status === "active" || mitigation.status === "escalated")
    && !mitigation.withdrawn_at && Date.parse(mitigation.expires_at) > now
    && Number.isInteger(minimum) && minimum > 0 && Number.isInteger(maximum) && maximum >= minimum

  const reasonBytes = new TextEncoder().encode(reason).length

  const valid = Number.isInteger(ttl) && ttl >= minimum && ttl <= maximum
    && reason.trim().length > 0 && reasonBytes <= 1024

  const proposed = now + ttl * 1000
  const unchanged = proposed <= Date.parse(mitigation.expires_at)

  async function refresh() {
    await Promise.allSettled([
      onUpdated(),
      mutate((key) => (key === "audit" || key === "mitigations") || (Array.isArray(key) && ["audit", "mitigations"].includes(key[0]))),
    ])
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault()

    if (!valid || busy || !eligible) return
    setBusy(true)
    setError(null)

    try {
      const result = await extendMitigation(mitigation.mitigation_id, ttl, reason.trim())
      await refresh()
      toast.success(result.extended ? "Saved lifetime extended" : "Existing expiry already meets the requested lifetime; no change recorded")
      setOpen(false)
    } catch (cause) {
      await refresh()
      const status = cause instanceof Error ? apiErrorStatus(cause) : null

      if (cause instanceof Error && status !== null && [400, 401, 403, 404, 409, 422, 429].includes(status)) {
        setError(cause.message)
      } else {
        setError("Could not confirm the lifetime update. Refresh the mitigation and audit before retrying; the update may have been saved.")
      }
    } finally {
      setBusy(false)
    }
  }

  if (!eligible && !open) return null

  return <Dialog open={open} onOpenChange={(value) => {
    if (busy) return

    if (value) {
      setTtl(Math.min(maximum, Math.max(minimum, Math.ceil((Date.parse(mitigation.expires_at) - Date.now()) / 1000) + 300)))
      setReason("")
      setError(null)
    }

    setOpen(value)
  }}>
    {eligible && <DialogTrigger asChild><Button variant="outline" size="sm"><Clock3 className="size-4" aria-hidden="true" />Extend lifetime</Button></DialogTrigger>}
    <DialogContent showCloseButton={!busy} className="max-h-[90dvh] overflow-y-auto">
      <DialogHeader>
        <DialogTitle>Extend saved FlowSpec lifetime</DialogTitle>
        <DialogDescription>Keep this exact match and action for longer. The controller rechecks current ownership and safety policy. Router enforcement remains independently observed.</DialogDescription>
      </DialogHeader>
      <form onSubmit={submit} className="space-y-4">
        <div className="overflow-hidden rounded-md border border-border"><FlowSpecPreview {...mitigation} /></div>
        {mitigation.action_type === "police" && <p className="text-sm text-muted-foreground">Exact rate: <span className="font-mono text-foreground">{mitigation.rate_bps} bps</span></p>}
        <div className="space-y-2">
          <Label htmlFor="extension-ttl">Remaining lifetime (seconds)</Label>
          <Input id="extension-ttl" type="number" min={minimum} max={maximum} step={1} value={ttl} disabled={busy} onChange={(event) => setTtl(Number(event.target.value))} aria-describedby="extension-bounds" />
          <p id="extension-bounds" className="text-xs text-muted-foreground">{minimum}–{maximum} seconds from the database update, rather than seconds added to the old expiry.</p>
        </div>
        <dl className="space-y-2 rounded-md border border-border bg-muted/40 p-3 text-sm">
          <div><dt className="text-muted-foreground">Current expiry</dt><dd>{formatTime(mitigation.expires_at, now)}</dd></div>
          <div><dt className="text-muted-foreground">{unchanged ? "Estimated expiry (unchanged)" : "Estimated new expiry"}</dt><dd>{formatTime(unchanged ? mitigation.expires_at : proposed, now)}</dd></div>
        </dl>
        <p className="text-xs text-muted-foreground">The saved expiry is never shortened. The database clock determines the result; a horizon already covered at the update writes no revision or audit entry.</p>
        {!eligible && <p role="status" className="text-sm text-warning">This mitigation is no longer eligible for a lifetime extension. Review its current status and audit before taking further action.</p>}
        <div className="space-y-2">
          <Label htmlFor="extension-reason">Reason for extending</Label>
          <Textarea id="extension-reason" required value={reason} disabled={busy} onChange={(event) => setReason(event.target.value)} placeholder="Why does this mitigation need more time?" aria-describedby="extension-reason-help" />
          <p id="extension-reason-help" className="text-xs text-muted-foreground">{reasonBytes} / 1,024 UTF-8 bytes. Required; saved with your identity and the old and new expiry.</p>
        </div>
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        <DialogFooter>
          <Button type="button" variant="outline" disabled={busy} onClick={() => setOpen(false)}>Cancel</Button>
          <Button type="submit" disabled={!eligible || !valid || busy}>{busy && <Loader2 className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" />}{unchanged ? "Confirm lifetime check" : "Confirm extension"}</Button>
        </DialogFooter>
      </form>
    </DialogContent>
  </Dialog>
}
