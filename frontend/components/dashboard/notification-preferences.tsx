"use client"

import { useCallback, useEffect, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Checkbox } from "@/components/ui/checkbox"
import { Label } from "@/components/ui/label"
import { Button } from "@/components/ui/button"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Save } from "lucide-react"
import { ErrorState, LoadingRows } from "@/components/dashboard/states"
import { useNotificationPreferences } from "@/hooks/use-api"
import { updateNotificationPreferences, type NotificationPreferences } from "@/lib/api"
import { toast } from "sonner"

const EVENT_TYPES = [
  { value: "mitigation.created", label: "Mitigation created", critical: true },
  { value: "mitigation.escalated", label: "Mitigation escalated", critical: true },
  { value: "mitigation.withdrawn", label: "Mitigation withdrawn", critical: false },
  { value: "mitigation.expired", label: "Mitigation expired", critical: false },
  { value: "config.reloaded", label: "Configuration reloaded", critical: false },
  { value: "guardrail.rejected", label: "Guardrail rejected", critical: false },
] as const

const HOURS = Array.from({ length: 24 }, (_, i) => i)

export function NotificationPreferencesPanel() {
  const { data, error, isLoading, mutate } = useNotificationPreferences()
  const [mutedEvents, setMutedEvents] = useState<string[]>([])
  const [quietStart, setQuietStart] = useState<number | null>(null)
  const [quietEnd, setQuietEnd] = useState<number | null>(null)
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)

  useEffect(() => {
    if (data) {
      setMutedEvents(data.muted_events)
      setQuietStart(data.quiet_hours_start)
      setQuietEnd(data.quiet_hours_end)
      setDirty(false)
    }
  }, [data])

  const toggleMuted = useCallback((event: string) => {
    setMutedEvents((prev) => {
      const next = prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]

      return next
    })
    setDirty(true)
  }, [])

  const handleSave = useCallback(async () => {
    setSaving(true)

    try {
      await updateNotificationPreferences({
        muted_events: mutedEvents,
        quiet_hours_start: quietStart,
        quiet_hours_end: quietEnd,
      })
      await mutate()
      setDirty(false)
      toast.success("Notification preferences saved")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save preferences")
    } finally {
      setSaving(false)
    }
  }, [mutedEvents, quietStart, quietEnd, mutate])

  if (isLoading) {
    return <LoadingRows label="Loading notification preferences" rows={3} />
  }

  // Never show defaults for a failed read: saving them would overwrite the stored preferences.
  if (error || !data) {
    return (
      <ErrorState
        title="Unable to load notification preferences"
        detail="Your saved preferences are unchanged. Retry before editing them."
        onRetry={() => { void mutate() }}
      />
    )
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>Toast notifications</CardTitle>
          <p className="text-xs text-muted-foreground">
            Muted events will not show toast notifications. SWR cache updates still happen.
          </p>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {EVENT_TYPES.map((evt) => {
              const isMuted = mutedEvents.includes(evt.value)

              return (
                <div key={evt.value} className="flex items-center gap-2">
                  <Checkbox
                    checked={!isMuted}
                    onCheckedChange={() => toggleMuted(evt.value)}
                    id={`notif-${evt.value}`}
                  />
                  <Label htmlFor={`notif-${evt.value}`} className="cursor-pointer">
                    {evt.label}
                    {evt.critical && <span className="text-xs text-muted-foreground ml-1">(critical)</span>}
                  </Label>
                </div>
              )
            })}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Quiet hours (UTC)</CardTitle>
          <p className="text-xs text-muted-foreground">
            During quiet hours, only critical events (created, escalated) show toasts.
          </p>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-3">
            <Select
              value={quietStart !== null ? String(quietStart) : "off"}
              onValueChange={(v) => {
                if (v === "off") {
                  setQuietStart(null)
                  setQuietEnd(null)
                } else {
                  setQuietStart(Number(v))

                  if (quietEnd === null) setQuietEnd(8)
                }

                setDirty(true)
              }}
            >
              <SelectTrigger className="w-28 h-8">
                <SelectValue placeholder="Start" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="off">Off</SelectItem>
                {HOURS.map((h) => (
                  <SelectItem key={h} value={String(h)}>{String(h).padStart(2, "0")}:00</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {quietStart !== null && (
              <>
                <span className="text-xs text-muted-foreground">to</span>
                <Select
                  value={quietEnd !== null ? String(quietEnd) : "8"}
                  onValueChange={(v) => {
                    setQuietEnd(Number(v))
                    setDirty(true)
                  }}
                >
                  <SelectTrigger className="w-28 h-8">
                    <SelectValue placeholder="End" />
                  </SelectTrigger>
                  <SelectContent>
                    {HOURS.map((h) => (
                      <SelectItem key={h} value={String(h)}>{String(h).padStart(2, "0")}:00</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <span className="text-xs text-muted-foreground">UTC</span>
              </>
            )}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button size="sm" onClick={handleSave} disabled={!dirty || saving}>
          <Save className="h-3.5 w-3.5 mr-1.5" />
          {saving ? "Saving…" : "Save preferences"}
        </Button>
      </div>
    </div>
  )
}
