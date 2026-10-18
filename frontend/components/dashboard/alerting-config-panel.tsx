"use client"

import { useCallback, useMemo, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { StatusPill } from "@/components/dashboard/status-pill"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Loader2, Send, CheckCircle2, XCircle, AlertCircle, Plus, Trash2, Pencil, Save, Undo2 } from "lucide-react"
import { useAlertingConfig } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { testAlerting, updateAlertingConfig, type AlertingDestination, type AlertingTestResult } from "@/lib/api"
import { toast } from "sonner"
import { cn } from "@/lib/utils"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"

const DEST_TYPES = ["slack", "discord", "teams", "telegram", "pagerduty", "opsgenie", "generic"] as const

type DestType = (typeof DEST_TYPES)[number]

// mitigation.escalated is never emitted, so it is not offered. A stored filter
// that still lists it is kept on save and shown as a badge.
const EVENT_TYPES = [
  "mitigation.created",
  "mitigation.withdrawn",
  "mitigation.expired",
  "config.reloaded",
  "guardrail.rejected",
] as const

const DEST_LABELS: Record<DestType, string> = {
  slack: "Slack",
  discord: "Discord",
  teams: "Microsoft Teams",
  telegram: "Telegram",
  pagerduty: "PagerDuty",
  opsgenie: "OpsGenie",
  generic: "Generic webhook",
}

// Third-party brand colours identify each destination as a small swatch beside its name.
const DEST_COLORS: Record<DestType, string> = {
  slack: "bg-[#4A154B]",
  discord: "bg-[#5865F2]",
  teams: "bg-[#6264A7]",
  telegram: "bg-[#0088CC]",
  pagerduty: "bg-[#06AC38]",
  opsgenie: "bg-[#2684FF]",
  generic: "bg-muted-foreground",
}

interface DraftDestination extends AlertingDestination {
  _id: string
}

function newId(): string {
  return Math.random().toString(36).slice(2, 10)
}

function emptyDest(type: DestType): DraftDestination {
  const base: DraftDestination = { type, _id: newId() }

  switch (type) {
    case "slack": return { ...base, webhook_url: "", channel: "" }
    case "discord": return { ...base, webhook_url: "" }
    case "teams": return { ...base, webhook_url: "" }
    case "telegram": return { ...base, bot_token: "", chat_id: "" }
    case "pagerduty": return { ...base, routing_key: "", events_url: "https://events.pagerduty.com/v2/enqueue" }
    case "opsgenie": return { ...base, api_key: "", region: "us" }
    case "generic": return { ...base, url: "", secret: "" }
  }
}

function toDraft(d: AlertingDestination): DraftDestination {
  return { ...d, _id: newId() }
}

function stripDraftId(d: DraftDestination): AlertingDestination {
  const { _id, ...rest } = d

  return rest
}

function destSummary(d: AlertingDestination): string {
  if (d.type === "slack" && d.channel) return d.channel

  if (d.type === "telegram" && d.chat_id) return `chat ${d.chat_id}`

  if (d.type === "pagerduty" && d.events_url) return d.events_url

  if (d.type === "opsgenie" && d.region) return `${d.region.toUpperCase()} region`

  if (d.type === "generic" && d.url) return d.url

  return ""
}

function DestinationEventsFilter({ dest, onChange }: { dest: DraftDestination; onChange: (d: DraftDestination) => void }) {
  const destEvents = dest.events ?? []

  const toggleDestEvent = (event: string) => {
    const next = destEvents.includes(event) ? destEvents.filter((e) => e !== event) : [...destEvents, event]
    onChange({ ...dest, events: next })
  }

  return (
    <div className="mt-3 pt-3 border-t border-border/50">
      <Label className="text-muted-foreground">Per-Destination Events</Label>
      <p className="text-xs text-muted-foreground mb-1.5">Override global filters for this destination. Empty = uses global.</p>
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-1.5">
        {EVENT_TYPES.map((event) => (
          <div key={event} className="flex items-center gap-1.5">
            <Checkbox
              checked={destEvents.includes(event)}
              onCheckedChange={() => toggleDestEvent(event)}
              id={`dest-event-${dest._id}-${event}`}
            />
            <Label htmlFor={`dest-event-${dest._id}-${event}`} className="cursor-pointer">{event}</Label>
          </div>
        ))}
      </div>
      {destEvents.length === 0 && (
        <p className="text-xs text-muted-foreground/60 mt-1">Using global events</p>
      )}
    </div>
  )
}

function DestinationForm({ dest, onChange }: { dest: DraftDestination; onChange: (d: DraftDestination) => void }) {
  const update = (field: string, value: string) => onChange({ ...dest, [field]: value })

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-2">
      {dest.type === "slack" && (
        <>
          <div className="space-y-1 sm:col-span-2">
            <Label className="text-muted-foreground">Webhook URL</Label>
            <Input
              type={dest.webhook_url === "***" ? "password" : "text"}
              value={dest.webhook_url ?? ""}
              onChange={(e) => update("webhook_url", e.target.value)}
              placeholder={dest.webhook_url === "***" ? "Leave as *** to keep existing" : "https://hooks.slack.com/services/…"}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-muted-foreground">Channel (optional)</Label>
            <Input value={dest.channel ?? ""} onChange={(e) => update("channel", e.target.value)} placeholder="#ddos-alerts" className="h-8 text-xs font-mono" />
          </div>
        </>
      )}
      {dest.type === "discord" && (
        <div className="space-y-1 sm:col-span-2">
          <Label className="text-muted-foreground">Webhook URL</Label>
          <Input
            type={dest.webhook_url === "***" ? "password" : "text"}
            value={dest.webhook_url ?? ""}
            onChange={(e) => update("webhook_url", e.target.value)}
            placeholder="https://discord.com/api/webhooks/…"
            className="h-8 text-xs font-mono"
          />
        </div>
      )}
      {dest.type === "teams" && (
        <div className="space-y-1 sm:col-span-2">
          <Label className="text-muted-foreground">Webhook URL</Label>
          <Input
            type={dest.webhook_url === "***" ? "password" : "text"}
            value={dest.webhook_url ?? ""}
            onChange={(e) => update("webhook_url", e.target.value)}
            placeholder="https://prod-XX.westus.logic.azure.com/…"
            className="h-8 text-xs font-mono"
          />
        </div>
      )}
      {dest.type === "telegram" && (
        <>
          <div className="space-y-1">
            <Label className="text-muted-foreground">Bot token</Label>
            <Input
              type={dest.bot_token === "***" ? "password" : "text"}
              value={dest.bot_token ?? ""}
              onChange={(e) => update("bot_token", e.target.value)}
              placeholder={dest.bot_token === "***" ? "Leave as *** to keep existing" : "123456:ABC-DEF…"}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-muted-foreground">Chat ID</Label>
            <Input value={dest.chat_id ?? ""} onChange={(e) => update("chat_id", e.target.value)} placeholder="-100123456789" className="h-8 text-xs font-mono" />
          </div>
        </>
      )}
      {dest.type === "pagerduty" && (
        <>
          <div className="space-y-1">
            <Label className="text-muted-foreground">Routing key</Label>
            <Input
              type={dest.routing_key === "***" ? "password" : "text"}
              value={dest.routing_key ?? ""}
              onChange={(e) => update("routing_key", e.target.value)}
              placeholder={dest.routing_key === "***" ? "Leave as *** to keep existing" : "routing-key"}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-muted-foreground">Events URL</Label>
            <Input value={dest.events_url ?? ""} onChange={(e) => update("events_url", e.target.value)} className="h-8 text-xs font-mono" />
          </div>
        </>
      )}
      {dest.type === "opsgenie" && (
        <>
          <div className="space-y-1">
            <Label className="text-muted-foreground">API Key</Label>
            <Input
              type={dest.api_key === "***" ? "password" : "text"}
              value={dest.api_key ?? ""}
              onChange={(e) => update("api_key", e.target.value)}
              placeholder={dest.api_key === "***" ? "Leave as *** to keep existing" : "api-key"}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-muted-foreground">Region</Label>
            <Select value={dest.region ?? "us"} onValueChange={(v) => update("region", v)}>
              <SelectTrigger className="h-8">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="us">US</SelectItem>
                <SelectItem value="eu">EU</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </>
      )}
      {dest.type === "generic" && (
        <>
          <div className="space-y-1 sm:col-span-2">
            <Label className="text-muted-foreground">URL</Label>
            <Input value={dest.url ?? ""} onChange={(e) => update("url", e.target.value)} placeholder="https://example.com/webhook" className="h-8 text-xs font-mono" />
          </div>
          <div className="space-y-1">
            <Label className="text-muted-foreground">HMAC Secret (optional)</Label>
            <Input
              type={dest.secret === "***" ? "password" : "text"}
              value={dest.secret ?? ""}
              onChange={(e) => update("secret", e.target.value)}
              placeholder={dest.secret === "***" ? "Leave as *** to keep existing" : "hmac-secret"}
              className="h-8 text-xs font-mono"
            />
          </div>
        </>
      )}
      <div className="sm:col-span-2">
        <DestinationEventsFilter dest={dest} onChange={onChange} />
      </div>
    </div>
  )
}

function ReadOnlyDestCard({ dest, testResult }: { dest: AlertingDestination; testResult?: AlertingTestResult }) {
  const summary = destSummary(dest)

  return (
    <div className="bg-secondary/50 px-3 py-2.5">
      <div className="flex items-center gap-3">
        <span aria-hidden="true" className={cn("size-2.5 shrink-0 rounded-sm", DEST_COLORS[dest.type] || DEST_COLORS.generic)} />
        <div className="flex-1 min-w-0">
          <span className="text-xs font-medium">{DEST_LABELS[dest.type] ?? dest.type}</span>
          {summary ? <span className="text-xs font-mono text-muted-foreground ml-2">{summary}</span> : null}
        </div>
        {testResult && (
          testResult.status === "ok" ? (
            <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
          ) : (
            <div className="flex items-center gap-1 shrink-0">
              <XCircle className="h-4 w-4 text-destructive" />
              {testResult.error ? <span className="text-xs text-destructive max-w-[150px] truncate">{testResult.error}</span> : null}
            </div>
          )
        )}
      </div>
      {dest.events && dest.events.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-1.5 ml-11">
          {dest.events.map((e) => (
            <Badge key={e} variant="outline" className="py-0">{e}</Badge>
          ))}
        </div>
      )}
    </div>
  )
}

export function AlertingConfigPanel() {
  const { data, error, isLoading, mutate: mutateAlerting } = useAlertingConfig()
  const { canEditAlerting, canReloadConfig } = usePermissions()
  const [testing, setTesting] = useState(false)
  const [testResults, setTestResults] = useState<AlertingTestResult[] | null>(null)
  const [testError, setTestError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  // Draft state for editing
  const [draft, setDraft] = useState<DraftDestination[] | null>(null)
  const [draftEvents, setDraftEvents] = useState<string[] | null>(null)
  const [editingIndex, setEditingIndex] = useState<number | null>(null)
  const [addingType, setAddingType] = useState<DestType | null>(null)

  const isEditing = draft !== null

  const initDraft = useCallback(() => {
    if (!data) return
    setDraft(data.destinations.map(toDraft))
    setDraftEvents([...data.events])
  }, [data])

  const discardDraft = useCallback(() => {
    setDraft(null)
    setDraftEvents(null)
    setEditingIndex(null)
    setAddingType(null)
  }, [])

  const hasChanges = useMemo(() => {
    if (!draft || !draftEvents || !data) return false
    const strippedDraft = draft.map(stripDraftId)

    return JSON.stringify(strippedDraft) !== JSON.stringify(data.destinations) ||
      JSON.stringify(draftEvents) !== JSON.stringify(data.events)
  }, [draft, draftEvents, data])

  const handleSave = useCallback(async () => {
    if (!draft || !draftEvents) return
    setSaving(true)

    try {
      await updateAlertingConfig({
        destinations: draft.map(stripDraftId),
        events: draftEvents,
      })
      await mutateAlerting()
      discardDraft()
      toast.success("Alerting config saved and reloaded")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save alerting config")
    } finally {
      setSaving(false)
    }
  }, [draft, draftEvents, mutateAlerting, discardDraft])

  const handleTest = async () => {
    setTesting(true)
    setTestResults(null)
    setTestError(null)

    try {
      const response = await testAlerting()
      setTestResults(response.results)
    } catch (e) {
      setTestError(e instanceof Error ? e.message : "Test failed")
    } finally {
      setTesting(false)
    }
  }

  const addDest = useCallback((type: DestType) => {
    setDraft((prev) => {
      const current = prev ?? []
      const next = [...current, emptyDest(type)]
      setEditingIndex(current.length)

      return next
    })
    setAddingType(null)
  }, [])

  const removeDest = useCallback((index: number) => {
    setDraft((prev) => (prev ?? []).filter((_, i) => i !== index))

    if (editingIndex === index) setEditingIndex(null)
    else if (editingIndex !== null && editingIndex > index) setEditingIndex(editingIndex - 1)
  }, [editingIndex])

  const updateDest = useCallback((index: number, updated: DraftDestination) => {
    setDraft((prev) => (prev ?? []).map((d, i) => (i === index ? updated : d)))
  }, [])

  const toggleEvent = useCallback((event: string) => {
    setDraftEvents((prev) => {
      if (!prev) return prev

      return prev.includes(event) ? prev.filter((e) => e !== event) : [...prev, event]
    })
  }, [])

  const readOnlyDestinations = useMemo(() => {
    if (!data) return []

    return data.destinations.map((dest, i) => ({
      ...dest,
      _id: `readonly-${dest.type}-${destSummary(dest)}-${i}`,
    }))
  }, [data])

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Alert destinations</CardTitle>
        </CardHeader>
        <LoadingRows label="Loading alerting configuration" rows={2} />
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle>Alert destinations</CardTitle>
        </CardHeader>
        <ErrorState
          title="Unable to load alerting configuration"
          detail={`${error.message}. Alerts keep using the running configuration; retry, or check that the controller is reachable.`}
          onRetry={() => { void mutateAlerting() }}
        />
      </Card>
    )
  }

  if (!data) return null

  // Read-only mode
  if (!canEditAlerting) {
    return (
      <div className="space-y-3">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Alert destinations</CardTitle>
              {canReloadConfig ? (
                <Button variant="outline" size="sm" onClick={handleTest} disabled={testing}>
                  {testing ? <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> : <Send className="h-3 w-3 mr-1.5" />}
                  Send test alert
                </Button>
              ) : null}
            </div>
          </CardHeader>
          {data.destinations.length === 0 ? (
            <EmptyState
              title="No alert destinations configured"
              description="Alerts are not being delivered anywhere. An operator with alerting access can add a destination."
            />
          ) : (
            <CardContent className="space-y-2">
              {data.destinations.map((dest, i) => (
                <ReadOnlyDestCard key={`${dest.type}-${i}`} dest={dest} testResult={testResults?.[i]} />
              ))}
            </CardContent>
          )}
        </Card>
        {data.events.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Event filters</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-1.5">
                {data.events.map((event) => (
                  <Badge key={event} variant="outline">{event}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
        {testError && (
          <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/50 text-sm">
            <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
            <span className="text-destructive text-xs">{testError}</span>
          </div>
        )}
      </div>
    )
  }

  // Editable mode
  const destinations = isEditing ? draft! : readOnlyDestinations
  const events = isEditing ? draftEvents! : data.events

  return (
    <div className="space-y-3">
      {/* Action bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {!isEditing ? (
            <Button variant="outline" size="sm" onClick={initDraft}>
              <Pencil className="h-3.5 w-3.5 mr-1.5" />
              Edit
            </Button>
          ) : (
            <>
              {addingType === null ? (
                <Select
                  onValueChange={(v) => {
                    const type = DEST_TYPES.find((t) => t === v)

                    if (type) addDest(type)
                  }}
                >
                  <SelectTrigger className="w-44 h-8">
                    <Plus className="h-3.5 w-3.5 mr-1" />
                    <span>Add destination</span>
                  </SelectTrigger>
                  <SelectContent>
                    {DEST_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>{DEST_LABELS[t]}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : null}
            </>
          )}
          <Button variant="outline" size="sm" onClick={handleTest} disabled={testing}>
            {testing ? <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> : <Send className="h-3 w-3 mr-1.5" />}
            Test
          </Button>
        </div>
        {isEditing && (
          <div className="flex items-center gap-2">
            {hasChanges && (
              <StatusPill tone="warning">Unsaved changes</StatusPill>
            )}
            <Button variant="ghost" size="sm" onClick={discardDraft} disabled={saving}>
              <Undo2 className="h-3.5 w-3.5 mr-1.5" />
              Discard
            </Button>
            <Button size="sm" onClick={handleSave} disabled={!hasChanges || saving}>
              <Save className="h-3.5 w-3.5 mr-1.5" />
              {saving ? "Saving…" : "Save"}
            </Button>
          </div>
        )}
      </div>

      {/* Destinations */}
      <Card>
        <CardHeader>
          <CardTitle>Alert destinations</CardTitle>
        </CardHeader>
        <CardContent className={cn("space-y-2", destinations.length === 0 && "p-0")}>
          {destinations.length === 0 ? (
            <EmptyState
              title={isEditing ? "No destinations in this draft" : "No alert destinations configured"}
              description={isEditing
                ? "Use “Add destination” above, or discard the draft. Saving with none stops alert delivery."
                : "Alerts are not being delivered anywhere. Choose Edit to add a destination."}
            />
          ) : (
            destinations.map((dest, i) => {
              const isEditingThis = isEditing && editingIndex === i

              if (isEditingThis) {
                return (
                  <Card key={dest._id} className="border-primary/30 ring-1 ring-primary/10">
                    <CardContent>
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span aria-hidden="true" className={cn("size-2.5 shrink-0 rounded-sm", DEST_COLORS[dest.type] || DEST_COLORS.generic)} />
                          <span className="text-xs font-medium">{DEST_LABELS[dest.type]}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Button variant="ghost" size="sm" className="h-7" onClick={() => setEditingIndex(null)}>Done</Button>
                          <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => removeDest(i)}>
                            <Trash2 className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      </div>
                      <DestinationForm dest={dest} onChange={(d) => updateDest(i, d)} />
                    </CardContent>
                  </Card>
                )
              }

              return (
                <div key={dest._id} className="flex items-center gap-3 bg-secondary/50 px-3 py-2.5">
                  <span aria-hidden="true" className={cn("size-2.5 shrink-0 rounded-sm", DEST_COLORS[dest.type] || DEST_COLORS.generic)} />
                  <div className="flex-1 min-w-0">
                    <span className="text-xs font-medium">{DEST_LABELS[dest.type] ?? dest.type}</span>
                    {destSummary(dest) ? <span className="text-xs font-mono text-muted-foreground ml-2">{destSummary(dest)}</span> : null}
                  </div>
                  {isEditing ? (
                    <div className="flex items-center gap-1 shrink-0">
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setEditingIndex(i)}>
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => removeDest(i)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  ) : (
                    testResults?.[i] && (
                      testResults[i]!.status === "ok" ? (
                        <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
                      ) : (
                        <div className="flex items-center gap-1 shrink-0">
                          <XCircle className="h-4 w-4 text-destructive" />
                          {testResults[i]!.error ? (
                            <span className="text-xs text-destructive max-w-[150px] truncate">
                              {testResults[i]!.error}
                            </span>
                          ) : null}
                        </div>
                      )
                    )
                  )}
                </div>
              )
            })
          )}
        </CardContent>
      </Card>

      {/* Event filters */}
      <Card>
        <CardHeader>
          <CardTitle>Event filters</CardTitle>
          <p className="text-xs text-muted-foreground mt-0.5">
            {isEditing ? "Select which events trigger alerts (empty = all events)" : "Events that trigger alerts (empty = all)"}
          </p>
        </CardHeader>
        <CardContent>
          {isEditing ? (
            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
              {EVENT_TYPES.map((event) => (
                <div key={event} className="flex items-center gap-2">
                  <Checkbox
                    checked={events.includes(event)}
                    onCheckedChange={() => toggleEvent(event)}
                    id={`event-${event}`}
                  />
                  <Label htmlFor={`event-${event}`} className="cursor-pointer">{event}</Label>
                </div>
              ))}
            </div>
          ) : events.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {events.map((event) => (
                <Badge key={event} variant="outline">{event}</Badge>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">All events (no filter)</p>
          )}
        </CardContent>
      </Card>

      {testError && (
        <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/50 text-sm">
          <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
          <span className="text-destructive text-xs">{testError}</span>
        </div>
      )}
    </div>
  )
}
