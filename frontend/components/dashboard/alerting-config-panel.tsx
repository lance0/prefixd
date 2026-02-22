"use client"

import { useCallback, useMemo, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Loader2, Bell, Send, CheckCircle2, XCircle, AlertCircle, Plus, Trash2, Pencil, Save, Undo2 } from "lucide-react"
import { useAlertingConfig } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { testAlerting, updateAlertingConfig, type AlertingDestination, type AlertingTestResult } from "@/lib/api"
import { toast } from "sonner"
import { cn } from "@/lib/utils"

const DEST_TYPES = ["slack", "discord", "teams", "telegram", "pagerduty", "opsgenie", "generic"] as const
type DestType = (typeof DEST_TYPES)[number]

const EVENT_TYPES = [
  "mitigation.created",
  "mitigation.escalated",
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
  generic: "Generic Webhook",
}

const DEST_COLORS: Record<string, string> = {
  slack: "bg-[#4A154B] text-white",
  discord: "bg-[#5865F2] text-white",
  teams: "bg-[#6264A7] text-white",
  telegram: "bg-[#0088CC] text-white",
  pagerduty: "bg-[#06AC38] text-white",
  opsgenie: "bg-[#2684FF] text-white",
  generic: "bg-secondary text-foreground",
}

const DEST_ICONS: Record<string, string> = {
  slack: "#",
  discord: "D",
  teams: "T",
  telegram: "TG",
  pagerduty: "PD",
  opsgenie: "OG",
  generic: "W",
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

function isSecretField(field: string): boolean {
  return ["webhook_url", "bot_token", "routing_key", "api_key", "secret"].includes(field)
}

function DestinationForm({ dest, onChange }: { dest: DraftDestination; onChange: (d: DraftDestination) => void }) {
  const update = (field: string, value: string) => onChange({ ...dest, [field]: value })

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-2">
      {dest.type === "slack" && (
        <>
          <div className="space-y-1 sm:col-span-2">
            <Label className="text-[10px] text-muted-foreground">Webhook URL</Label>
            <Input
              type={dest.webhook_url === "***" ? "password" : "text"}
              value={dest.webhook_url ?? ""}
              onChange={(e) => update("webhook_url", e.target.value)}
              placeholder={dest.webhook_url === "***" ? "Leave as *** to keep existing" : "https://hooks.slack.com/services/..."}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Channel (optional)</Label>
            <Input value={dest.channel ?? ""} onChange={(e) => update("channel", e.target.value)} placeholder="#ddos-alerts" className="h-8 text-xs font-mono" />
          </div>
        </>
      )}
      {dest.type === "discord" && (
        <div className="space-y-1 sm:col-span-2">
          <Label className="text-[10px] text-muted-foreground">Webhook URL</Label>
          <Input
            type={dest.webhook_url === "***" ? "password" : "text"}
            value={dest.webhook_url ?? ""}
            onChange={(e) => update("webhook_url", e.target.value)}
            placeholder="https://discord.com/api/webhooks/..."
            className="h-8 text-xs font-mono"
          />
        </div>
      )}
      {dest.type === "teams" && (
        <div className="space-y-1 sm:col-span-2">
          <Label className="text-[10px] text-muted-foreground">Webhook URL</Label>
          <Input
            type={dest.webhook_url === "***" ? "password" : "text"}
            value={dest.webhook_url ?? ""}
            onChange={(e) => update("webhook_url", e.target.value)}
            placeholder="https://prod-XX.westus.logic.azure.com/..."
            className="h-8 text-xs font-mono"
          />
        </div>
      )}
      {dest.type === "telegram" && (
        <>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Bot Token</Label>
            <Input
              type={dest.bot_token === "***" ? "password" : "text"}
              value={dest.bot_token ?? ""}
              onChange={(e) => update("bot_token", e.target.value)}
              placeholder={dest.bot_token === "***" ? "Leave as *** to keep existing" : "123456:ABC-DEF..."}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Chat ID</Label>
            <Input value={dest.chat_id ?? ""} onChange={(e) => update("chat_id", e.target.value)} placeholder="-100123456789" className="h-8 text-xs font-mono" />
          </div>
        </>
      )}
      {dest.type === "pagerduty" && (
        <>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Routing Key</Label>
            <Input
              type={dest.routing_key === "***" ? "password" : "text"}
              value={dest.routing_key ?? ""}
              onChange={(e) => update("routing_key", e.target.value)}
              placeholder={dest.routing_key === "***" ? "Leave as *** to keep existing" : "routing-key"}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Events URL</Label>
            <Input value={dest.events_url ?? ""} onChange={(e) => update("events_url", e.target.value)} className="h-8 text-xs font-mono" />
          </div>
        </>
      )}
      {dest.type === "opsgenie" && (
        <>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">API Key</Label>
            <Input
              type={dest.api_key === "***" ? "password" : "text"}
              value={dest.api_key ?? ""}
              onChange={(e) => update("api_key", e.target.value)}
              placeholder={dest.api_key === "***" ? "Leave as *** to keep existing" : "api-key"}
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Region</Label>
            <Select value={dest.region ?? "us"} onValueChange={(v) => update("region", v)}>
              <SelectTrigger className="h-8 text-xs font-mono">
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
            <Label className="text-[10px] text-muted-foreground">URL</Label>
            <Input value={dest.url ?? ""} onChange={(e) => update("url", e.target.value)} placeholder="https://example.com/webhook" className="h-8 text-xs font-mono" />
          </div>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">HMAC Secret (optional)</Label>
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
    </div>
  )
}

function ReadOnlyDestCard({ dest, testResult }: { dest: AlertingDestination; testResult?: AlertingTestResult }) {
  const summary = destSummary(dest)
  return (
    <div className="flex items-center gap-3 bg-secondary/50 px-3 py-2.5">
      <span className={cn("shrink-0 flex items-center justify-center h-6 w-8 text-[10px] font-bold font-mono", DEST_COLORS[dest.type] || DEST_COLORS.generic)}>
        {DEST_ICONS[dest.type] || "?"}
      </span>
      <div className="flex-1 min-w-0">
        <span className="text-xs font-mono font-medium">{DEST_LABELS[dest.type as DestType] ?? dest.type}</span>
        {summary ? <span className="text-xs font-mono text-muted-foreground ml-2">{summary}</span> : null}
      </div>
      {testResult && (
        testResult.status === "ok" ? (
          <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
        ) : (
          <div className="flex items-center gap-1 shrink-0">
            <XCircle className="h-4 w-4 text-destructive" />
            {testResult.error ? <span className="text-[10px] text-destructive font-mono max-w-[150px] truncate">{testResult.error}</span> : null}
          </div>
        )
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
    setDraft((prev) => [...(prev ?? []), emptyDest(type)])
    setEditingIndex((prev ?? []).length)
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

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4 flex items-center gap-2 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm font-mono">Loading alerting config...</span>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-4 text-sm text-destructive font-mono">
          Failed to load alerting config: {error.message}
        </CardContent>
      </Card>
    )
  }

  if (!data) return null

  // Read-only mode
  if (!canEditAlerting) {
    return (
      <div className="space-y-3">
        <Card>
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-mono">Alert Destinations</CardTitle>
              {canReloadConfig ? (
                <Button variant="outline" size="sm" onClick={handleTest} disabled={testing} className="font-mono text-xs">
                  {testing ? <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> : <Send className="h-3 w-3 mr-1.5" />}
                  Send Test Alert
                </Button>
              ) : null}
            </div>
          </CardHeader>
          <CardContent className="space-y-2">
            {data.destinations.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-6 text-center">
                <Bell className="h-8 w-8 text-muted-foreground mb-2" />
                <p className="text-sm text-muted-foreground font-mono">No alert destinations configured</p>
              </div>
            ) : (
              data.destinations.map((dest, i) => (
                <ReadOnlyDestCard key={i} dest={dest} testResult={testResults?.find((r) => r.destination === dest.type)} />
              ))
            )}
          </CardContent>
        </Card>
        {data.events.length > 0 && (
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-mono">Event Filters</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-1.5">
                {data.events.map((event) => (
                  <Badge key={event} variant="outline" className="text-[10px] font-mono">{event}</Badge>
                ))}
              </div>
            </CardContent>
          </Card>
        )}
        {testError && (
          <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/50 text-sm">
            <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
            <span className="text-destructive font-mono text-xs">{testError}</span>
          </div>
        )}
      </div>
    )
  }

  // Editable mode
  const destinations = isEditing ? draft! : data.destinations.map(toDraft)
  const events = isEditing ? draftEvents! : data.events

  return (
    <div className="space-y-3">
      {/* Action bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {!isEditing ? (
            <Button variant="outline" size="sm" onClick={initDraft} className="text-xs font-mono">
              <Pencil className="h-3.5 w-3.5 mr-1.5" />
              Edit
            </Button>
          ) : (
            <>
              {addingType === null ? (
                <Select onValueChange={(v) => addDest(v as DestType)}>
                  <SelectTrigger className="w-44 h-8 text-xs font-mono">
                    <Plus className="h-3.5 w-3.5 mr-1" />
                    <span>Add Destination</span>
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
          <Button variant="outline" size="sm" onClick={handleTest} disabled={testing} className="font-mono text-xs">
            {testing ? <Loader2 className="h-3 w-3 mr-1.5 animate-spin" /> : <Send className="h-3 w-3 mr-1.5" />}
            Test
          </Button>
        </div>
        {isEditing && (
          <div className="flex items-center gap-2">
            {hasChanges && (
              <Badge variant="secondary" className="text-[10px] bg-yellow-500/10 text-yellow-600 border-yellow-500/30">
                Unsaved changes
              </Badge>
            )}
            <Button variant="ghost" size="sm" onClick={discardDraft} disabled={saving} className="text-xs font-mono">
              <Undo2 className="h-3.5 w-3.5 mr-1.5" />
              Discard
            </Button>
            <Button size="sm" onClick={handleSave} disabled={!hasChanges || saving} className="text-xs font-mono">
              <Save className="h-3.5 w-3.5 mr-1.5" />
              {saving ? "Saving..." : "Save"}
            </Button>
          </div>
        )}
      </div>

      {/* Destinations */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-mono">Alert Destinations</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {destinations.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-6 text-center">
              <Bell className="h-8 w-8 text-muted-foreground mb-2" />
              <p className="text-sm text-muted-foreground font-mono">
                {isEditing ? "No destinations. Use \"Add Destination\" above." : "No alert destinations configured"}
              </p>
              {!isEditing && (
                <p className="text-xs text-muted-foreground mt-1">Click Edit to add destinations</p>
              )}
            </div>
          ) : (
            destinations.map((dest, i) => {
              const isEditingThis = isEditing && editingIndex === i

              if (isEditingThis) {
                return (
                  <Card key={dest._id} className="border-primary/30 ring-1 ring-primary/10">
                    <CardContent className="p-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className={cn("shrink-0 flex items-center justify-center h-6 w-8 text-[10px] font-bold font-mono", DEST_COLORS[dest.type])}>
                            {DEST_ICONS[dest.type]}
                          </span>
                          <span className="text-xs font-mono font-medium">{DEST_LABELS[dest.type as DestType]}</span>
                        </div>
                        <div className="flex items-center gap-1">
                          <Button variant="ghost" size="sm" className="h-7 text-xs" onClick={() => setEditingIndex(null)}>Done</Button>
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
                  <span className={cn("shrink-0 flex items-center justify-center h-6 w-8 text-[10px] font-bold font-mono", DEST_COLORS[dest.type] || DEST_COLORS.generic)}>
                    {DEST_ICONS[dest.type] || "?"}
                  </span>
                  <div className="flex-1 min-w-0">
                    <span className="text-xs font-mono font-medium">{DEST_LABELS[dest.type as DestType] ?? dest.type}</span>
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
                    testResults?.find((r) => r.destination === dest.type) && (
                      testResults.find((r) => r.destination === dest.type)!.status === "ok" ? (
                        <CheckCircle2 className="h-4 w-4 text-success shrink-0" />
                      ) : (
                        <div className="flex items-center gap-1 shrink-0">
                          <XCircle className="h-4 w-4 text-destructive" />
                          {testResults.find((r) => r.destination === dest.type)!.error ? (
                            <span className="text-[10px] text-destructive font-mono max-w-[150px] truncate">
                              {testResults.find((r) => r.destination === dest.type)!.error}
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
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-mono">Event Filters</CardTitle>
          <p className="text-[10px] text-muted-foreground font-mono mt-0.5">
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
                  <Label htmlFor={`event-${event}`} className="text-xs font-mono cursor-pointer">{event}</Label>
                </div>
              ))}
            </div>
          ) : events.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {events.map((event) => (
                <Badge key={event} variant="outline" className="text-[10px] font-mono">{event}</Badge>
              ))}
            </div>
          ) : (
            <p className="text-xs text-muted-foreground font-mono">All events (no filter)</p>
          )}
        </CardContent>
      </Card>

      {testError && (
        <div className="flex items-center gap-2 p-3 bg-destructive/10 border border-destructive/50 text-sm">
          <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
          <span className="text-destructive font-mono text-xs">{testError}</span>
        </div>
      )}
    </div>
  )
}
