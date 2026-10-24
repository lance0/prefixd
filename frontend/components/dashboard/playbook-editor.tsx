"use client"

import { useCallback, useMemo, useState, useId } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { ActionBadge } from "@/components/dashboard/action-badge"
import { StatusPill } from "@/components/dashboard/status-pill"
import { EmptyState } from "@/components/dashboard/states"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Pencil, Trash2, Plus, GripVertical, Save, Undo2, AlertCircle } from "lucide-react"
import type { ConfigPlaybook, JsonValue, PlaybookRule, PlaybookStep } from "@/lib/api"

const VECTORS = ["udp_flood", "udp_amplification", "syn_flood", "ack_flood", "icmp_flood", "unknown"] as const
const ACTIONS = ["police", "discard", "blackhole"] as const

interface PlaybookEditorProps {
  playbooks: ConfigPlaybook[]
  onSave: (playbooks: ConfigPlaybook[]) => Promise<void>
  saving: boolean
}

type DraftStep = PlaybookStep & { _id: string }

type DraftPlaybook = Omit<ConfigPlaybook, "steps"> & { _id: string; steps: DraftStep[] }

function createId(): string {
  // randomUUID is exposed only in secure contexts; plain-HTTP dashboards fall back.
  if (typeof crypto !== "undefined" && "randomUUID" in crypto) {
    return crypto.randomUUID()
  }

  return `pb-${Math.random().toString(36).slice(2, 10)}`
}

function emptyStep(): DraftStep {
  return { _id: createId(), action: "police", rate_bps: 5_000_000, ttl_seconds: 120 }
}

function emptyPlaybook(): DraftPlaybook {
  return {
    _id: createId(),
    name: "",
    match: { vector: "udp_flood" },
    steps: [emptyStep()],
  }
}

// Keep every field the API sent (for example `correlation`), so an untouched draft
// equals the loaded playbooks and saving never drops settings this form does not edit.
function toDraft(playbooks: ConfigPlaybook[]): DraftPlaybook[] {
  return playbooks.map((playbook) => ({
    ...playbook,
    _id: createId(),
    steps: playbook.steps.map((step) => ({ ...step, _id: createId() })),
  }))
}

// null and an absent key mean the same thing to the API; compare them as equal.
function samePlaybooks(a: ConfigPlaybook[], b: ConfigPlaybook[]): boolean {
  return JSON.stringify(a, (_key, value) => value ?? undefined) === JSON.stringify(b, (_key, value) => value ?? undefined)
}

function toApiPlaybooks(playbooks: DraftPlaybook[]): ConfigPlaybook[] {
  return playbooks.map(({ _id: _playbookId, steps, ...rest }) => ({
    ...rest,
    steps: steps.map(({ _id: _stepId, ...step }) => step),
  }))
}

function validatePlaybooks(playbooks: ConfigPlaybook[]): string[] {
  const errors: string[] = []
  const names = new Set<string>()

  if (playbooks.length === 0) {
    errors.push("At least one playbook is required")

    return errors
  }

  for (let i = 0; i < playbooks.length; i++) {
    const pb = playbooks[i]
    // A YAML draft may carry any scalar here; the controller refuses a non-string name.
    const name = pb.name == null ? "" : String(pb.name)
    const ctx = `Playbook "${name || `#${i + 1}`}"`

    if (!name.trim()) {
      errors.push(`${ctx}: name is required`)
    } else if (new TextEncoder().encode(name).length > 128) {
      errors.push(`${ctx}: name exceeds 128 bytes`)
    } else if (names.has(name)) {
      errors.push(`${ctx}: duplicate name`)
    }

    names.add(name)

    if (!VECTORS.some((vector) => vector === pb.match.vector)) {
      errors.push(`${ctx}: vector must be one of ${VECTORS.join(", ")}`)
    }

    if (pb.steps.length === 0) {
      errors.push(`${ctx}: at least one step is required`)
      continue
    }

    const first = pb.steps[0]

    if (first.require_confidence_at_least != null || first.require_persistence_seconds != null) {
      errors.push(`${ctx}: first step must not have escalation requirements`)
    }

    for (let j = 0; j < pb.steps.length; j++) {
      const step = pb.steps[j]
      const sctx = `${ctx} step ${j + 1}`
      const hasRules = Array.isArray(step.rules) && step.rules.length > 0

      // Rule details (ports, fragment, length, opt-ins) are left to the controller.
      if (hasRules) {
        if (step.action != null) errors.push(`${sctx}: a step has an action or rules, not both`)

        if (pb.match.vector !== "udp_amplification") errors.push(`${sctx}: rules are valid only in udp_amplification playbooks`)
      } else if (step.action == null) {
        errors.push(`${sctx}: a step needs an action or rules`)
      } else if (!ACTIONS.some((action) => action === step.action)) {
        errors.push(`${sctx}: action must be one of ${ACTIONS.join(", ")}`)
      } else if (step.action === "blackhole") {
        if (pb.match.vector === "udp_amplification") errors.push(`${sctx}: a blackhole step is not valid in udp_amplification playbooks`)

        if (step.rate_bps != null) errors.push(`${sctx}: a blackhole step takes no rate`)
      }

      if (!Number.isFinite(step.ttl_seconds) || step.ttl_seconds < 1 || step.ttl_seconds > 86400) {
        errors.push(`${sctx}: TTL must be 1-86400 seconds`)
      }

      if (
        step.action === "police" &&
        (!Number.isFinite(step.rate_bps ?? NaN) || !step.rate_bps || step.rate_bps <= 0)
      ) {
        errors.push(`${sctx}: police action requires rate > 0`)
      }

      if (
        step.require_confidence_at_least != null &&
        (!Number.isFinite(step.require_confidence_at_least) ||
          step.require_confidence_at_least < 0 ||
          step.require_confidence_at_least > 1)
      ) {
        errors.push(`${sctx}: confidence must be 0.0-1.0`)
      }

      if (
        step.require_persistence_seconds != null &&
        (!Number.isFinite(step.require_persistence_seconds) || step.require_persistence_seconds < 0)
      ) {
        errors.push(`${sctx}: persistence must be >= 0 seconds`)
      }
    }
  }

  return errors
}

function formatRate(bps: number): string {
  if (bps >= 1_000_000_000) return `${(bps / 1_000_000_000).toFixed(1)} Gbps`

  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(0)} Mbps`

  if (bps >= 1_000) return `${(bps / 1_000).toFixed(0)} Kbps`

  return `${bps} bps`
}

/** One rule of a `rules` step, for example "UDP src from event → discard". */
function describeRule(rule: PlaybookRule): string {
  const match = rule.match ?? {}
  const parts = ["UDP"]

  if (match.src_ports === "from_event") parts.push("src from event")
  else if (Array.isArray(match.src_ports)) parts.push(`src ${match.src_ports.join(", ")}`)

  if (match.fragment === "non_first") parts.push("non-first fragments")

  if (match.packet_length) parts.push(`length ${match.packet_length.min}–${match.packet_length.max} B`)

  const action = rule.action === "police" && rule.rate_bps ? `police ${formatRate(rule.rate_bps)}` : rule.action

  return `${parts.join(" ")} → ${action}`
}

/** Read-only `rules` list: the form keeps them as sent, and the YAML view edits them. */
function RulesSummary({ rules }: { rules: PlaybookRule[] }) {
  return (
    <ul className="space-y-0.5">
      {rules.map((rule, index) => (
        <li key={index} className="break-words font-mono">{describeRule(rule)}</li>
      ))}
    </ul>
  )
}

/** One step in the card views: its action and rate, or its rules. */
function StepSummary({ step, index }: { step: PlaybookStep; index: number }) {
  return (
    <div className="flex flex-wrap items-start gap-x-3 gap-y-1 rounded-sm bg-muted/40 px-3 py-2 text-xs">
      <span className="text-muted-foreground w-4">{index + 1}.</span>
      {step.rules?.length ? (
        <div className="min-w-0 flex-1 basis-56">
          <span className="text-muted-foreground">{step.rules.length} rules, each its own mitigation</span>
          <RulesSummary rules={step.rules} />
        </div>
      ) : (
        <>
          <ActionBadge actionType={step.action ?? "unknown"} />
          {step.rate_bps ? <span className="text-muted-foreground">{formatRate(step.rate_bps)}</span> : null}
        </>
      )}
      <span className="text-muted-foreground">TTL {formatTtl(step.ttl_seconds)}</span>
      {step.require_confidence_at_least != null ? (
        <span className="text-muted-foreground">confidence ≥ {step.require_confidence_at_least}</span>
      ) : null}
      {step.require_persistence_seconds != null ? (
        <span className="text-muted-foreground">persist {formatTtl(step.require_persistence_seconds)}</span>
      ) : null}
    </div>
  )
}

/**
 * The controller's reasons from a failed save, verbatim: the `errors` list a playbook PUT
 * returns, an `error` message, or the raw failure text.
 */
export function serverErrors(message: string): string[] {
  const body = message.replace(/^API error \d+: /, "")
  let parsed: JsonValue

  try {
    // SAFETY: JSON.parse yields only JSON values; each field is checked before use.
    parsed = JSON.parse(body) as JsonValue
  } catch {
    return [message]
  }

  if (parsed instanceof Object && !Array.isArray(parsed)) {
    const list = parsed.errors

    if (Array.isArray(list) && list.length > 0) return list.map(String)

    if (parsed.error != null) return [String(parsed.error)]
  }

  return [message]
}

function formatTtl(seconds: number): string {
  if (seconds >= 3600) return `${(seconds / 3600).toFixed(1)}h`

  if (seconds >= 60) return `${(seconds / 60).toFixed(0)}m`

  return `${seconds}s`
}

function StepEditor({
  step,
  index,
  isFirst,
  onChange,
  onRemove,
}: {
  step: DraftStep
  index: number
  isFirst: boolean
  onChange: (step: DraftStep) => void
  onRemove: () => void
}) {
  const id = useId()

  return (
    <div className="flex flex-wrap items-start gap-3 bg-secondary/50 px-3 py-2.5 rounded-md">
      <div className="flex items-center gap-1 text-muted-foreground pt-2">
        <GripVertical className="h-3.5 w-3.5" />
        <span className="text-xs w-4">{index + 1}.</span>
      </div>

      {step.rules?.length ? (
        <div className="min-w-0 flex-1 basis-full space-y-1 text-xs sm:basis-64">
          <span className="text-muted-foreground">Rules ({step.rules.length}, each its own mitigation)</span>
          <RulesSummary rules={step.rules} />
          <p className="text-muted-foreground">Edit rules in the YAML view. This form keeps them unchanged.</p>
        </div>
      ) : (
        <div className="space-y-1">
          <Label htmlFor={`${id}-action`} className="text-muted-foreground">Action</Label>
          <Select
            value={step.action ?? undefined}
            onValueChange={(v) => {
              if (v === "police") onChange({ ...step, action: v, rate_bps: step.rate_bps ?? 5_000_000 })

              if (v === "discard" || v === "blackhole") onChange({ ...step, action: v, rate_bps: undefined })
            }}
          >
            <SelectTrigger id={`${id}-action`} className="w-28 h-8" aria-label={`Step ${index + 1} action`}>
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ACTIONS.map((a) => (
                <SelectItem key={a} value={a}>{a}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      )}

      {step.action === "police" && (
        <div className="space-y-1">
          <Label htmlFor={`${id}-rate`} className="text-muted-foreground">Rate (bps)</Label>
          <Input
            id={`${id}-rate`}
            type="number"
            min={1}
            value={step.rate_bps ?? ""}
            onChange={(e) => onChange({ ...step, rate_bps: e.target.value ? Number(e.target.value) : undefined })}
            className="w-32 h-8 text-xs"
          />
        </div>
      )}

      <div className="space-y-1">
        <Label htmlFor={`${id}-ttl`} className="text-muted-foreground">TTL (seconds)</Label>
        <Input
          id={`${id}-ttl`}
          type="number"
          min={1}
          max={86400}
          value={step.ttl_seconds}
          onChange={(e) => onChange({ ...step, ttl_seconds: Number(e.target.value) || 0 })}
          aria-label={`Step ${index + 1} TTL (seconds)`}
          className="w-24 h-8 text-xs"
        />
      </div>

      {!isFirst && (
        <>
          <div className="space-y-1">
            <Label htmlFor={`${id}-confidence`} className="text-muted-foreground">Min confidence</Label>
            <Input
              id={`${id}-confidence`}
              type="number"
              min={0}
              max={1}
              step={0.1}
              value={step.require_confidence_at_least ?? ""}
              onChange={(e) => onChange({ ...step, require_confidence_at_least: e.target.value ? Number(e.target.value) : undefined })}
              className="w-24 h-8 text-xs"
              placeholder="optional"
            />
          </div>

          <div className="space-y-1">
            <Label htmlFor={`${id}-persistence`} className="text-muted-foreground">Min persist (s)</Label>
            <Input
              id={`${id}-persistence`}
              type="number"
              min={0}
              value={step.require_persistence_seconds ?? ""}
              onChange={(e) => onChange({ ...step, require_persistence_seconds: e.target.value ? Number(e.target.value) : undefined })}
              className="w-24 h-8 text-xs"
              placeholder="optional"
            />
          </div>
        </>
      )}

      <div className="pt-5">
        <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={onRemove} aria-label={`Remove step ${index + 1}`}>
          <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
        </Button>
      </div>
    </div>
  )
}

function ReadOnlyPlaybookCard({ playbook }: { playbook: ConfigPlaybook }) {
  return (
    <Card>
      <CardHeader>
        <div className="flex items-center gap-2">
          <CardTitle>{playbook.name}</CardTitle>
          <Badge variant="outline">{playbook.match.vector}</Badge>
          {playbook.match.require_top_ports && (
            <Badge variant="secondary">top ports required</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-1.5">
          {playbook.steps.map((step, i) => (
            <StepSummary key={i} step={step} index={i} />
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function PlaybookEditor({ playbooks: initialPlaybooks, onSave, saving }: PlaybookEditorProps) {
  const id = useId()
  const [draft, setDraft] = useState<DraftPlaybook[]>(() => toDraft(initialPlaybooks))
  const [editingIndex, setEditingIndex] = useState<number | null>(null)

  const apiDraft = useMemo(() => toApiPlaybooks(draft), [draft])
  const hasChanges = useMemo(() => !samePlaybooks(apiDraft, initialPlaybooks), [apiDraft, initialPlaybooks])

  const errors = useMemo(() => validatePlaybooks(apiDraft), [apiDraft])

  const updatePlaybook = useCallback((index: number, updated: DraftPlaybook) => {
    setDraft((prev) => prev.map((p, i) => (i === index ? updated : p)))
  }, [])

  const removePlaybook = useCallback((index: number) => {
    setDraft((prev) => prev.filter((_, i) => i !== index))
    setEditingIndex(null)
  }, [])

  const addPlaybook = useCallback(() => {
    setDraft((prev) => [...prev, emptyPlaybook()])
    setEditingIndex(draft.length)
  }, [draft.length])

  const handleDiscard = useCallback(() => {
    setDraft(toDraft(initialPlaybooks))
    setEditingIndex(null)
  }, [initialPlaybooks])

  const [saveErrors, setSaveErrors] = useState<string[]>([])

  const handleSave = useCallback(async () => {
    setSaveErrors([])

    try {
      await onSave(apiDraft)
      setEditingIndex(null)
    } catch (e) {
      setSaveErrors(serverErrors(e instanceof Error ? e.message : String(e)))
    }
  }, [apiDraft, onSave])

  return (
    <div className="space-y-3">
      {/* Action bar */}
      <div className="flex items-center justify-between">
        <Button variant="outline" size="sm" onClick={addPlaybook}>
          <Plus className="h-3.5 w-3.5 mr-1.5" />
          Add playbook
        </Button>
        <div className="flex items-center gap-2">
          {hasChanges && (
            <StatusPill tone="warning">Unsaved changes</StatusPill>
          )}
          <Button variant="ghost" size="sm" onClick={handleDiscard} disabled={!hasChanges || saving}>
            <Undo2 className="h-3.5 w-3.5 mr-1.5" />
            Discard
          </Button>
          <Button size="sm" onClick={handleSave} disabled={!hasChanges || errors.length > 0 || saving} className="text-xs">
            <Save className="h-3.5 w-3.5 mr-1.5" />
            {saving ? "Saving…" : "Save all"}
          </Button>
        </div>
      </div>

      <SaveErrors errors={saveErrors} />

      {/* Validation errors */}
      {errors.length > 0 && hasChanges && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent>
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div className="space-y-1">
                {errors.map((err, i) => (
                  <p key={`${err}-${i}`} className="text-xs text-destructive">{err}</p>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Playbook cards */}
      {draft.length === 0 ? (
        <Card>
          <EmptyState
            title="No playbooks configured"
            description="Without playbooks, events are recorded but no mitigation is proposed. Choose “Add playbook” to create one."
          />
        </Card>
      ) : (
        draft.map((playbook, index) => {
          const isEditing = editingIndex === index

          if (!isEditing) {
            return (
              <Card key={playbook._id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CardTitle>{playbook.name || <span className="italic text-muted-foreground">unnamed</span>}</CardTitle>
                      <Badge variant="outline">{playbook.match.vector}</Badge>
                      {playbook.match.require_top_ports && (
                        <Badge variant="secondary">top ports required</Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setEditingIndex(index)} aria-label={`Edit playbook ${playbook.name || index + 1}`}>
                        <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => removePlaybook(index)} aria-label={`Remove playbook ${playbook.name || index + 1}`}>
                        <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1.5">
                    {playbook.steps.map((step, i) => (
                      <StepSummary key={step._id} step={step} index={i} />
                    ))}
                  </div>
                </CardContent>
              </Card>
            )
          }

          // Edit mode
          return (
            <Card key={playbook._id} className="border-primary/30 ring-1 ring-primary/10">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-muted-foreground">Editing</span>
                  <Button variant="ghost" size="sm" onClick={() => setEditingIndex(null)}>
                    Done
                  </Button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-2">
                  <div className="space-y-1">
                    <Label htmlFor={`${id}-${playbook._id}-name`} className="text-muted-foreground">Name</Label>
                    <Input
                      id={`${id}-${playbook._id}-name`}
                      value={playbook.name}
                      onChange={(e) => updatePlaybook(index, { ...playbook, name: e.target.value })}
                      className="h-8 text-xs font-mono"
                      placeholder="e.g. udp_flood_police_first"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label htmlFor={`${id}-${playbook._id}-vector`} className="text-muted-foreground">Vector</Label>
                    <Select value={playbook.match.vector} onValueChange={(v) => updatePlaybook(index, { ...playbook, match: { ...playbook.match, vector: v } })}>
                      <SelectTrigger id={`${id}-${playbook._id}-vector`} className="h-8">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {VECTORS.map((v) => (
                          <SelectItem key={v} value={v}>{v}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>
                  <div className="flex items-end gap-2 pb-0.5">
                    <Checkbox
                      checked={playbook.match.require_top_ports ?? false}
                      onCheckedChange={(checked) => updatePlaybook(index, { ...playbook, match: { ...playbook.match, require_top_ports: checked === true } })}
                      id={`ports-${playbook._id}`}
                    />
                    <Label htmlFor={`ports-${playbook._id}`} className="text-muted-foreground cursor-pointer">Require top ports</Label>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-muted-foreground font-medium">Steps</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7"
                    onClick={() => updatePlaybook(index, { ...playbook, steps: [...playbook.steps, emptyStep()] })}
                  >
                    <Plus className="h-3 w-3 mr-1" /> Add step
                  </Button>
                </div>
                {playbook.steps.map((step, stepIdx) => (
                  <StepEditor
                    key={step._id}
                    step={step}
                    index={stepIdx}
                    isFirst={stepIdx === 0}
                    onChange={(updated) => {
                      const newSteps = playbook.steps.map((s, si) => (si === stepIdx ? updated : s))
                      updatePlaybook(index, { ...playbook, steps: newSteps })
                    }}
                    onRemove={() => {
                      if (playbook.steps.length <= 1) return
                      const newSteps = playbook.steps.filter((_, si) => si !== stepIdx)
                      updatePlaybook(index, { ...playbook, steps: newSteps })
                    }}
                  />
                ))}
              </CardContent>
            </Card>
          )
        })
      )}
    </div>
  )
}

/** The controller's refusal of the last save, shown as sent. */
export function SaveErrors({ errors }: { errors: string[] }) {
  if (errors.length === 0) return null

  return (
    <Card role="alert" className="border-destructive/50 bg-destructive/5">
      <CardContent>
        <div className="flex items-start gap-2">
          <AlertCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" aria-hidden="true" />
          <div className="min-w-0 space-y-1">
            <p className="text-xs font-medium text-destructive">The controller refused the save:</p>
            {errors.map((err, i) => (
              <p key={`${err}-${i}`} className="break-words font-mono text-xs text-destructive">{err}</p>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export { ReadOnlyPlaybookCard, validatePlaybooks }
