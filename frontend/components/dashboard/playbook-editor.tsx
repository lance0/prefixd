"use client"

import { useCallback, useMemo, useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Pencil, Trash2, Plus, GripVertical, Save, Undo2, AlertCircle } from "lucide-react"
import { cn } from "@/lib/utils"
import type { ConfigPlaybook } from "@/lib/api"

const VECTORS = ["udp_flood", "syn_flood", "ack_flood", "icmp_flood", "unknown"] as const
const ACTIONS = ["police", "discard"] as const

interface PlaybookEditorProps {
  playbooks: ConfigPlaybook[]
  onSave: (playbooks: ConfigPlaybook[]) => Promise<void>
  saving: boolean
}

function emptyStep(): ConfigPlaybook["steps"][0] {
  return { action: "police", rate_bps: 5_000_000, ttl_seconds: 120 }
}

function emptyPlaybook(): ConfigPlaybook {
  return {
    name: "",
    match: { vector: "udp_flood" },
    steps: [emptyStep()],
  }
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
    const ctx = `Playbook "${pb.name || `#${i + 1}`}"`

    if (!pb.name.trim()) {
      errors.push(`${ctx}: name is required`)
    } else if (pb.name.length > 128) {
      errors.push(`${ctx}: name exceeds 128 characters`)
    } else if (names.has(pb.name)) {
      errors.push(`${ctx}: duplicate name`)
    }
    names.add(pb.name)

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

      if (step.ttl_seconds < 1 || step.ttl_seconds > 86400) {
        errors.push(`${sctx}: TTL must be 1-86400 seconds`)
      }
      if (step.action === "police" && (!step.rate_bps || step.rate_bps <= 0)) {
        errors.push(`${sctx}: police action requires rate > 0`)
      }
      if (step.require_confidence_at_least != null && (step.require_confidence_at_least < 0 || step.require_confidence_at_least > 1)) {
        errors.push(`${sctx}: confidence must be 0.0-1.0`)
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
  step: ConfigPlaybook["steps"][0]
  index: number
  isFirst: boolean
  onChange: (step: ConfigPlaybook["steps"][0]) => void
  onRemove: () => void
}) {
  return (
    <div className="flex flex-wrap items-start gap-3 bg-secondary/50 px-3 py-2.5 rounded-md">
      <div className="flex items-center gap-1 text-muted-foreground pt-2">
        <GripVertical className="h-3.5 w-3.5" />
        <span className="text-xs font-mono w-4">{index + 1}.</span>
      </div>

      <div className="space-y-1">
        <Label className="text-[10px] text-muted-foreground">Action</Label>
        <Select value={step.action} onValueChange={(v) => onChange({ ...step, action: v as "police" | "discard", rate_bps: v === "discard" ? undefined : (step.rate_bps ?? 5_000_000) })}>
          <SelectTrigger className="w-24 h-8 text-xs font-mono">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {ACTIONS.map((a) => (
              <SelectItem key={a} value={a}>{a}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      {step.action === "police" && (
        <div className="space-y-1">
          <Label className="text-[10px] text-muted-foreground">Rate (bps)</Label>
          <Input
            type="number"
            min={1}
            value={step.rate_bps ?? ""}
            onChange={(e) => onChange({ ...step, rate_bps: e.target.value ? Number(e.target.value) : undefined })}
            className="w-32 h-8 text-xs font-mono"
          />
        </div>
      )}

      <div className="space-y-1">
        <Label className="text-[10px] text-muted-foreground">TTL (seconds)</Label>
        <Input
          type="number"
          min={1}
          max={86400}
          value={step.ttl_seconds}
          onChange={(e) => onChange({ ...step, ttl_seconds: Number(e.target.value) || 0 })}
          className="w-24 h-8 text-xs font-mono"
        />
      </div>

      {!isFirst && (
        <>
          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Min Confidence</Label>
            <Input
              type="number"
              min={0}
              max={1}
              step={0.1}
              value={step.require_confidence_at_least ?? ""}
              onChange={(e) => onChange({ ...step, require_confidence_at_least: e.target.value ? Number(e.target.value) : undefined })}
              className="w-24 h-8 text-xs font-mono"
              placeholder="optional"
            />
          </div>

          <div className="space-y-1">
            <Label className="text-[10px] text-muted-foreground">Min Persist (s)</Label>
            <Input
              type="number"
              min={0}
              value={step.require_persistence_seconds ?? ""}
              onChange={(e) => onChange({ ...step, require_persistence_seconds: e.target.value ? Number(e.target.value) : undefined })}
              className="w-24 h-8 text-xs font-mono"
              placeholder="optional"
            />
          </div>
        </>
      )}

      <div className="pt-5">
        <Button variant="ghost" size="icon" className="h-8 w-8 text-destructive hover:text-destructive" onClick={onRemove}>
          <Trash2 className="h-3.5 w-3.5" />
        </Button>
      </div>
    </div>
  )
}

function ReadOnlyPlaybookCard({ playbook }: { playbook: ConfigPlaybook }) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center gap-2">
          <CardTitle className="text-sm font-mono">{playbook.name}</CardTitle>
          <Badge variant="outline" className="text-[10px] font-mono">{playbook.match.vector}</Badge>
          {playbook.match.require_top_ports && (
            <Badge variant="secondary" className="text-[10px] font-mono">top ports required</Badge>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-1.5">
          {playbook.steps.map((step, i) => (
            <div key={i} className="flex items-center gap-3 text-xs font-mono bg-secondary/50 px-3 py-2">
              <span className="text-muted-foreground w-4">{i + 1}.</span>
              <Badge variant={step.action === "discard" ? "destructive" : "default"} className="text-[10px] font-mono">
                {step.action}
              </Badge>
              {step.rate_bps ? <span className="text-muted-foreground">{formatRate(step.rate_bps)}</span> : null}
              <span className="text-muted-foreground">TTL {formatTtl(step.ttl_seconds)}</span>
              {step.require_confidence_at_least != null ? (
                <span className="text-muted-foreground">confidence ≥ {step.require_confidence_at_least}</span>
              ) : null}
              {step.require_persistence_seconds != null ? (
                <span className="text-muted-foreground">persist {formatTtl(step.require_persistence_seconds)}</span>
              ) : null}
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  )
}

export function PlaybookEditor({ playbooks: initialPlaybooks, onSave, saving }: PlaybookEditorProps) {
  const [draft, setDraft] = useState<ConfigPlaybook[]>(initialPlaybooks)
  const [editingIndex, setEditingIndex] = useState<number | null>(null)

  const hasChanges = useMemo(
    () => JSON.stringify(draft) !== JSON.stringify(initialPlaybooks),
    [draft, initialPlaybooks]
  )

  const errors = useMemo(() => validatePlaybooks(draft), [draft])

  const updatePlaybook = useCallback((index: number, updated: ConfigPlaybook) => {
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
    setDraft(initialPlaybooks)
    setEditingIndex(null)
  }, [initialPlaybooks])

  const handleSave = useCallback(async () => {
    await onSave(draft)
    setEditingIndex(null)
  }, [draft, onSave])

  return (
    <div className="space-y-3">
      {/* Action bar */}
      <div className="flex items-center justify-between">
        <Button variant="outline" size="sm" onClick={addPlaybook} className="text-xs font-mono">
          <Plus className="h-3.5 w-3.5 mr-1.5" />
          Add Playbook
        </Button>
        <div className="flex items-center gap-2">
          {hasChanges && (
            <Badge variant="secondary" className="text-[10px] bg-yellow-500/10 text-yellow-600 border-yellow-500/30">
              Unsaved changes
            </Badge>
          )}
          <Button variant="ghost" size="sm" onClick={handleDiscard} disabled={!hasChanges || saving} className="text-xs font-mono">
            <Undo2 className="h-3.5 w-3.5 mr-1.5" />
            Discard
          </Button>
          <Button size="sm" onClick={handleSave} disabled={!hasChanges || errors.length > 0 || saving} className="text-xs font-mono">
            <Save className="h-3.5 w-3.5 mr-1.5" />
            {saving ? "Saving..." : "Save All"}
          </Button>
        </div>
      </div>

      {/* Validation errors */}
      {errors.length > 0 && hasChanges && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="p-3">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div className="space-y-1">
                {errors.map((err, i) => (
                  <p key={i} className="text-xs text-destructive font-mono">{err}</p>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Playbook cards */}
      {draft.length === 0 ? (
        <Card>
          <CardContent className="p-4 text-sm text-muted-foreground font-mono">
            No playbooks configured. Click &quot;Add Playbook&quot; to create one.
          </CardContent>
        </Card>
      ) : (
        draft.map((playbook, index) => {
          const isEditing = editingIndex === index

          if (!isEditing) {
            return (
              <Card key={index}>
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-sm font-mono">{playbook.name || <span className="italic text-muted-foreground">unnamed</span>}</CardTitle>
                      <Badge variant="outline" className="text-[10px] font-mono">{playbook.match.vector}</Badge>
                      {playbook.match.require_top_ports && (
                        <Badge variant="secondary" className="text-[10px] font-mono">top ports required</Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-1">
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => setEditingIndex(index)}>
                        <Pencil className="h-3.5 w-3.5" />
                      </Button>
                      <Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" onClick={() => removePlaybook(index)}>
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1.5">
                    {playbook.steps.map((step, i) => (
                      <div key={i} className="flex items-center gap-3 text-xs font-mono bg-secondary/50 px-3 py-2">
                        <span className="text-muted-foreground w-4">{i + 1}.</span>
                        <Badge variant={step.action === "discard" ? "destructive" : "default"} className="text-[10px] font-mono">
                          {step.action}
                        </Badge>
                        {step.rate_bps ? <span className="text-muted-foreground">{formatRate(step.rate_bps)}</span> : null}
                        <span className="text-muted-foreground">TTL {formatTtl(step.ttl_seconds)}</span>
                        {step.require_confidence_at_least != null ? (
                          <span className="text-muted-foreground">confidence ≥ {step.require_confidence_at_least}</span>
                        ) : null}
                        {step.require_persistence_seconds != null ? (
                          <span className="text-muted-foreground">persist {formatTtl(step.require_persistence_seconds)}</span>
                        ) : null}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )
          }

          // Edit mode
          return (
            <Card key={index} className="border-primary/30 ring-1 ring-primary/10">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono text-primary font-medium">Editing</span>
                  <Button variant="ghost" size="sm" className="text-xs" onClick={() => setEditingIndex(null)}>
                    Done
                  </Button>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-2">
                  <div className="space-y-1">
                    <Label className="text-[10px] text-muted-foreground">Name</Label>
                    <Input
                      value={playbook.name}
                      onChange={(e) => updatePlaybook(index, { ...playbook, name: e.target.value })}
                      className="h-8 text-xs font-mono"
                      placeholder="e.g. udp_flood_police_first"
                    />
                  </div>
                  <div className="space-y-1">
                    <Label className="text-[10px] text-muted-foreground">Vector</Label>
                    <Select value={playbook.match.vector} onValueChange={(v) => updatePlaybook(index, { ...playbook, match: { ...playbook.match, vector: v } })}>
                      <SelectTrigger className="h-8 text-xs font-mono">
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
                      id={`ports-${index}`}
                    />
                    <Label htmlFor={`ports-${index}`} className="text-xs text-muted-foreground cursor-pointer">Require top ports</Label>
                  </div>
                </div>
              </CardHeader>
              <CardContent className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label className="text-xs text-muted-foreground font-medium">Steps</Label>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 text-[10px]"
                    onClick={() => updatePlaybook(index, { ...playbook, steps: [...playbook.steps, emptyStep()] })}
                  >
                    <Plus className="h-3 w-3 mr-1" /> Add Step
                  </Button>
                </div>
                {playbook.steps.map((step, stepIdx) => (
                  <StepEditor
                    key={stepIdx}
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

export { ReadOnlyPlaybookCard, validatePlaybooks }
