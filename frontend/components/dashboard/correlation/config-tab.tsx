"use client"

import { useState, useCallback, useEffect } from "react"
import { toast } from "sonner"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useCorrelationConfig, useConfigPlaybooks } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { updateCorrelationConfig } from "@/lib/api"
import type {
  CorrelationConfig,
  MatchDimension,
  SourceConfig,
  SourceMode,
} from "@/lib/api"
import { Settings, Plus, Pencil, Trash2, Save, Loader2, AlertCircle, Link as LinkIcon } from "lucide-react"
import Link from "next/link"

import { WebhookAdaptersEditor } from "./webhook-adapters"

export function ConfigTab() {
  return (
    <div className="space-y-6">
      <CorrelationSettingsEditor />
      <SignalSourceCards />
      <WebhookAdaptersEditor />
      <PlaybookOverrides />
    </div>
  )
}

// ── Correlation Settings Editor ────────────────────────────

function CorrelationSettingsEditor() {
  const { data: config, error, isLoading, mutate } = useCorrelationConfig()
  const { isAdmin } = usePermissions()
  const [saving, setSaving] = useState(false)
  const [formState, setFormState] = useState<CorrelationConfig | null>(null)
  const [validationErrors, setValidationErrors] = useState<string[]>([])

  // Initialize form state from fetched config
  const form = formState ?? config

  const handleFieldChange = (field: keyof CorrelationConfig, value: unknown) => {
    if (!form) return
    const updated = { ...form, [field]: value }
    setFormState(updated)
    setValidationErrors(validateConfig(updated))
  }

  const handleSave = useCallback(async () => {
    if (!formState) return
    const errors = validateConfig(formState)
    if (errors.length > 0) {
      setValidationErrors(errors)
      return
    }

    setSaving(true)
    try {
      await updateCorrelationConfig(formState)
      await mutate()
      setFormState(null)
      toast.success("Correlation config saved")
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save config")
    } finally {
      setSaving(false)
    }
  }, [formState, mutate])

  if (isLoading) {
    return (
      <Card>
        <CardContent className="p-4">
          <Skeleton className="h-4 w-32 mb-4" />
          <Skeleton className="h-8 w-full mb-3" />
          <Skeleton className="h-8 w-full mb-3" />
          <Skeleton className="h-8 w-full" />
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="p-4 flex items-center gap-2 text-destructive">
          <AlertCircle className="h-4 w-4" />
          <span className="text-sm font-mono">Failed to load correlation config</span>
        </CardContent>
      </Card>
    )
  }

  if (!form) return null

  const isDirty = formState != null
  const readOnly = !isAdmin

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xs font-mono text-muted-foreground uppercase tracking-wider flex items-center gap-1.5">
            <Settings className="h-3 w-3" />
            Correlation Settings
          </CardTitle>
          <Badge variant={form.enabled ? "default" : "secondary"} className="text-[10px]">
            {form.enabled ? "Enabled" : "Disabled"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div className="space-y-1.5">
            <Label htmlFor="corr-window" className="text-xs font-mono">Window (seconds)</Label>
            <Input
              id="corr-window"
              type="number"
              value={form.window_seconds}
              onChange={(e) => handleFieldChange("window_seconds", parseInt(e.target.value) || 0)}
              disabled={readOnly}
              className="h-8 text-xs font-mono"
              min={1}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="corr-min-sources" className="text-xs font-mono">Min Sources</Label>
            <Input
              id="corr-min-sources"
              type="number"
              value={form.min_sources}
              onChange={(e) => handleFieldChange("min_sources", parseInt(e.target.value) || 0)}
              disabled={readOnly}
              className="h-8 text-xs font-mono"
              min={1}
            />
          </div>
          <div className="space-y-1.5">
            <Label htmlFor="corr-threshold" className="text-xs font-mono">Confidence Threshold</Label>
            <Input
              id="corr-threshold"
              type="number"
              value={form.confidence_threshold}
              onChange={(e) => handleFieldChange("confidence_threshold", parseFloat(e.target.value) || 0)}
              disabled={readOnly}
              className="h-8 text-xs font-mono"
              min={0}
              max={1}
              step={0.1}
            />
          </div>
        </div>

        {validationErrors.length > 0 && (
          <div className="bg-destructive/10 border border-destructive/20 rounded-md p-3">
            {validationErrors.map((err, i) => (
              <p key={i} className="text-xs font-mono text-destructive">{err}</p>
            ))}
          </div>
        )}

        {isAdmin && isDirty && (
          <div className="flex justify-end gap-2">
            <Button
              variant="ghost"
              size="sm"
              onClick={() => { setFormState(null); setValidationErrors([]) }}
              className="text-xs font-mono"
            >
              Cancel
            </Button>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={saving || validationErrors.length > 0}
              className="text-xs font-mono"
            >
              {saving ? (
                <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />
              ) : (
                <Save className="h-3 w-3 mr-1.5" />
              )}
              Save
            </Button>
          </div>
        )}

        {readOnly && (
          <p className="text-[10px] font-mono text-muted-foreground">
            Admin access required to edit settings
          </p>
        )}
      </CardContent>
    </Card>
  )
}

// ── Signal Source CRUD Cards ────────────────────────────

function SignalSourceCards() {
  const { data: config, mutate } = useCorrelationConfig()
  const { isAdmin } = usePermissions()
  const [editingSource, setEditingSource] = useState<{ name: string; config: SourceConfig } | null>(null)
  const [addingSource, setAddingSource] = useState(false)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)
  const [deleting, setDeleting] = useState(false)

  if (!config) return null

  const sources = Object.entries(config.sources ?? {})

  const handleDeleteSource = async (name: string) => {
    if (!config) return
    setDeleting(true)
    const updated = { ...config, sources: { ...config.sources } }
    delete updated.sources[name]
    try {
      await updateCorrelationConfig(updated)
      await mutate()
      toast.success(`Removed source "${name}"`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to remove source")
    } finally {
      setDeleting(false)
      setDeleteConfirm(null)
    }
  }

  const handleSaveSource = async (name: string, sourceConfig: SourceConfig, isNew: boolean) => {
    if (!config) return
    const updated = {
      ...config,
      sources: { ...config.sources, [name]: sourceConfig },
    }
    try {
      await updateCorrelationConfig(updated)
      await mutate()
      toast.success(isNew ? `Added source "${name}"` : `Updated source "${name}"`)
      setEditingSource(null)
      setAddingSource(false)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to save source")
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
            Signal Sources
          </CardTitle>
          {isAdmin && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setAddingSource(true)}
              className="h-7 text-xs font-mono"
            >
              <Plus className="h-3 w-3 mr-1" />
              Add Source
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent>
        {sources.length === 0 ? (
          <p className="text-xs font-mono text-muted-foreground text-center py-4">
            No signal sources configured
          </p>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {sources.map(([name, src]) => (
              <div key={name} className="border border-border rounded-md p-3">
                <div className="flex items-center justify-between mb-2 gap-1">
                  <span className="text-sm font-mono font-medium truncate">{name}</span>
                  <div className="flex gap-1 shrink-0">
                    {src.mode === "corroborating" && (
                      <Badge
                        variant="secondary"
                        className="text-[10px] font-mono bg-amber-500/10 text-amber-700 dark:text-amber-400 border-amber-500/30"
                        title="Corroborating-only source: cannot trigger mitigations on its own"
                      >
                        corroborating
                      </Badge>
                    )}
                    <Badge variant="outline" className="text-[10px] font-mono">
                      {src.type || "unknown"}
                    </Badge>
                  </div>
                </div>
                <div className="text-xs font-mono text-muted-foreground space-y-0.5">
                  <div className="flex justify-between">
                    <span>Weight</span>
                    <span className="text-foreground">{src.weight.toFixed(1)}</span>
                  </div>
                  {Object.keys(src.confidence_mapping).length > 0 && (
                    <div className="flex justify-between">
                      <span>Mappings</span>
                      <span className="text-foreground">
                        {Object.keys(src.confidence_mapping).length}
                      </span>
                    </div>
                  )}
                  {src.mode === "corroborating" && src.match_dimensions && src.match_dimensions.length > 0 && (
                    <div className="flex justify-between">
                      <span>Match on</span>
                      <span className="text-foreground truncate ml-2">
                        {src.match_dimensions.join(", ")}
                      </span>
                    </div>
                  )}
                </div>
                {isAdmin && (
                  <div className="flex gap-1 mt-2 pt-2 border-t border-border/50">
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setEditingSource({ name, config: src })}
                      className="h-6 text-[10px] font-mono px-2"
                    >
                      <Pencil className="h-2.5 w-2.5 mr-1" />
                      Edit
                    </Button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setDeleteConfirm(name)}
                      className="h-6 text-[10px] font-mono px-2 text-destructive hover:text-destructive"
                    >
                      <Trash2 className="h-2.5 w-2.5 mr-1" />
                      Remove
                    </Button>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </CardContent>

      {/* Add/Edit Dialog */}
      <SourceDialog
        open={addingSource || editingSource != null}
        onClose={() => { setAddingSource(false); setEditingSource(null) }}
        onSave={handleSaveSource}
        initialName={editingSource?.name}
        initialConfig={editingSource?.config}
        isNew={addingSource}
      />

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteConfirm != null} onOpenChange={(open) => { if (!open) setDeleteConfirm(null) }}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove Signal Source</AlertDialogTitle>
            <AlertDialogDescription>
              This will remove the signal source{" "}
              <span className="font-mono font-semibold">{deleteConfirm}</span>{" "}
              and its weight configuration. Events from this source will still be accepted
              using the default weight.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={() => deleteConfirm && handleDeleteSource(deleteConfirm)}
              disabled={deleting}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleting ? "Removing..." : "Remove"}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

function SourceDialog({
  open,
  onClose,
  onSave,
  initialName,
  initialConfig,
  isNew,
}: {
  open: boolean
  onClose: () => void
  onSave: (name: string, config: SourceConfig, isNew: boolean) => Promise<void>
  initialName?: string
  initialConfig?: SourceConfig
  isNew: boolean
}) {
  const [name, setName] = useState(initialName || "")
  const [weight, setWeight] = useState(initialConfig?.weight?.toString() || "1.0")
  const [type, setType] = useState(initialConfig?.type || "detector")
  const [mode, setMode] = useState<SourceMode>(initialConfig?.mode ?? "primary")
  const [matchDims, setMatchDims] = useState<MatchDimension[]>(
    initialConfig?.match_dimensions ?? []
  )
  const [formError, setFormError] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)

  const resetForm = useCallback(() => {
    setName(initialName || "")
    setWeight(initialConfig?.weight?.toString() || "1.0")
    setType(initialConfig?.type || "detector")
    setMode(initialConfig?.mode ?? "primary")
    setMatchDims(initialConfig?.match_dimensions ?? [])
    setFormError(null)
  }, [initialName, initialConfig])

  const handleOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      onClose()
    } else {
      resetForm()
    }
  }

  useEffect(() => {
    resetForm()
  }, [resetForm])

  const toggleDimension = (dim: MatchDimension) => {
    setMatchDims((prev) =>
      prev.includes(dim) ? prev.filter((d) => d !== dim) : [...prev, dim]
    )
  }

  const handleSave = async () => {
    if (!name.trim()) return
    setFormError(null)
    if (mode === "corroborating" && matchDims.length === 0) {
      setFormError("Select at least one match dimension for corroborating sources")
      return
    }
    if (mode === "primary" && matchDims.length > 0) {
      setFormError("Match dimensions are only valid for corroborating sources")
      return
    }
    setSaving(true)
    try {
      await onSave(
        name.trim(),
        {
          weight: parseFloat(weight) || 1.0,
          type,
          confidence_mapping: initialConfig?.confidence_mapping ?? {},
          mode,
          match_dimensions: mode === "corroborating" ? matchDims : [],
        },
        isNew,
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="text-sm font-mono">
            {isNew ? "Add Signal Source" : `Edit Source: ${initialName}`}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 py-2">
          <div className="space-y-1.5">
            <Label className="text-xs font-mono">Name</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              disabled={!isNew}
              placeholder="e.g., fastnetmon"
              className="h-8 text-xs font-mono"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs font-mono">Type</Label>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger className="h-8 text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="detector" className="text-xs font-mono">Detector</SelectItem>
                <SelectItem value="telemetry" className="text-xs font-mono">Telemetry</SelectItem>
                <SelectItem value="manual" className="text-xs font-mono">Manual</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs font-mono">Weight</Label>
            <Input
              type="number"
              value={weight}
              onChange={(e) => setWeight(e.target.value)}
              className="h-8 text-xs font-mono"
              min={0}
              step={0.1}
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs font-mono">Mode</Label>
            <Select value={mode} onValueChange={(v) => setMode(v as SourceMode)}>
              <SelectTrigger className="h-8 text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="primary" className="text-xs font-mono">
                  Primary (can trigger mitigations)
                </SelectItem>
                <SelectItem value="corroborating" className="text-xs font-mono">
                  Corroborating (strengthens other sources only)
                </SelectItem>
              </SelectContent>
            </Select>
            <p className="text-[10px] font-mono text-muted-foreground">
              Corroborating sources post to /v1/signals/corroborator and never
              fire mitigations on their own (ADR 021).
            </p>
          </div>
          {mode === "corroborating" && (
            <div className="space-y-1.5">
              <Label className="text-xs font-mono">Match dimensions</Label>
              <div className="grid grid-cols-2 gap-1.5">
                {(["customer_id", "pop", "service_id", "interface"] as MatchDimension[]).map(
                  (dim) => (
                    <button
                      key={dim}
                      type="button"
                      onClick={() => toggleDimension(dim)}
                      className={`h-7 text-[11px] font-mono rounded border px-2 ${
                        matchDims.includes(dim)
                          ? "bg-primary/10 border-primary/40 text-primary"
                          : "border-border text-muted-foreground hover:bg-muted/40"
                      }`}
                    >
                      {dim}
                    </button>
                  )
                )}
              </div>
              <p className="text-[10px] font-mono text-muted-foreground">
                Signals from this source must populate at least one of these
                fields; the matcher uses OR across dimensions.
              </p>
            </div>
          )}
          {formError && (
            <p className="text-xs font-mono text-destructive">{formError}</p>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-xs font-mono">
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={saving || !name.trim()}
            className="text-xs font-mono"
          >
            {saving ? <Loader2 className="h-3 w-3 mr-1 animate-spin" /> : <Save className="h-3 w-3 mr-1" />}
            {isNew ? "Add" : "Save"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── Per-Playbook Overrides ────────────────────────────

function PlaybookOverrides() {
  const { data: playbooksData } = useConfigPlaybooks()

  if (!playbooksData) return null

  // Check which playbooks have correlation overrides
  // The playbooks API doesn't currently expose correlation field,
  // so we show a read-only display with a link to the Playbooks tab
  const playbooks = playbooksData.playbooks

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-xs font-mono text-muted-foreground uppercase tracking-wider">
            Per-Playbook Overrides
          </CardTitle>
          <Link href="/config" className="text-xs font-mono text-primary hover:underline flex items-center gap-1">
            <LinkIcon className="h-3 w-3" />
            Edit in Playbooks
          </Link>
        </div>
      </CardHeader>
      <CardContent>
        {playbooks.length === 0 ? (
          <p className="text-xs font-mono text-muted-foreground text-center py-4">
            No playbooks configured.{" "}
            <Link href="/config" className="text-primary hover:underline">
              Configure playbooks
            </Link>
          </p>
        ) : (
          <div className="space-y-2">
            {playbooks.map((playbook) => (
              <div
                key={playbook.name}
                className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"
              >
                <div>
                  <span className="text-xs font-mono font-medium">{playbook.name}</span>
                  <span className="text-[10px] font-mono text-muted-foreground ml-2">
                    {playbook.match.vector.replace(/_/g, " ")}
                  </span>
                </div>
                <Badge variant="outline" className="text-[10px] font-mono">
                  Uses global defaults
                </Badge>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Validation ────────────────────────────

/**
 * Validate a SourceConfig as submitted by the SourceDialog. Mirrors the
 * server-side validator in src/correlation/config.rs so the user sees the
 * error before round-tripping to the API.
 */
export function validateSourceConfig(
  name: string,
  src: SourceConfig
): string[] {
  const errors: string[] = []
  if (!name.trim()) errors.push("Source name is required")
  if (!Number.isFinite(src.weight) || src.weight < 0) {
    errors.push("Weight must be a non-negative number")
  }
  const mode: SourceMode = src.mode ?? "primary"
  const dims = src.match_dimensions ?? []
  if (mode === "primary" && dims.length > 0) {
    errors.push(
      "match_dimensions is only valid for mode=corroborating — clear it or switch modes"
    )
  }
  if (mode === "corroborating" && dims.length === 0) {
    errors.push(
      "Corroborating sources require at least one match_dimension"
    )
  }
  return errors
}

function validateConfig(config: CorrelationConfig): string[] {
  const errors: string[] = []
  if (config.window_seconds < 1) errors.push("Window must be at least 1 second")
  if (config.min_sources < 1) errors.push("Min sources must be at least 1")
  if (config.confidence_threshold < 0 || config.confidence_threshold > 1)
    errors.push("Confidence threshold must be between 0 and 1")
  if (config.default_weight < 0) errors.push("Default weight must be non-negative")
  return errors
}
