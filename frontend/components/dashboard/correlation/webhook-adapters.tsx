"use client"

import { useState, useCallback } from "react"
import { toast } from "sonner"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { useCorrelationConfig } from "@/hooks/use-api"
import { usePermissions } from "@/hooks/use-permissions"
import { updateCorrelationConfig } from "@/lib/api"
import type {
  CorrelationConfig,
  WebhookAdapter,
  WebhookAuth,
  WebhookFieldMap,
} from "@/lib/api"
import {
  Webhook,
  Plus,
  Pencil,
  Trash2,
  Save,
  Loader2,
  AlertCircle,
  Copy,
} from "lucide-react"

const NAME_PATTERN = /^[a-z0-9-]{1,64}$/

export function WebhookAdaptersEditor() {
  const { data: config, error, isLoading, mutate } = useCorrelationConfig()
  const { isAdmin } = usePermissions()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [editing, setEditing] = useState<WebhookAdapter | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null)

  const adapters = config?.webhook_adapters ?? []

  const persist = useCallback(
    async (updater: (adapters: WebhookAdapter[]) => WebhookAdapter[]) => {
      if (!config) return
      const next: CorrelationConfig = {
        ...config,
        webhook_adapters: updater(adapters),
      }
      try {
        await updateCorrelationConfig(next)
        await mutate()
        toast.success("Webhook adapters saved")
      } catch (e) {
        toast.error("Failed to save", {
          description: e instanceof Error ? e.message : String(e),
        })
      }
    },
    [config, adapters, mutate],
  )

  const handleUpsert = (adapter: WebhookAdapter) => {
    persist((list) => {
      const idx = list.findIndex((a) => a.name === adapter.name)
      if (idx >= 0) {
        const clone = [...list]
        clone[idx] = adapter
        return clone
      }
      return [...list, adapter]
    })
    setDialogOpen(false)
    setEditing(null)
  }

  const handleDelete = () => {
    if (!deleteTarget) return
    const name = deleteTarget
    persist((list) => list.filter((a) => a.name !== name))
    setDeleteTarget(null)
  }

  if (isLoading) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <Webhook className="h-4 w-4" /> Webhook Adapters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Skeleton className="h-24 w-full" />
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <Webhook className="h-4 w-4" /> Webhook Adapters
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-2 text-xs font-mono text-destructive">
            <AlertCircle className="h-4 w-4" />
            Failed to load configuration
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm font-mono flex items-center gap-2">
          <Webhook className="h-4 w-4" /> Webhook Adapters
          <Badge variant="secondary" className="ml-1 text-[10px]">
            {adapters.length}
          </Badge>
        </CardTitle>
        {isAdmin && (
          <Button
            size="sm"
            variant="outline"
            className="font-mono text-xs"
            onClick={() => {
              setEditing(newAdapter())
              setDialogOpen(true)
            }}
          >
            <Plus className="h-3 w-3 mr-1" /> Add Adapter
          </Button>
        )}
      </CardHeader>
      <CardContent className="space-y-2">
        <p className="text-xs font-mono text-muted-foreground">
          Generic webhook endpoints at{" "}
          <code className="px-1 py-0.5 bg-muted rounded">
            POST /v1/signals/webhook/&#123;name&#125;
          </code>
          . Map arbitrary JSON payloads from any detector using JSONPath.
        </p>

        {adapters.length === 0 ? (
          <div className="text-xs font-mono text-muted-foreground py-4 text-center border border-dashed rounded">
            No webhook adapters configured
          </div>
        ) : (
          <div className="space-y-2">
            {adapters.map((a) => (
              <AdapterRow
                key={a.name}
                adapter={a}
                canEdit={isAdmin}
                onEdit={() => {
                  setEditing(a)
                  setDialogOpen(true)
                }}
                onDelete={() => setDeleteTarget(a.name)}
              />
            ))}
          </div>
        )}
      </CardContent>

      <AdapterDialog
        open={dialogOpen}
        onOpenChange={(o) => {
          setDialogOpen(o)
          if (!o) setEditing(null)
        }}
        initial={editing}
        existingNames={adapters.map((a) => a.name)}
        onSubmit={handleUpsert}
      />

      <AlertDialog
        open={deleteTarget !== null}
        onOpenChange={(o) => !o && setDeleteTarget(null)}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove webhook adapter?</AlertDialogTitle>
            <AlertDialogDescription>
              This will disable the <code>/v1/signals/webhook/{deleteTarget}</code>{" "}
              endpoint. Existing events are unaffected. You can re-add it later.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction onClick={handleDelete}>Remove</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

function AdapterRow({
  adapter,
  canEdit,
  onEdit,
  onDelete,
}: {
  adapter: WebhookAdapter
  canEdit: boolean
  onEdit: () => void
  onDelete: () => void
}) {
  const endpoint = `/v1/signals/webhook/${adapter.name}`
  return (
    <div className="flex items-start justify-between rounded border p-3 gap-4">
      <div className="flex-1 min-w-0 space-y-1.5">
        <div className="flex items-center gap-2">
          <code className="text-xs font-mono font-medium">{adapter.name}</code>
          <Badge
            variant={adapter.enabled ? "default" : "secondary"}
            className="text-[10px] px-1 py-0"
          >
            {adapter.enabled ? "enabled" : "disabled"}
          </Badge>
          <Badge variant="outline" className="text-[10px] px-1 py-0">
            auth: {adapter.auth.type}
          </Badge>
          {adapter.root_path && (
            <Badge variant="outline" className="text-[10px] px-1 py-0">
              batched
            </Badge>
          )}
        </div>
        {adapter.description && (
          <div className="text-xs font-mono text-muted-foreground">
            {adapter.description}
          </div>
        )}
        <div className="flex items-center gap-2">
          <code className="text-[11px] font-mono bg-muted px-1.5 py-0.5 rounded flex-1 truncate">
            POST {endpoint}
          </code>
          <button
            type="button"
            aria-label="Copy endpoint"
            onClick={() => {
              navigator.clipboard.writeText(endpoint).then(() => {
                toast.success("Endpoint copied")
              })
            }}
            className="p-1 hover:bg-muted rounded"
          >
            <Copy className="h-3 w-3" />
          </button>
        </div>
      </div>
      {canEdit && (
        <div className="flex items-center gap-1">
          <Button
            size="sm"
            variant="ghost"
            className="h-7 w-7 p-0"
            aria-label="Edit adapter"
            onClick={onEdit}
          >
            <Pencil className="h-3 w-3" />
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="h-7 w-7 p-0 text-destructive hover:text-destructive"
            aria-label="Remove adapter"
            onClick={onDelete}
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>
      )}
    </div>
  )
}

function AdapterDialog({
  open,
  onOpenChange,
  initial,
  existingNames,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  initial: WebhookAdapter | null
  existingNames: string[]
  onSubmit: (a: WebhookAdapter) => void
}) {
  const [form, setForm] = useState<WebhookAdapter>(initial ?? newAdapter())
  const [saving, setSaving] = useState(false)

  // Reset form when dialog opens with new adapter
  useState(() => {
    if (initial) setForm(initial)
  })

  const isNew = !existingNames.includes(form.name)
  const errors = validateAdapter(form, existingNames, isNew)
  const canSave = errors.length === 0

  const handleSave = async () => {
    if (!canSave) return
    setSaving(true)
    try {
      await Promise.resolve(onSubmit(form))
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(o) => {
        onOpenChange(o)
        if (o && initial) setForm(initial)
        if (o && !initial) setForm(newAdapter())
      }}
    >
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="font-mono text-sm">
            {initial && existingNames.includes(initial.name)
              ? `Edit ${initial.name}`
              : "New webhook adapter"}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 text-xs font-mono">
          <Field
            label="Name"
            hint="URL path segment, [a-z0-9-]{1,64}"
            value={form.name}
            onChange={(v) => setForm({ ...form, name: v })}
            disabled={initial !== null && existingNames.includes(initial.name)}
            error={
              !NAME_PATTERN.test(form.name) ? "Must match [a-z0-9-]{1,64}" : undefined
            }
          />

          <Field
            label="Description"
            value={form.description}
            onChange={(v) => setForm({ ...form, description: v })}
          />

          <div className="flex items-center gap-2">
            <input
              id="adapter-enabled"
              type="checkbox"
              checked={form.enabled}
              onChange={(e) => setForm({ ...form, enabled: e.target.checked })}
              className="h-3 w-3"
            />
            <Label htmlFor="adapter-enabled" className="text-xs font-mono">
              Enabled
            </Label>
          </div>

          <div className="border-t pt-3">
            <div className="text-xs font-mono font-medium mb-2">Authentication</div>
            <Select
              value={form.auth.type}
              onValueChange={(v) => setForm({ ...form, auth: defaultAuth(v as WebhookAuth["type"]) })}
            >
              <SelectTrigger className="h-8 text-xs font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="hmac" className="text-xs font-mono">
                  HMAC-SHA256
                </SelectItem>
                <SelectItem value="bearer" className="text-xs font-mono">
                  Bearer token
                </SelectItem>
                <SelectItem value="none" className="text-xs font-mono">
                  None (insecure)
                </SelectItem>
              </SelectContent>
            </Select>

            {form.auth.type === "hmac" && (
              <div className="space-y-2 mt-2 pl-2 border-l-2">
                <Field
                  label="Secret env var"
                  hint="Name of the env var holding the HMAC secret (value never sent)"
                  value={form.auth.secret_env}
                  onChange={(v) =>
                    setForm({
                      ...form,
                      auth: { ...(form.auth as Extract<WebhookAuth, { type: "hmac" }>), secret_env: v },
                    })
                  }
                />
                <Field
                  label="Header"
                  value={form.auth.header}
                  onChange={(v) =>
                    setForm({
                      ...form,
                      auth: { ...(form.auth as Extract<WebhookAuth, { type: "hmac" }>), header: v },
                    })
                  }
                />
              </div>
            )}
          </div>

          <div className="border-t pt-3">
            <div className="text-xs font-mono font-medium mb-2">Field Mappings (JSONPath)</div>
            <FieldMapEditor
              value={form.fields}
              onChange={(fields) => setForm({ ...form, fields })}
            />
          </div>

          <div className="border-t pt-3">
            <div className="text-xs font-mono font-medium mb-2">Advanced</div>
            <Field
              label="root_path"
              hint='Optional; iterate a JSON array (e.g. "$.alerts[*]")'
              value={form.root_path ?? ""}
              onChange={(v) => setForm({ ...form, root_path: v || null })}
            />
            <Field
              label="default_vector"
              hint="Fallback when vector field is missing or not in vector_map"
              value={form.default_vector ?? ""}
              onChange={(v) => setForm({ ...form, default_vector: v || null })}
            />
            <Field
              label="confidence_scale"
              hint="Divisor (e.g. 100 for 0-100 scales)"
              value={form.confidence_scale?.toString() ?? ""}
              onChange={(v) => {
                const n = v === "" ? null : Number(v)
                setForm({ ...form, confidence_scale: Number.isNaN(n) ? null : n })
              }}
            />
            <Field
              label="source_id_prefix"
              hint='Prefix for extracted source_id (e.g. "radware-")'
              value={form.source_id_prefix ?? ""}
              onChange={(v) => setForm({ ...form, source_id_prefix: v || null })}
            />

            <div className="mt-3">
              <Label className="text-xs font-mono">
                vector_map <span className="text-muted-foreground">(one per line, raw=prefixd)</span>
              </Label>
              <Textarea
                className="mt-1 text-xs font-mono h-20"
                value={vectorMapToText(form.vector_map)}
                onChange={(e) =>
                  setForm({ ...form, vector_map: textToVectorMap(e.target.value) })
                }
                placeholder="UDP_FLOOD=udp_flood&#10;SYN_FLOOD=syn_flood"
              />
            </div>
          </div>

          {errors.length > 0 && (
            <div className="rounded border border-destructive/30 bg-destructive/5 p-2 text-xs font-mono text-destructive space-y-0.5">
              {errors.map((e) => (
                <div key={e}>{e}</div>
              ))}
            </div>
          )}
        </div>

        <DialogFooter>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onOpenChange(false)}
          >
            Cancel
          </Button>
          <Button
            size="sm"
            onClick={handleSave}
            disabled={!canSave || saving}
            className="font-mono"
          >
            {saving ? (
              <Loader2 className="h-3 w-3 mr-1 animate-spin" />
            ) : (
              <Save className="h-3 w-3 mr-1" />
            )}
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function Field({
  label,
  hint,
  value,
  onChange,
  disabled,
  error,
}: {
  label: string
  hint?: string
  value: string
  onChange: (v: string) => void
  disabled?: boolean
  error?: string
}) {
  return (
    <div className="space-y-1">
      <Label className="text-xs font-mono">{label}</Label>
      <Input
        value={value}
        onChange={(e) => onChange(e.target.value)}
        disabled={disabled}
        className="h-8 text-xs font-mono"
      />
      {error && <div className="text-[11px] text-destructive">{error}</div>}
      {hint && !error && (
        <div className="text-[11px] text-muted-foreground">{hint}</div>
      )}
    </div>
  )
}

function FieldMapEditor({
  value,
  onChange,
}: {
  value: WebhookFieldMap
  onChange: (v: WebhookFieldMap) => void
}) {
  const entries: Array<[keyof WebhookFieldMap, string, boolean]> = [
    ["victim_ip", 'REQUIRED; e.g. "$.target.ip"', true],
    ["vector", 'Optional; e.g. "$.alert_type"', false],
    ["timestamp", 'Optional RFC3339 string', false],
    ["bps", 'Optional number', false],
    ["pps", 'Optional number', false],
    ["confidence", 'Optional number', false],
    ["source_id", 'Optional; used for dedup', false],
    ["top_dst_ports", 'Optional array of ports', false],
    ["action", 'Optional "ban" or "unban"', false],
  ]
  return (
    <div className="space-y-2">
      {entries.map(([key, hint, required]) => (
        <Field
          key={key}
          label={key + (required ? " *" : "")}
          hint={hint}
          value={(value[key] ?? "") as string}
          onChange={(v) => {
            const next = { ...value }
            if (required) {
              ;(next as WebhookFieldMap).victim_ip = v
            } else {
              ;(next as Record<string, string | null>)[key as string] =
                v || null
            }
            onChange(next)
          }}
        />
      ))}
    </div>
  )
}

// Helpers

function newAdapter(): WebhookAdapter {
  return {
    name: "",
    description: "",
    enabled: true,
    auth: { type: "hmac", secret_env: "", header: "X-Signature-SHA256", algorithm: "sha256" },
    root_path: null,
    fields: {
      victim_ip: "$.victim_ip",
      vector: null,
      timestamp: null,
      bps: null,
      pps: null,
      confidence: null,
      source_id: null,
      top_dst_ports: null,
      action: null,
    },
    vector_map: {},
    default_vector: null,
    confidence_scale: null,
    source_id_prefix: null,
  }
}

function defaultAuth(type: WebhookAuth["type"]): WebhookAuth {
  switch (type) {
    case "hmac":
      return {
        type: "hmac",
        secret_env: "",
        header: "X-Signature-SHA256",
        algorithm: "sha256",
      }
    case "bearer":
      return { type: "bearer" }
    default:
      return { type: "none" }
  }
}

function vectorMapToText(map: Record<string, string> | undefined): string {
  if (!map) return ""
  return Object.entries(map)
    .map(([k, v]) => `${k}=${v}`)
    .join("\n")
}

function textToVectorMap(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split("\n")) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith("#")) continue
    const eq = trimmed.indexOf("=")
    if (eq <= 0) continue
    const k = trimmed.slice(0, eq).trim()
    const v = trimmed.slice(eq + 1).trim()
    if (k && v) out[k] = v
  }
  return out
}

export function validateAdapter(
  adapter: WebhookAdapter,
  existingNames: string[],
  isNew: boolean,
): string[] {
  const errors: string[] = []
  if (!NAME_PATTERN.test(adapter.name)) {
    errors.push("name must match [a-z0-9-]{1,64}")
  }
  if (isNew && existingNames.includes(adapter.name)) {
    errors.push(`name '${adapter.name}' is already in use`)
  }
  if (!adapter.fields.victim_ip) {
    errors.push("fields.victim_ip is required")
  }
  if (adapter.auth.type === "hmac" && !adapter.auth.secret_env) {
    errors.push("auth.secret_env is required for HMAC")
  }
  if (
    adapter.confidence_scale !== null &&
    adapter.confidence_scale !== undefined &&
    adapter.confidence_scale <= 0
  ) {
    errors.push("confidence_scale must be > 0")
  }
  return errors
}
