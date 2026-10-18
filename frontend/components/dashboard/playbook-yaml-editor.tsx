"use client"

import { useCallback, useMemo, useState } from "react"
import * as yaml from "js-yaml"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { StatusPill } from "@/components/dashboard/status-pill"
import { AlertCircle, Save, Undo2 } from "lucide-react"
import type { ConfigPlaybook, JsonValue } from "@/lib/api"
import { validatePlaybooks } from "@/components/dashboard/playbook-editor"

// Preserve merge keys accepted by the editor while keeping YAML 1.2 core types.
const PLAYBOOK_YAML_SCHEMA = yaml.CORE_SCHEMA.withTags(yaml.mergeTag)

interface PlaybookYamlEditorProps {
  playbooks: ConfigPlaybook[]
  onSave: (playbooks: ConfigPlaybook[]) => Promise<void>
  saving: boolean
}

function playbooksToYaml(playbooks: ConfigPlaybook[]): string {
  const obj = {
    playbooks: playbooks.map((p) => ({
      name: p.name,
      match: {
        vector: p.match.vector,
        // undefined keys are omitted by yaml.dump's skipInvalid.
        require_top_ports: p.match.require_top_ports ? true : undefined,
      },
      // Round-trip per-playbook correlation overrides; omit unset fields.
      correlation: definedFields(p.correlation),
      // undefined keys are omitted by yaml.dump's skipInvalid.
      steps: p.steps.map((s) => ({
        action: s.action,
        rate_bps: s.rate_bps ?? undefined,
        ttl_seconds: s.ttl_seconds,
        require_confidence_at_least: s.require_confidence_at_least ?? undefined,
        require_persistence_seconds: s.require_persistence_seconds ?? undefined,
      })),
    })),
  }

  return yaml.dump(obj, { lineWidth: 120, noRefs: true, skipInvalid: true })
}

function definedFields(value: ConfigPlaybook["correlation"]): ConfigPlaybook["correlation"] | undefined {
  const entries = Object.entries(value ?? {}).filter(([, v]) => v != null)

  return entries.length > 0 ? Object.fromEntries(entries) : undefined
}

interface ParsedPlaybooks {
  playbooks?: ConfigPlaybook[]
  error?: string
}

type YamlMapping = { [key: string]: JsonValue }

function asMapping(value: JsonValue | undefined): YamlMapping {
  return value instanceof Object && !Array.isArray(value) ? value : {}
}

function asList(value: JsonValue | undefined): JsonValue[] {
  return Array.isArray(value) ? value : []
}

function optionalNumber(value: JsonValue | undefined): number | undefined {
  return value != null ? Number(value) : undefined
}

function parseYaml(text: string): ParsedPlaybooks {
  let document: JsonValue | undefined

  try {
    // SAFETY: CORE_SCHEMA constructs only null, booleans, numbers, strings, sequences and
    // mappings (merge keys only combine mappings); an empty document loads as undefined.
    document = yaml.load(text, { schema: PLAYBOOK_YAML_SCHEMA }) as JsonValue | undefined
  } catch (e) {
    return { error: `YAML parse error: ${e instanceof Error ? e.message : String(e)}` }
  }

  const entries = asMapping(document).playbooks

  if (!Array.isArray(entries)) {
    return { error: "YAML must contain a top-level 'playbooks' array" }
  }

  // Coerce to ConfigPlaybook shape for validation
  const playbooks: ConfigPlaybook[] = []

  for (const [i, entry] of entries.entries()) {
    const pb = asMapping(entry)
    const match = asMapping(pb.match)
    const name = String(pb.name ?? "")
    const steps: ConfigPlaybook["steps"] = []

    for (const [j, rawStep] of asList(pb.steps).entries()) {
      const s = asMapping(rawStep)
      const action = String(s.action ?? "police")

      if (action !== "police" && action !== "discard") {
        return { error: `Playbook "${name || `#${i + 1}`}" step ${j + 1}: action must be one of police, discard` }
      }

      steps.push({
        action,
        rate_bps: optionalNumber(s.rate_bps),
        ttl_seconds: Number(s.ttl_seconds ?? 0),
        require_confidence_at_least: optionalNumber(s.require_confidence_at_least),
        require_persistence_seconds: optionalNumber(s.require_persistence_seconds),
      })
    }

    playbooks.push({
      name,
      match: {
        vector: String(match.vector ?? "unknown"),
        require_top_ports: match.require_top_ports === true,
      },
      // SAFETY: the override is sent as written; nothing here reads it, and the controller,
      // which owns its schema, rejects an invalid override when the playbooks are saved.
      correlation: (pb.correlation ?? undefined) as ConfigPlaybook["correlation"],
      steps,
    })
  }

  return { playbooks }
}

export function PlaybookYamlEditor({ playbooks: initialPlaybooks, onSave, saving }: PlaybookYamlEditorProps) {
  const initialYaml = useMemo(() => playbooksToYaml(initialPlaybooks), [initialPlaybooks])
  const [text, setText] = useState(initialYaml)

  const hasChanges = text !== initialYaml

  const { parsed, parseError, validationErrors } = useMemo(() => {
    const result = parseYaml(text)

    if (result.error) return { parsed: null, parseError: result.error, validationErrors: [] }
    const valErrors = result.playbooks ? validatePlaybooks(result.playbooks) : []

    return { parsed: result.playbooks ?? null, parseError: null, validationErrors: valErrors }
  }, [text])

  const allErrors = parseError ? [parseError] : validationErrors

  const handleDiscard = useCallback(() => {
    setText(initialYaml)
  }, [initialYaml])

  const handleSave = useCallback(async () => {
    if (!parsed) return
    await onSave(parsed)
  }, [parsed, onSave])

  return (
    <div className="space-y-3">
      {/* Action bar */}
      <div className="flex items-center justify-end gap-2">
        {hasChanges && (
          <StatusPill tone="warning">Unsaved changes</StatusPill>
        )}
        <Button variant="ghost" size="sm" onClick={handleDiscard} disabled={!hasChanges || saving}>
          <Undo2 className="h-3.5 w-3.5 mr-1.5" />
          Discard
        </Button>
        <Button size="sm" onClick={handleSave} disabled={!hasChanges || allErrors.length > 0 || saving} className="text-xs">
          <Save className="h-3.5 w-3.5 mr-1.5" />
          {saving ? "Applying…" : "Apply"}
        </Button>
      </div>

      {/* Errors */}
      {allErrors.length > 0 && hasChanges && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent>
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div className="space-y-1">
                {allErrors.map((err, i) => (
                  <p key={i} className="text-xs text-destructive">{err}</p>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* YAML textarea */}
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        spellCheck={false}
        className={
          "w-full min-h-[400px] bg-secondary/50 border border-border rounded-md p-4 " +
          "text-xs font-mono text-foreground resize-y focus:outline-none focus:ring-1 focus:ring-primary"
        }
      />
    </div>
  )
}
