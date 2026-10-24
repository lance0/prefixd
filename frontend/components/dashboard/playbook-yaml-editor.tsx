"use client"

import { useCallback, useMemo, useState } from "react"
import * as yaml from "js-yaml"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { StatusPill } from "@/components/dashboard/status-pill"
import { AlertCircle, Save, Undo2 } from "lucide-react"
import type { ConfigPlaybook, JsonValue } from "@/lib/api"
import { SaveErrors, serverErrors, validatePlaybooks } from "@/components/dashboard/playbook-editor"

// Preserve merge keys accepted by the editor while keeping YAML 1.2 core types.
const PLAYBOOK_YAML_SCHEMA = yaml.CORE_SCHEMA.withTags(yaml.mergeTag)

interface PlaybookYamlEditorProps {
  playbooks: ConfigPlaybook[]
  onSave: (playbooks: ConfigPlaybook[]) => Promise<void>
  saving: boolean
}

type YamlMapping = { [key: string]: JsonValue }

function isMapping(value: JsonValue | undefined): value is YamlMapping {
  return value instanceof Object && !Array.isArray(value)
}

// Every field the API sent is written out, including `rules` steps and keys this editor
// does not know, so applying an untouched or edited document never drops one. Null
// fields, which the API sends for unset options, are left out.
function playbooksToYaml(playbooks: ConfigPlaybook[]): string {
  const document = JSON.parse(JSON.stringify({ playbooks }, (_key, value) => value ?? undefined))

  return yaml.dump(document, { lineWidth: 120, noRefs: true })
}

interface ParsedPlaybooks {
  playbooks?: ConfigPlaybook[]
  error?: string
}

/**
 * Checks only what the form validation reads; every other field is sent as written, and the
 * controller, which owns the schema, refuses an invalid one with its reason.
 */
function parseYaml(text: string): ParsedPlaybooks {
  let document: JsonValue | undefined

  try {
    // SAFETY: CORE_SCHEMA constructs only null, booleans, numbers, strings, sequences and
    // mappings (merge keys only combine mappings); an empty document loads as undefined.
    document = yaml.load(text, { schema: PLAYBOOK_YAML_SCHEMA }) as JsonValue | undefined
  } catch (e) {
    return { error: `YAML parse error: ${e instanceof Error ? e.message : String(e)}` }
  }

  const entries = isMapping(document) ? document.playbooks : undefined

  if (!Array.isArray(entries)) {
    return { error: "YAML must contain a top-level 'playbooks' array" }
  }

  for (const [i, entry] of entries.entries()) {
    const ctx = `Playbook #${i + 1}`

    if (!isMapping(entry)) return { error: `${ctx} must be a mapping` }

    if (!isMapping(entry.match)) return { error: `${ctx}: match must be a mapping` }

    if (!Array.isArray(entry.steps) || !entry.steps.every((step) => isMapping(step))) {
      return { error: `${ctx}: steps must be a list of mappings` }
    }
  }

  // Each entry was checked above for the fields the form validation reads. A JSON copy
  // passes the rest through unchanged (CORE_SCHEMA values are all JSON values), and the
  // controller validates it on save.
  const playbooks: ConfigPlaybook[] = JSON.parse(JSON.stringify(entries))

  return { playbooks }
}

export function PlaybookYamlEditor({ playbooks: initialPlaybooks, onSave, saving }: PlaybookYamlEditorProps) {
  const initialYaml = useMemo(() => playbooksToYaml(initialPlaybooks), [initialPlaybooks])
  const [text, setText] = useState(initialYaml)
  const [saveErrors, setSaveErrors] = useState<string[]>([])

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
    setSaveErrors([])
  }, [initialYaml])

  const handleSave = useCallback(async () => {
    if (!parsed) return
    setSaveErrors([])

    try {
      await onSave(parsed)
    } catch (e) {
      setSaveErrors(serverErrors(e instanceof Error ? e.message : String(e)))
    }
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

      <SaveErrors errors={saveErrors} />

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
        aria-label="Playbooks YAML"
        className={
          "w-full min-h-[400px] bg-secondary/50 border border-input-border rounded-md p-4 " +
          "text-xs font-mono text-foreground resize-y focus:outline-none focus:ring-1 focus:ring-primary"
        }
      />
    </div>
  )
}
