"use client"

import { useCallback, useMemo, useState } from "react"
import yaml from "js-yaml"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { AlertCircle, Save, Undo2 } from "lucide-react"
import type { ConfigPlaybook } from "@/lib/api"
import { validatePlaybooks } from "@/components/dashboard/playbook-editor"

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
        ...(p.match.require_top_ports ? { require_top_ports: true } : {}),
      },
      steps: p.steps.map((s) => {
        const step: Record<string, unknown> = { action: s.action }
        if (s.rate_bps != null) step.rate_bps = s.rate_bps
        step.ttl_seconds = s.ttl_seconds
        if (s.require_confidence_at_least != null) step.require_confidence_at_least = s.require_confidence_at_least
        if (s.require_persistence_seconds != null) step.require_persistence_seconds = s.require_persistence_seconds
        return step
      }),
    })),
  }
  return yaml.dump(obj, { lineWidth: 120, noRefs: true })
}

function parseYaml(text: string): { playbooks?: ConfigPlaybook[]; error?: string } {
  try {
    const parsed = yaml.load(text) as { playbooks?: unknown[] }
    if (!parsed || !Array.isArray(parsed.playbooks)) {
      return { error: "YAML must contain a top-level 'playbooks' array" }
    }
    // Coerce to ConfigPlaybook shape for validation
    const playbooks: ConfigPlaybook[] = parsed.playbooks.map((p: unknown) => {
      const pb = p as Record<string, unknown>
      const match = pb.match as Record<string, unknown> | undefined
      const steps = (pb.steps as Record<string, unknown>[]) || []
      return {
        name: String(pb.name ?? ""),
        match: {
          vector: String(match?.vector ?? "unknown"),
          require_top_ports: Boolean(match?.require_top_ports),
        },
        steps: steps.map((s) => ({
          action: (String(s.action ?? "police")) as "police" | "discard",
          rate_bps: s.rate_bps != null ? Number(s.rate_bps) : undefined,
          ttl_seconds: Number(s.ttl_seconds ?? 0),
          require_confidence_at_least: s.require_confidence_at_least != null ? Number(s.require_confidence_at_least) : undefined,
          require_persistence_seconds: s.require_persistence_seconds != null ? Number(s.require_persistence_seconds) : undefined,
        })),
      }
    })
    return { playbooks }
  } catch (e) {
    return { error: `YAML parse error: ${e instanceof Error ? e.message : String(e)}` }
  }
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
          <Badge variant="secondary" className="text-[10px] bg-yellow-500/10 text-yellow-600 border-yellow-500/30">
            Unsaved changes
          </Badge>
        )}
        <Button variant="ghost" size="sm" onClick={handleDiscard} disabled={!hasChanges || saving} className="text-xs font-mono">
          <Undo2 className="h-3.5 w-3.5 mr-1.5" />
          Discard
        </Button>
        <Button size="sm" onClick={handleSave} disabled={!hasChanges || allErrors.length > 0 || saving} className="text-xs font-mono">
          <Save className="h-3.5 w-3.5 mr-1.5" />
          {saving ? "Applying..." : "Apply"}
        </Button>
      </div>

      {/* Errors */}
      {allErrors.length > 0 && hasChanges && (
        <Card className="border-destructive/50 bg-destructive/5">
          <CardContent className="p-3">
            <div className="flex items-start gap-2">
              <AlertCircle className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <div className="space-y-1">
                {allErrors.map((err, i) => (
                  <p key={i} className="text-xs text-destructive font-mono">{err}</p>
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
