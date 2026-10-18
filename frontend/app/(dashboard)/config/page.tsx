"use client"

import { useCallback, useState } from "react"
import { useSWRConfig } from "swr"
import { toast } from "sonner"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { PageHeader } from "@/components/dashboard/page-header"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { formatUtc } from "@/lib/format"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useConfigSettings, useConfigPlaybooks } from "@/hooks/use-api"
import { reloadConfig, updatePlaybooks, type ConfigPlaybook } from "@/lib/api"
import { usePermissions } from "@/hooks/use-permissions"
import { useTabParam } from "@/hooks/use-tab-param"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { RefreshCw, Loader2 } from "lucide-react"
import { AlertingConfigPanel } from "@/components/dashboard/alerting-config-panel"
import { PlaybookEditor, ReadOnlyPlaybookCard } from "@/components/dashboard/playbook-editor"
import { PlaybookYamlEditor } from "@/components/dashboard/playbook-yaml-editor"

const TABS = ["settings", "playbooks", "alerting"] as const

export default function ConfigPage() {
  const [activeTab, setActiveTab] = useTabParam(TABS)
  const { data: settingsData, error: settingsError, mutate: mutateSettings } = useConfigSettings()
  const { data: playbooksData, error: playbooksError, mutate: mutatePlaybooks } = useConfigPlaybooks()
  const { mutate } = useSWRConfig()
  const { canReloadConfig, canEditPlaybooks } = usePermissions()
  const [reloading, setReloading] = useState(false)
  const [reloadResult, setReloadResult] = useState<string | null>(null)
  const [saving, setSaving] = useState(false)
  const [playbookView, setPlaybookView] = useState<"form" | "yaml">("form")

  const handleReload = async () => {
    setReloading(true)
    setReloadResult(null)

    try {
      await reloadConfig()
      await Promise.all([mutate("config-settings"), mutate("config-playbooks"), mutate("config-inventory")])
      setReloadResult("Config reloaded successfully")
      setTimeout(() => setReloadResult(null), 5000)
    } catch (e) {
      setReloadResult(`Reload failed: ${e instanceof Error ? e.message : "unknown error"}`)
    } finally {
      setReloading(false)
    }
  }

  const handleSavePlaybooks = useCallback(async (playbooks: ConfigPlaybook[]) => {
    setSaving(true)

    try {
      await updatePlaybooks(playbooks)
      await mutatePlaybooks()
      toast.success("Playbooks saved and reloaded")
    } catch (e) {
      const msg = e instanceof Error ? e.message : "Failed to save playbooks"
      toast.error(msg)
      throw e
    } finally {
      setSaving(false)
    }
  }, [mutatePlaybooks])

  return (
    <div className="space-y-6">
      <PageHeader
        title="Configuration"
        description={canEditPlaybooks ? "Settings, playbooks and alerting for this controller." : "Running controller configuration (read-only)."}
        actions={
          <>
            {reloadResult && (
              <span role="status" className={`text-sm ${reloadResult.includes("failed") ? "text-destructive" : "text-muted-foreground"}`}>
                {reloadResult}
              </span>
            )}
            {canReloadConfig && (
              <TooltipProvider>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button variant="outline" size="sm" onClick={handleReload} disabled={reloading}>
                      {reloading ? (
                        <Loader2 className="size-4 animate-spin" aria-hidden="true" />
                      ) : (
                        <RefreshCw className="size-4" aria-hidden="true" />
                      )}
                      Reload
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent>Hot-reload inventory and playbooks from disk</TooltipContent>
                </Tooltip>
              </TooltipProvider>
            )}
          </>
        }
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="settings">Settings</TabsTrigger>
          <TabsTrigger value="playbooks">
            Playbooks
            {playbooksData ? (
              <Badge variant="secondary">{playbooksData.total_playbooks}</Badge>
            ) : null}
          </TabsTrigger>
          <TabsTrigger value="alerting">Alerting</TabsTrigger>
        </TabsList>

        <TabsContent value="settings" className="mt-4">
          {settingsError ? (
            <div className="rounded-md border bg-card">
              <ErrorState
                title="Unable to load settings"
                detail={`${settingsError.message}. The controller keeps its running configuration; retry, or check that it is reachable.`}
                onRetry={() => { void mutateSettings() }}
              />
            </div>
          ) : !settingsData ? (
            <div className="rounded-md border bg-card"><LoadingRows label="Loading settings" /></div>
          ) : (
            <Card>
              <CardHeader className="flex flex-wrap items-center justify-between gap-2">
                <CardTitle className="font-mono">prefixd.yaml</CardTitle>
                <span className="text-xs text-muted-foreground tabular-nums">
                  Loaded {formatUtc(settingsData.loaded_at)}
                </span>
              </CardHeader>
              <CardContent>
                <pre className="max-h-[600px] overflow-auto whitespace-pre-wrap rounded-md bg-muted/50 p-4 font-mono text-xs">
                  {JSON.stringify(settingsData.settings, null, 2)}
                </pre>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="playbooks" className="mt-4 space-y-3">
          {playbooksError ? (
            <div className="rounded-md border bg-card">
              <ErrorState
                title="Unable to load playbooks"
                detail={`${playbooksError.message}. The running playbooks are unchanged; retry before editing.`}
                onRetry={() => { void mutatePlaybooks() }}
              />
            </div>
          ) : !playbooksData ? (
            <div className="rounded-md border bg-card"><LoadingRows label="Loading playbooks" /></div>
          ) : canEditPlaybooks ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs text-muted-foreground tabular-nums">
                  Loaded {formatUtc(playbooksData.loaded_at)}
                </span>
                <div role="group" aria-label="Playbook editor view" className="flex items-center gap-1 rounded-md border p-0.5">
                  {(["form", "yaml"] as const).map((view) => (
                    <button
                      key={view}
                      type="button"
                      aria-pressed={playbookView === view}
                      onClick={() => setPlaybookView(view)}
                      className={`min-h-8 rounded-sm px-2.5 text-sm ${playbookView === view ? "bg-secondary font-medium text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                    >
                      {view === "form" ? "Form" : "YAML"}
                    </button>
                  ))}
                </div>
              </div>
              {playbookView === "form" ? (
                <PlaybookEditor
                  key={playbooksData.loaded_at}
                  playbooks={playbooksData.playbooks}
                  onSave={handleSavePlaybooks}
                  saving={saving}
                />
              ) : (
                <PlaybookYamlEditor
                  key={playbooksData.loaded_at}
                  playbooks={playbooksData.playbooks}
                  onSave={handleSavePlaybooks}
                  saving={saving}
                />
              )}
            </>
          ) : (
            playbooksData.playbooks.length === 0 ? (
              <div className="rounded-md border bg-card">
                <EmptyState title="No playbooks configured" description="Without playbooks, events are recorded but no mitigation is proposed." />
              </div>
            ) : (
              playbooksData.playbooks.map((playbook) => (
                <ReadOnlyPlaybookCard key={playbook.name} playbook={playbook} />
              ))
            )
          )}
        </TabsContent>

        <TabsContent value="alerting" className="mt-4">
          <AlertingConfigPanel />
        </TabsContent>
      </Tabs>
    </div>
  )
}
