"use client"

import { useCallback, useState } from "react"
import { useSWRConfig } from "swr"
import { toast } from "sonner"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useConfigSettings, useConfigPlaybooks } from "@/hooks/use-api"
import { reloadConfig, updatePlaybooks, type ConfigPlaybook } from "@/lib/api"
import { usePermissions } from "@/hooks/use-permissions"
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { RefreshCw, Loader2, FileCode, Zap, Bell, Code } from "lucide-react"
import { AlertingConfigPanel } from "@/components/dashboard/alerting-config-panel"
import { PlaybookEditor, ReadOnlyPlaybookCard } from "@/components/dashboard/playbook-editor"
import { PlaybookYamlEditor } from "@/components/dashboard/playbook-yaml-editor"

export default function ConfigPage() {
  const { data: settingsData, error: settingsError } = useConfigSettings()
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
    <DashboardLayout>
      <div className="flex-1 overflow-auto">
        <div className="p-4 sm:p-6 space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-lg font-mono font-medium">Configuration</h1>
              <p className="text-xs text-muted-foreground font-mono mt-0.5">
                {canEditPlaybooks ? "Manage daemon configuration" : "Running daemon configuration (read-only)"}
              </p>
            </div>
            <div className="flex items-center gap-3">
              {reloadResult && (
                <span className={`text-xs font-mono ${reloadResult.includes("failed") ? "text-destructive" : "text-success"}`}>
                  {reloadResult}
                </span>
              )}
              {canReloadConfig && (
                <TooltipProvider>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleReload}
                        disabled={reloading}
                        className="font-mono text-xs hover:text-foreground"
                      >
                        {reloading ? (
                          <Loader2 className="h-3 w-3 mr-1.5 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3 w-3 mr-1.5" />
                        )}
                        Reload
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent className="font-mono text-xs">
                      Hot-reload inventory and playbooks from disk
                    </TooltipContent>
                  </Tooltip>
                </TooltipProvider>
              )}
            </div>
          </div>

          <Tabs defaultValue="settings">
            <TabsList className="font-mono">
              <TabsTrigger value="settings" className="text-xs">
                <FileCode className="h-3 w-3 mr-1.5" />
                Settings
              </TabsTrigger>
              <TabsTrigger value="playbooks" className="text-xs">
                <Zap className="h-3 w-3 mr-1.5" />
                Playbooks
                {playbooksData ? (
                  <Badge variant="secondary" className="ml-1.5 text-[10px] px-1 py-0">
                    {playbooksData.total_playbooks}
                  </Badge>
                ) : null}
              </TabsTrigger>
              <TabsTrigger value="alerting" className="text-xs">
                <Bell className="h-3 w-3 mr-1.5" />
                Alerting
              </TabsTrigger>
            </TabsList>

            <TabsContent value="settings" className="mt-4">
              {settingsError ? (
                <Card>
                  <CardContent className="p-4 text-sm text-destructive font-mono">
                    Failed to load settings: {settingsError.message}
                  </CardContent>
                </Card>
              ) : !settingsData ? (
                <Card>
                  <CardContent className="p-4 flex items-center gap-2 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm font-mono">Loading settings...</span>
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-mono">prefixd.yaml</CardTitle>
                      <span className="text-[10px] font-mono text-muted-foreground">
                        Loaded: {new Date(settingsData.loaded_at).toLocaleString()}
                      </span>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <pre className="text-xs font-mono bg-secondary/50 p-4 overflow-auto max-h-[600px] whitespace-pre-wrap">
                      {JSON.stringify(settingsData.settings, null, 2)}
                    </pre>
                  </CardContent>
                </Card>
              )}
            </TabsContent>

            <TabsContent value="playbooks" className="mt-4 space-y-3">
              {playbooksError ? (
                <Card>
                  <CardContent className="p-4 text-sm text-destructive font-mono">
                    Failed to load playbooks: {playbooksError.message}
                  </CardContent>
                </Card>
              ) : !playbooksData ? (
                <Card>
                  <CardContent className="p-4 flex items-center gap-2 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    <span className="text-sm font-mono">Loading playbooks...</span>
                  </CardContent>
                </Card>
              ) : canEditPlaybooks ? (
                <>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] font-mono text-muted-foreground">
                      Loaded: {new Date(playbooksData.loaded_at).toLocaleString()}
                    </span>
                    <div className="flex items-center gap-1 border border-border rounded-md p-0.5">
                      <button
                        onClick={() => setPlaybookView("form")}
                        className={`px-2 py-1 text-[10px] font-mono rounded-sm transition-colors ${playbookView === "form" ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                      >
                        <Zap className="h-3 w-3 inline mr-1" />
                        Form
                      </button>
                      <button
                        onClick={() => setPlaybookView("yaml")}
                        className={`px-2 py-1 text-[10px] font-mono rounded-sm transition-colors ${playbookView === "yaml" ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground"}`}
                      >
                        <Code className="h-3 w-3 inline mr-1" />
                        YAML
                      </button>
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
                  <Card>
                    <CardContent className="p-4 text-sm text-muted-foreground font-mono">
                      No playbooks configured
                    </CardContent>
                  </Card>
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
      </div>
    </DashboardLayout>
  )
}
