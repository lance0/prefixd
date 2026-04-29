"use client"

import { useState } from "react"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Badge } from "@/components/ui/badge"
import { Radio, Layers, Settings, Database } from "lucide-react"
import { useOpenSignalGroupCount } from "@/hooks/use-api"
import { SignalsTab } from "@/components/dashboard/correlation/signals-tab"
import { GroupsTab } from "@/components/dashboard/correlation/groups-tab"
import { ConfigTab } from "@/components/dashboard/correlation/config-tab"
import { CacheTab } from "@/components/dashboard/correlation/cache-tab"

export default function CorrelationPage() {
  const [activeTab, setActiveTab] = useState("signals")
  const openGroupCount = useOpenSignalGroupCount()

  return (
    <DashboardLayout>
      <div className="flex-1 overflow-auto">
        <div className="p-4 sm:p-6 space-y-4">
          <div>
            <h1 className="text-lg font-mono font-medium">Correlation</h1>
            <p className="text-xs text-muted-foreground font-mono mt-0.5">
              Multi-signal correlation engine — combine signals from multiple sources
            </p>
          </div>

          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="font-mono">
              <TabsTrigger value="signals" className="text-xs">
                <Radio className="h-3 w-3 mr-1.5" />
                Signals
              </TabsTrigger>
              <TabsTrigger value="groups" className="text-xs">
                <Layers className="h-3 w-3 mr-1.5" />
                Groups
                {openGroupCount > 0 && (
                  <Badge variant="secondary" className="ml-1.5 text-[10px] px-1 py-0">
                    {openGroupCount}
                  </Badge>
                )}
              </TabsTrigger>
              <TabsTrigger value="cache" className="text-xs">
                <Database className="h-3 w-3 mr-1.5" />
                Cache
              </TabsTrigger>
              <TabsTrigger value="config" className="text-xs">
                <Settings className="h-3 w-3 mr-1.5" />
                Config
              </TabsTrigger>
            </TabsList>

            <TabsContent value="signals" className="mt-4">
              <SignalsTab />
            </TabsContent>

            <TabsContent value="groups" className="mt-4">
              <GroupsTab />
            </TabsContent>

            <TabsContent value="cache" className="mt-4">
              <CacheTab />
            </TabsContent>

            <TabsContent value="config" className="mt-4">
              <ConfigTab />
            </TabsContent>
          </Tabs>
        </div>
      </div>
    </DashboardLayout>
  )
}
