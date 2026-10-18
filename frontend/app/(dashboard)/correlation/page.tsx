"use client"

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useTabParam } from "@/hooks/use-tab-param"
import { Badge } from "@/components/ui/badge"
import { PageHeader } from "@/components/dashboard/page-header"
import { useOpenSignalGroupCount } from "@/hooks/use-api"
import { SignalsTab } from "@/components/dashboard/correlation/signals-tab"
import { GroupsTab } from "@/components/dashboard/correlation/groups-tab"
import { ConfigTab } from "@/components/dashboard/correlation/config-tab"
import { CacheTab } from "@/components/dashboard/correlation/cache-tab"

const TABS = ["signals", "groups", "cache", "config"] as const

export default function CorrelationPage() {
  const [activeTab, setActiveTab] = useTabParam(TABS)
  const openGroupCount = useOpenSignalGroupCount()

  return (
    <div className="space-y-6">
      <PageHeader
        title="Correlation"
        description="Combine signals from several detectors before mitigating, and review how each group reached its confidence."
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="signals">Signals</TabsTrigger>
          <TabsTrigger value="groups">
            Groups
            {openGroupCount > 0 && (
              <Badge variant="secondary" aria-label={`${openGroupCount} open`}>{openGroupCount}</Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="cache">Cache</TabsTrigger>
          <TabsTrigger value="config">Configuration</TabsTrigger>
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
  )
}
