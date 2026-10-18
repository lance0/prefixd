"use client"

import { PageHeader } from "@/components/dashboard/page-header"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import { ActivityFeedLive } from "@/components/dashboard/activity-feed-live"
import { ActiveMitigationsMini } from "@/components/dashboard/active-mitigations-mini"
import { MitigationActivityChart } from "@/components/dashboard/mitigation-activity-chart"
import { useMitigations } from "@/hooks/use-api"

export default function OverviewPage() {
  const { data, error, isLoading, mutate } = useMitigations({ status: ["active", "escalated"], limit: 50 })

  return (
    <div className="space-y-6">
      <PageHeader title="Mitigation workspace" description="Review active intent, its signals and remaining lifetime." />

      <BgpSessionStatus />

      <ActiveMitigationsMini
        mitigations={data?.mitigations ?? []}
        loading={isLoading}
        error={Boolean(error)}
        hasMore={data?.has_more}
        onRetry={() => { void mutate() }}
      />

      <section aria-label="History" className="grid gap-6 xl:grid-cols-2">
        <MitigationActivityChart />
        <ActivityFeedLive />
      </section>
    </div>
  )
}
