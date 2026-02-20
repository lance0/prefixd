"use client"

import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { StatCard } from "@/components/dashboard/stat-card"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import { QuotaGauge } from "@/components/dashboard/quota-gauge"
import { ActivityFeedLive } from "@/components/dashboard/activity-feed-live"
import { VectorBreakdownChart } from "@/components/dashboard/vector-breakdown-chart"
import { ActiveMitigationsMini } from "@/components/dashboard/active-mitigations-mini"
import { MitigationActivityChart } from "@/components/dashboard/mitigation-activity-chart"
import { useStats, useMitigations } from "@/hooks/use-api"

export default function OverviewPage() {
  const { data: stats } = useStats()
  const { data: mitigations } = useMitigations({ status: ["active", "escalated"], limit: 50 })
  
  const activeMitigations = mitigations?.filter((m) => m.status === "active" || m.status === "escalated") || []
  const policeActions = activeMitigations.filter((m) => m.action_type === "police")
  const discardActions = activeMitigations.filter((m) => m.action_type === "discard")

  return (
      <DashboardLayout>
        <div className="space-y-4">
          <BgpSessionStatus />

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard title="Active Mitigations" value={stats?.total_active ?? activeMitigations.length} href="/mitigations" />
            <StatCard title="Police Actions" value={policeActions.length} accent="primary" href="/mitigations" />
            <StatCard title="Discard Actions" value={discardActions.length} accent="destructive" href="/mitigations" />
            <StatCard title="Total Events" value={stats?.total_events ?? 0} href="/events" />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            <VectorBreakdownChart mitigations={activeMitigations} />
            <div className="lg:col-span-2">
              <ActiveMitigationsMini mitigations={activeMitigations} />
            </div>
          </div>

          <MitigationActivityChart />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            <QuotaGauge
              title="Global Quota"
              current={stats?.total_active ?? 0}
              max={500}
              secondary={{
                title: "Total Events",
                current: stats?.total_events ?? 0,
                max: 10000,
              }}
            />
            <div className="lg:col-span-2">
              <ActivityFeedLive />
            </div>
          </div>
        </div>
      </DashboardLayout>
  )
}
