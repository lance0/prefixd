"use client"

import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { StatCard } from "@/components/dashboard/stat-card"
import { BgpSessionStatus } from "@/components/dashboard/bgp-session-status"
import { QuotaGauge } from "@/components/dashboard/quota-gauge"
import { ActivityFeedLive } from "@/components/dashboard/activity-feed-live"
import { RequireAuth } from "@/components/require-auth"
import { useStats, useMitigations } from "@/hooks/use-api"
import { useWebSocket } from "@/hooks/use-websocket"

export default function OverviewPage() {
  const { data: stats } = useStats()
  const { data: mitigations } = useMitigations({ status: ["active", "escalated"] })
  
  // Connect to WebSocket for real-time updates
  useWebSocket()

  const activeMitigations = mitigations?.filter((m) => m.status === "active" || m.status === "escalated") || []
  const policeActions = activeMitigations.filter((m) => m.action_type === "police")
  const discardActions = activeMitigations.filter((m) => m.action_type === "discard")

  return (
    <RequireAuth>
      <DashboardLayout>
        <div className="space-y-4">
          <BgpSessionStatus />

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard title="Active Mitigations" value={stats?.active_mitigations ?? activeMitigations.length} />
            <StatCard title="Police Actions" value={policeActions.length} accent="primary" />
            <StatCard title="Discard Actions" value={discardActions.length} accent="destructive" />
            <StatCard title="Events (24h)" value={stats?.events_24h ?? 0} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
            <QuotaGauge
              title="Global Quota"
              current={stats?.active_mitigations ?? 0}
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
    </RequireAuth>
  )
}
