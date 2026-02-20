"use client"

import { Suspense } from "react"
import { useSearchParams } from "next/navigation"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"
import { RefreshCw } from "lucide-react"

function LoadingState() {
  return (
    <div className="bg-card border border-border rounded-lg p-8 text-center">
      <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-muted-foreground" />
      <p className="text-muted-foreground">Loading mitigations...</p>
    </div>
  )
}

export default function MitigationsPage() {
  const searchParams = useSearchParams()
  const ipSearch = searchParams.get("ip")
  const openMitigate = searchParams.get("mitigate") === "true"

  return (
    <DashboardLayout>
      <Suspense fallback={<LoadingState />}>
        <MitigationsContentLive initialSearch={ipSearch} initialMitigateOpen={openMitigate} />
      </Suspense>
    </DashboardLayout>
  )
}
