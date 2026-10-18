"use client"

import { Suspense } from "react"
import { useSearchParams } from "next/navigation"
import { MitigationsContentLive } from "@/components/dashboard/mitigations-content-live"
import { PageHeader } from "@/components/dashboard/page-header"
import { LoadingRows } from "@/components/dashboard/states"

export default function MitigationsPage() {
  const searchParams = useSearchParams()
  const ipSearch = searchParams.get("ip")
  const openMitigate = searchParams.get("mitigate") === "true"

  return (
    <div className="space-y-6">
      <PageHeader
        title="Mitigations"
        description="FlowSpec intent for this POP. Withdrawal is recorded locally; router convergence is not verified here."
      />
      <Suspense fallback={<div className="rounded-md border bg-card"><LoadingRows label="Loading mitigations" rows={5} /></div>}>
        <MitigationsContentLive initialSearch={ipSearch} initialMitigateOpen={openMitigate} />
      </Suspense>
    </div>
  )
}
