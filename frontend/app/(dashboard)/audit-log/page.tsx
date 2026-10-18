import { Suspense } from "react"
import { AuditLogContentLive } from "@/components/dashboard/audit-log-content-live"
import { PageHeader } from "@/components/dashboard/page-header"
import { LoadingRows } from "@/components/dashboard/states"

export default function AuditLogPage() {
  return (
    <div className="space-y-6">
      <PageHeader title="Audit log" description="Who changed mitigation intent and configuration, and why." />
      <Suspense fallback={<div className="rounded-md border bg-card"><LoadingRows label="Loading audit log" rows={5} /></div>}>
        <AuditLogContentLive />
      </Suspense>
    </div>
  )
}
