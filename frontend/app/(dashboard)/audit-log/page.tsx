import { Suspense } from "react"
import { AuditLogContentLive } from "@/components/dashboard/audit-log-content-live"
import { RefreshCw } from "lucide-react"

function LoadingState() {
  return (
    <div className="bg-card border border-border rounded-lg p-8 text-center">
      <RefreshCw className="h-8 w-8 mx-auto mb-2 animate-spin text-muted-foreground" />
      <p className="text-muted-foreground">Loading audit log...</p>
    </div>
  )
}

export default function AuditLogPage() {
  return (
    <>
      <Suspense fallback={<LoadingState />}>
        <AuditLogContentLive />
      </Suspense>
    </>
  )
}
