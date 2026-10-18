import { RequireAuth } from "@/components/require-auth"
import { WebSocketProvider } from "@/components/websocket-provider"
import { ErrorBoundary } from "@/components/error-boundary"
import { DashboardLayout } from "@/components/dashboard/dashboard-layout"

// One shell for every dashboard route: it stays mounted across navigation,
// and a page error renders inside the chrome instead of replacing it.
export default function DashboardGroupLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <RequireAuth>
      <WebSocketProvider>
        <DashboardLayout>
          <ErrorBoundary>
            {children}
          </ErrorBoundary>
        </DashboardLayout>
      </WebSocketProvider>
    </RequireAuth>
  )
}
