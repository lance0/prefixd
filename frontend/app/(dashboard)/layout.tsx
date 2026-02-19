import { RequireAuth } from "@/components/require-auth"
import { WebSocketProvider } from "@/components/websocket-provider"
import { ErrorBoundary } from "@/components/error-boundary"

export default function DashboardGroupLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <RequireAuth>
      <WebSocketProvider>
        <ErrorBoundary>
          {children}
        </ErrorBoundary>
      </WebSocketProvider>
    </RequireAuth>
  )
}
