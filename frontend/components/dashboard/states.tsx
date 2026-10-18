import type { ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"

// Shared panel states. A failed fetch must never render as an empty list, so
// "no data" and "could not load" are separate components with separate copy.

interface EmptyStateProps {
  title: string
  /** What will appear here, or how to widen a filtered view. */
  description?: string
  /** One next step, e.g. a link or button. */
  action?: ReactNode
}

export function EmptyState({ title, description, action }: EmptyStateProps) {
  return (
    <div className="space-y-1 p-6 text-sm">
      <p className="font-medium">{title}</p>
      {description ? <p className="text-muted-foreground text-pretty">{description}</p> : null}
      {action ? <div className="pt-2">{action}</div> : null}
    </div>
  )
}

interface ErrorStateProps {
  /** What failed, e.g. "Unable to load mitigations". */
  title: string
  /** What it means and what to do; never imply that no data exists. */
  detail?: string
  onRetry?: () => void
  retryLabel?: string
}

export function ErrorState({ title, detail, onRetry, retryLabel = "Retry" }: ErrorStateProps) {
  return (
    <div role="alert" className="space-y-1 p-6 text-sm">
      <p className="font-medium">{title}</p>
      {detail ? <p className="text-muted-foreground text-pretty">{detail}</p> : null}
      {onRetry ? (
        <div className="pt-2">
          <Button variant="outline" size="sm" onClick={onRetry}>{retryLabel}</Button>
        </div>
      ) : null}
    </div>
  )
}

/** Skeleton rows shaped like the table they replace, so content does not shift on load. */
export function LoadingRows({ label, rows = 3 }: { label: string; rows?: number }) {
  return (
    <div role="status" aria-label={label} className="divide-y">
      {Array.from({ length: rows }, (_, row) => (
        <div key={row} className="flex gap-6 px-4 py-3">
          <Skeleton className="h-5 w-1/4" />
          <Skeleton className="h-5 flex-1" />
          <Skeleton className="h-5 w-16" />
        </div>
      ))}
    </div>
  )
}
