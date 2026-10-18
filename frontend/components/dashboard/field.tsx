import type { ReactNode } from "react"
import { cn } from "@/lib/utils"

/** A label/value list. Values are sans unless they are machine identifiers. */
export function FieldList({ children, className }: { children: ReactNode; className?: string }) {
  return <dl className={cn("grid gap-x-6 gap-y-3 sm:grid-cols-2", className)}>{children}</dl>
}

export function Field({ label, children, className }: { label: ReactNode; children: ReactNode; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <dt className="text-xs text-muted-foreground">{label}</dt>
      <dd className="mt-0.5 break-words text-sm">{children}</dd>
    </div>
  )
}
