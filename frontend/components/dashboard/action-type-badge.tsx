import { cn } from "@/lib/utils"

interface ActionTypeBadgeProps {
  action: string
}

export function ActionTypeBadge({ action }: ActionTypeBadgeProps) {
  const normalized = action.toLowerCase()
  const isPositive =
    normalized === "announce" ||
    normalized === "create" ||
    normalized === "extend" ||
    normalized === "ingest" ||
    normalized === "safelist_add"
  const isNegative = normalized === "reject" || normalized === "escalate"

  return (
    <span
      className={cn(
        "inline-flex items-center border px-2 py-0.5 text-[10px] font-mono uppercase tracking-wide",
        isPositive && "border-primary/30 text-primary bg-primary/5",
        isNegative && "border-destructive/30 text-destructive bg-destructive/5",
        !isPositive && !isNegative && "border-border text-muted-foreground bg-muted/50",
      )}
    >
      {action}
    </span>
  )
}
