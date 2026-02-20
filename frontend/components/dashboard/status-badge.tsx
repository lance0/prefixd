"use client"

import { motion } from "motion/react"
import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/use-reduced-motion"

interface StatusBadgeProps {
  status: "pending" | "active" | "escalated" | "expired" | "withdrawn" | "rejected"
  size?: "sm" | "default"
}

export function StatusBadge({ status, size = "default" }: StatusBadgeProps) {
  const reducedMotion = useReducedMotion()
  const isPositive = status === "active"
  const isNegative = status === "escalated" || status === "rejected"
  const isPending = status === "pending"
  const isInactive = status === "expired" || status === "withdrawn"

  const shouldPulse = isPositive && !reducedMotion

  return (
    <span
      className={cn(
        "inline-flex items-center border font-mono uppercase tracking-wide",
        size === "sm" ? "px-1.5 py-0.5 text-[10px]" : "px-2 py-1 text-[10px]",
        isPositive && "border-primary/50 text-primary bg-primary/5",
        isNegative && "border-destructive/50 text-destructive bg-destructive/5",
        isPending && "border-warning/50 text-warning bg-warning/5",
        isInactive && "border-border text-muted-foreground bg-muted/50",
      )}
    >
      {shouldPulse ? (
        <motion.span
          className="mr-1.5 size-1.5 bg-primary"
          animate={{ scale: [1, 1.3, 1] }}
          transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
        />
      ) : (
        <span
          className={cn(
            "mr-1.5 size-1.5",
            isPositive && "bg-primary",
            isNegative && "bg-destructive",
            isPending && "bg-warning",
            isInactive && "bg-muted-foreground",
          )}
        />
      )}
      {status}
    </span>
  )
}
