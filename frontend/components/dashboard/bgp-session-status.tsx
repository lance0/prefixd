"use client"

import { motion } from "motion/react"
import { useHealth, usePops } from "@/hooks/use-api"
import { cn } from "@/lib/utils"
import { useReducedMotion } from "@/hooks/use-reduced-motion"

export function BgpSessionStatus() {
  const { data: health, error } = useHealth()
  const { data: pops } = usePops()
  const reducedMotion = useReducedMotion()

  const isUp = health?.bgp_session_up ?? false
  const shouldAnimate = isUp && !reducedMotion

  return (
    <div className="border border-border bg-card p-4">
      <h3 className="text-xs font-mono uppercase tracking-wide text-muted-foreground mb-3">System Status</h3>
      <div className="flex flex-wrap gap-2">
        <div className="group relative flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
          {shouldAnimate ? (
            <motion.span
              className="size-1.5 bg-primary"
              animate={{ opacity: [1, 0.4, 1] }}
              transition={{ duration: 2, repeat: Infinity, ease: "easeInOut" }}
            />
          ) : (
            <span className={cn("size-1.5", isUp ? "bg-primary" : "bg-destructive")} />
          )}
          <span className="font-mono text-xs text-foreground">BGP</span>
          <span className={cn("text-[10px] font-mono uppercase", isUp ? "text-primary" : "text-destructive")}>
            {isUp ? "UP" : error ? "ERROR" : "DOWN"}
          </span>
        </div>

        {health && (
          <div className="group relative flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
            <span className="size-1.5 bg-primary" />
            <span className="font-mono text-xs text-foreground">DB</span>
            <span className="text-[10px] font-mono uppercase text-primary">
              {health.database === "connected" ? "OK" : "ERR"}
            </span>
          </div>
        )}

        {health && (
          <div className="group relative flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
            <span className="font-mono text-xs text-muted-foreground tabular-nums">
              {health.active_mitigations} active
            </span>
          </div>
        )}

        {pops && pops.length > 1 && (
          <div className="flex items-center gap-2 bg-secondary px-3 py-2 border border-border">
            <span className="font-mono text-xs text-muted-foreground">
              {pops.length} POPs
            </span>
          </div>
        )}
      </div>
    </div>
  )
}
