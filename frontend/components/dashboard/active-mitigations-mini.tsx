"use client"

import Link from "next/link"
import { ArrowRight } from "lucide-react"
import { StatusBadge } from "./status-badge"
import { ActionBadge } from "./action-badge"
import { cn } from "@/lib/utils"
import type { Mitigation } from "@/lib/api"

interface ActiveMitigationsMiniProps {
  mitigations: Mitigation[]
  limit?: number
}

function formatTimeRemaining(expiresAt: string): string {
  const now = new Date()
  const expires = new Date(expiresAt)
  const diffMs = expires.getTime() - now.getTime()
  
  if (diffMs <= 0) return "expired"
  
  const mins = Math.floor(diffMs / 60000)
  if (mins < 60) return `${mins}m`
  
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ${mins % 60}m`
  
  const days = Math.floor(hours / 24)
  return `${days}d ${hours % 24}h`
}

export function ActiveMitigationsMini({ mitigations, limit = 5 }: ActiveMitigationsMiniProps) {
  const active = mitigations
    .filter((m) => m.status === "active" || m.status === "escalated")
    .slice(0, limit)

  return (
    <div className="border border-border bg-card p-4 h-full flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-mono uppercase text-muted-foreground text-balance">
          Active Mitigations
        </h3>
        <Link
          href="/mitigations?status=active"
          className="text-xs text-primary hover:underline flex items-center gap-1"
        >
          View all
          <ArrowRight className="size-3" />
        </Link>
      </div>
      
      {active.length === 0 ? (
        <div className="flex-1 flex items-center justify-center text-muted-foreground text-xs">
          No active mitigations
        </div>
      ) : (
        <div className="space-y-0 flex-1">
          {active.map((m, index) => (
            <div
              key={m.mitigation_id}
              className={cn(
                "flex items-center justify-between py-2",
                index !== active.length - 1 && "border-b border-border/50"
              )}
            >
              <div className="flex items-center gap-3 min-w-0">
                <StatusBadge status={m.status} size="sm" />
                <div className="min-w-0">
                  <div className="font-mono text-xs text-foreground truncate">
                    {m.victim_ip}
                  </div>
                  <div className="text-[10px] text-muted-foreground">
                    {m.vector.replace(/_/g, " ")}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 flex-shrink-0">
                <ActionBadge actionType={m.action_type} rateBps={m.rate_bps} size="sm" />
                <span className="text-[10px] font-mono text-muted-foreground tabular-nums w-12 text-right">
                  {formatTimeRemaining(m.expires_at)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
