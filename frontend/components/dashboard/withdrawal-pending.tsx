import { RefreshCw } from "lucide-react"
import { useTimeFormat } from "@/components/time-zone-provider"
import type { WithdrawalPending } from "@/lib/api"
import { StatusPill } from "./status-pill"

/** The recorded requester, reason and last attempt error, for a hover title. */
export function withdrawalPendingDetail(pending: WithdrawalPending): string {
  const base = `Requested by ${pending.actor}: ${pending.reason}`

  return pending.last_error ? `${base}. Last error: ${pending.last_error}` : base
}

/**
 * A still-pending durable withdrawal. The row's stored status is not the whole
 * story: an expired rule keeps this state until the speaker confirms the delete.
 */
export function WithdrawalPendingPill({ pending, now }: { pending?: WithdrawalPending | null; now: number }) {
  const { formatTime } = useTimeFormat()

  if (!pending) return null

  return (
    <StatusPill
      tone="warning"
      icon={<RefreshCw aria-hidden="true" />}
      className="whitespace-normal text-left"
    >
      <span title={withdrawalPendingDetail(pending)}>
        Withdrawal retrying since <time dateTime={pending.requested_at}>{formatTime(pending.requested_at, now)}</time>
      </span>
    </StatusPill>
  )
}
