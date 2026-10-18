import type { Mitigation } from "@/lib/api"
import { StatusPill, mitigationTone } from "./status-pill"

export function StatusBadge({ status }: { status: Mitigation["status"] }) {
  return <StatusPill tone={mitigationTone(status)}>{status}</StatusPill>
}
