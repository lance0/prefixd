import type { ScrubberDiversion, ScrubberState } from "@/lib/api"

// Event ingestion is not a frame type: event lists keep their API refresh.
export type WsMessageType =
  | "mitigation_created"
  | "mitigation_updated"
  | "mitigation_expired"
  | "mitigation_withdrawn"
  | "diversion_updated"
  | "scrubber_updated"
  | "resync_required"

export interface WsMessage {
  type: WsMessageType
  // mitigation_created / mitigation_updated
  mitigation?: {
    mitigation_id: string
    status: string
    customer_id: string | null
    victim_ip: string
    vector: string
    action_type: string
    rate_bps: number | null
    created_at: string
    expires_at: string
    scope_hash: string
  }
  // mitigation_expired / mitigation_withdrawn
  mitigation_id?: string
  diversion?: ScrubberDiversion
  profile?: string
  state?: ScrubberState
}

export type ConnectionState = "connecting" | "connected" | "polling" | "disconnected" | "error"
