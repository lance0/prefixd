import type { EventResponse } from "@/lib/api"

export type WsMessageType =
  | "mitigation_created"
  | "mitigation_updated"
  | "mitigation_expired"
  | "mitigation_withdrawn"
  | "event_ingested"
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
  // event_ingested
  event?: EventResponse
}

export type ConnectionState = "connecting" | "connected" | "polling" | "disconnected" | "error"
