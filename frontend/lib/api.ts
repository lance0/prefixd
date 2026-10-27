import { parseDestination } from "./destination"

// Use relative URL to proxy through Next.js API route
// This allows the dashboard to work on any host without hardcoded URLs
const API_BASE = "/api/prefixd"

// Cache for deduplicating in-flight requests (client-swr-dedup pattern)
const requestCache = new Map<string, Promise<unknown>>()

// Debounce auth-expired events: only dispatch once per 2s window
let authExpiredTimer: ReturnType<typeof setTimeout> | null = null

function dispatchAuthExpired() {
  if (authExpiredTimer) return
  authExpiredTimer = setTimeout(() => { authExpiredTimer = null }, 2000)
  window.dispatchEvent(new CustomEvent("prefixd:auth-expired"))
}

/** A decoded JSON value, for payloads the dashboard displays without interpreting. */
export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

export interface CorrelationContext {
  signal_group_id: string
  derived_confidence: number
  source_count: number
  corroboration_met: boolean
  /** Populated on detail endpoint only (null/absent on list endpoint) */
  contributing_sources?: string[] | null
  /** Human-readable explanation (populated on detail endpoint only) */
  explanation?: string | null
}

export type AnnouncementOutcome = "unconfirmed"

/** Next hop and communities frozen into a blackhole at admission: saved intent, not router state. */
export interface BlackholeRoute {
  next_hop: string
  /** `ASN:value`, always including BLACKHOLE `65535:666`. */
  communities: string[]
  large_communities: string[]
}

/**
 * A mitigation's export toward one Established peer. `committed` means the
 * speaker holds it in that peer's Adj-RIB-Out: not receipt, installation or
 * enforcement, which BGP does not report.
 */
export type ExportDisposition = "committed" | "withheld" | "pending"

export interface PeerExport {
  peer_address: string
  disposition: ExportDisposition
  /** Bounded speaker code, e.g. `export_policy`; empty when committed. */
  reason: string
  explain_code: string
  /** Speaker text; not stable. */
  detail: string
  advertised_path_id: number
}

export interface ExportWarning {
  reason: string
  message: string
}

export interface DispositionCounts {
  committed: number
  withheld: number
  pending: number
}

/** Shared export evidence for active rules, excluding those recorded as dry-run. */
export interface BlackholeExportEvidence {
  /** `error` means current export is unknown; historical rows may remain. */
  status: "observed" | "no_local_route" | "error" | "unsupported" | "not_observed"
  /** Retained evidence from before the controller last lost ownership. */
  historical: boolean
  observed_at: string | null
  peers: PeerExport[]
  /** Null when sessions were not observed: unknown, not none. */
  not_established_peers: { peer_address: string; state: string }[] | null
  counts: DispositionCounts
  warning: ExportWarning | null
  error: string | null
}

export type FragmentMatch = "non_first"

export interface PacketLengthRange {
  min: number
  max: number
}

export interface Mitigation {
  /** This creation request had no successful speaker reply; not persisted status. */
  announcement_outcome?: AnnouncementOutcome
  mitigation_id: string
  scope_hash: string
  status: "pending" | "active" | "escalated" | "expired" | "withdrawn" | "rejected"
  customer_id: string | null
  service_id: string | null
  pop: string
  victim_ip: string
  vector: string
  action_type: "police" | "discard" | "blackhole"
  rate_bps: number | null
  dst_prefix: string
  /** Source CIDR; null or absent means no source constraint. */
  src_prefix?: string | null
  protocol: number | null
  dst_ports: number[]
  /** UDP source ports (ADR 028), sorted; absent from controllers that predate them. */
  src_ports?: number[]
  /** `non_first` when the rule matches non-first IP fragments. */
  fragment?: FragmentMatch | null
  /** Inclusive total IP packet length. */
  packet_length?: PacketLengthRange | null
  created_at: string
  updated_at: string
  expires_at: string
  withdrawn_at: string | null
  triggering_event_id: string
  last_event_id: string
  reason: string
  acknowledged_at: string | null
  acknowledged_by: string | null
  /** Mode that admitted this row; null (or absent from older controllers) is unknown, not enforced. */
  origin_mode?: "dry-run" | "enforced" | null
  /** Correlation context (present when mitigation was created via corroboration) */
  correlation?: CorrelationContext | null
  /** Present only for a blackhole, which drops all traffic to the victim. */
  blackhole?: BlackholeRoute | null
  /** Detail endpoint only, on active mitigations excluding those recorded as dry-run. */
  export_evidence?: BlackholeExportEvidence | null
}

export interface PaginatedResponse<T> {
  count: number
  next_cursor: string | null
  has_more: boolean
  items: T[]
}

export interface Event {
  event_id: string
  external_event_id: string | null
  source: string
  event_timestamp: string
  ingested_at: string
  victim_ip: string
  vector: string
  protocol: number | null
  bps: number | null
  pps: number | null
  top_dst_ports_json: string
  /** Absent or null when the detector sent no source ports; "[]" when it sent an empty list. */
  top_src_ports_json?: string | null
  confidence: number | null
}

export interface Stats {
  total_active: number
  total_mitigations: number
  total_events: number
  pops: PopStats[]
}

export interface PopStats {
  pop: string
  active: number
  total: number
}

export interface PopInfo {
  pop: string
  active_mitigations: number
  total_mitigations: number
}

export interface PublicHealthResponse {
  status: string
  version: string
  auth_mode: string
}

export interface HealthResponse {
  status: string
  version: string
  pop: string
  uptime_seconds: number
  bgp_sessions: Record<string, string>
  active_mitigations: number
  database: string
  gobgp: {
    status: string
    error?: string
  }
  auth_mode: string
  speaker?: {
    backend: string
    daemon?: {
      status: "observed" | "error" | "unsupported"
      version: string | null
      uptime_seconds: number | null
      ready: boolean | null
      observed_at: string | null
    }
    capabilities: {
      rule_reader: boolean
      peer_observer: boolean
      daemon_health?: boolean
      blackhole_export?: boolean
      flowspec_export?: boolean
      flowspec_match?: {
        source_prefix?: boolean
        source_ports?: boolean
        fragment?: boolean
        packet_length?: boolean
      }
    }
    /** Present when the speaker reports blackhole export. */
    blackhole_exports?: {
      historical: boolean
      observed_at: string | null
      blackholes: number
      counts: DispositionCounts
      errors: number
      no_local_route: number
      unexported: ({ mitigation_id: string; prefix: string } & ExportWarning)[]
    }
    /** Present when the speaker reports exact-key FlowSpec export. */
    flowspec_exports?: {
      historical: boolean
      observed_at: string | null
      rules: number
      counts: DispositionCounts
      errors: number
      no_local_route: number
      unexported: ({ mitigation_id: string; prefix: string } & ExportWarning)[]
    }
  }
  // True only after successful observation of at least one peer, all established.
  bgp_session_up: boolean
}

export interface SafelistEntry {
  prefix: string
  reason: string | null
  added_by: string
  added_at: string
  expires_at: string | null
}

async function fetchApi<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...options?.headers,
  }

  const url = `${API_BASE}${endpoint}`
  const method = options?.method || "GET"
  
  // Only cache GET requests (client-swr-dedup pattern)
  if (method === "GET") {
    const cacheKey = url
    const cached = requestCache.get(cacheKey)

    if (cached) {
      // SAFETY: the key is the request URL, and every endpoint is read with one response type.
      return cached as Promise<T>
    }
    
    const promise = doFetch<T>(url, { ...options, headers }).finally(() => {
      requestCache.delete(cacheKey)
    })

    requestCache.set(cacheKey, promise)
    
    return promise
  }

  return doFetch<T>(url, { ...options, headers })
}

/** HTTP errors use the existing API error prefix; transport errors have no status. */
export function apiErrorStatus(error: Error): number | null {
  const match = /^API error (\d{3}):/.exec(error.message)

  return match ? Number(match[1]) : null
}

/** True only for a 404 from the API, so a failed request is never shown as "not found". */
export function isNotFound(error: Error): boolean {
  return error.message.startsWith("API error 404:")
}

async function doFetch<T>(url: string, options: RequestInit): Promise<T> {
  const res = await fetch(url, {
    ...options,
    credentials: "include", // Send session cookies for hybrid auth
  })

  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined") {
      dispatchAuthExpired()
    }

    const error = await res.text()
    throw new Error(`API error ${res.status}: ${error}`)
  }

  const text = await res.text()

  // SAFETY: T is the controller's documented response type for this endpoint. The
  // dashboard trusts its own controller and does not re-validate responses.
  return (text.trim() ? JSON.parse(text) : null) as T
}

export async function getHealth(): Promise<PublicHealthResponse> {
  return fetchApi<PublicHealthResponse>("/v1/health")
}

export async function getHealthDetail(): Promise<HealthResponse> {
  const data = await fetchApi<Omit<HealthResponse, 'bgp_session_up'>>("/v1/health/detail")
  const sessions = Object.values(data.bgp_sessions ?? {})

  return {
    ...data,
    bgp_session_up: data.gobgp.status === "connected" && sessions.length > 0 && sessions.every((s) => s === "established"),
  }
}

export async function getStats(): Promise<Stats> {
  return fetchApi<Stats>("/v1/stats")
}

export interface LocalFlowSpecRule {
  nlri: {
    dst_prefix: string
    src_prefix?: string | null
    protocol: number | null
    dst_ports: number[]
    src_ports?: number[]
    fragment?: FragmentMatch | null
    packet_length?: PacketLengthRange | null
  }
  actions: { action_type: "police" | "discard"; rate_bps?: number }[]
  /** Injection identity only; absent or empty does not establish controller ownership. */
  owner?: string
}

export interface SpeakerRoutesResponse {
  backend: string
  observation_scope: "retained_local_flow_spec_intent" | "accepted_local_flow_spec_rib" | "adapter_local_flow_spec"
  routes: LocalFlowSpecRule[]
}

export async function getSpeakerRoutes(): Promise<SpeakerRoutesResponse> {
  return fetchApi<SpeakerRoutesResponse>("/v1/speaker/routes")
}

export interface MitigationsResponse {
  mitigations: Mitigation[]
  count: number
  next_cursor: string | null
  has_more: boolean
}

export async function getMitigations(params?: {
  status?: string[]
  customer_id?: string
  victim_ip?: string
  pop?: string
  acknowledged?: boolean
  limit?: number
  cursor?: string
  start?: string
  end?: string
}): Promise<MitigationsResponse> {
  const searchParams = new URLSearchParams()

  if (params?.status && params.status.length > 0) {
    searchParams.set("status", params.status.join(","))
  }

  if (params?.customer_id) searchParams.set("customer_id", params.customer_id)

  if (params?.victim_ip) searchParams.set("victim_ip", params.victim_ip)

  if (params?.pop) searchParams.set("pop", params.pop)

  if (params?.acknowledged !== undefined) searchParams.set("acknowledged", params.acknowledged.toString())

  if (params?.limit) searchParams.set("limit", params.limit.toString())

  if (params?.cursor) searchParams.set("cursor", params.cursor)

  if (params?.start) searchParams.set("start", params.start)

  if (params?.end) searchParams.set("end", params.end)

  const query = searchParams.toString()

  return fetchApi<MitigationsResponse>(`/v1/mitigations${query ? `?${query}` : ""}`)
}

export async function getMitigation(id: string): Promise<Mitigation> {
  return fetchApi<Mitigation>(`/v1/mitigations/${id}`)
}

export async function withdrawMitigation(
  id: string,
  reason: string,
  operator: string
): Promise<void> {
  await fetchApi(`/v1/mitigations/${id}/withdraw`, {
    method: "POST",
    body: JSON.stringify({ reason, operator_id: operator }),
  })
}

export interface CreateBlackholeRequest {
  victim_ip: string
  /** Must exactly equal `victim_ip`; the controller returns 400 otherwise. */
  confirm_victim_ip: string
  reason: string
  ttl_seconds: number
}

/** Admin-only manual blackhole (ADR 027). Bearer tokens and Operator sessions get 403. */
export async function createBlackhole(request: CreateBlackholeRequest): Promise<Mitigation> {
  return fetchApi<Mitigation>("/v1/mitigations", {
    method: "POST",
    body: JSON.stringify({ ...request, action: "blackhole" }),
  })
}

export interface CreateFlowSpecRequest {
  /** IP or aligned destination CIDR; subnet admission requires configured prefix bounds and ownership. */
  victim_ip: string
  /** Same-family source CIDR; requires guardrails.allow_src_prefix_match. */
  src_prefix?: string
  /** udp, tcp, icmp, icmpv6 or any. Source ports, fragment and packet length need udp. */
  protocol: string
  action: "discard" | "police"
  rate_bps?: number
  ttl_seconds: number
  reason: string
  dst_ports?: number[]
  src_ports?: number[]
  fragment?: FragmentMatch
  packet_length?: PacketLengthRange
}

export interface FlowSpecAdmissionPreview {
  outcome: "admissible" | "refused" | "unavailable"
  checked_at: string
  mode: "dry-run" | "enforced"
  speaker_state: "unobserved"
  candidate: {
    victim_ip: string
    customer_id: string | null
    service_id: string | null
    pop: string
    scope: {
      dst_prefix: string
      src_prefix?: string | null
      protocol: number | null
      dst_ports: number[]
      src_ports?: number[]
      fragment?: FragmentMatch | null
      packet_length?: PacketLengthRange | null
    }
    action: { action_type: "discard" | "police"; rate_bps?: number | null }
    ttl_seconds: number
    expires_at_cap: string | null
  } | null
  failed_check: "input" | "target" | "ownership" | "safelist" | "guardrails" | "creation_rate" | "capability" | "lifetime" | "timeout" | null
  reason: string | null
}

function isRecord(value: JsonValue | undefined): value is { [key: string]: JsonValue } {
  return value instanceof Object && !Array.isArray(value)
}

/** JSON.parse supplies only JSON values; boxed primitive identity distinguishes text. */
function isText(value: JsonValue | undefined): value is string {
  return Object(value) instanceof String
}

function isWholeNumber(value: JsonValue | undefined): value is number {
  return Number.isSafeInteger(value)
}

function isPortList(value: JsonValue | undefined): value is number[] {
  return Array.isArray(value) && value.every((port: JsonValue) => isWholeNumber(port) && port >= 0 && port <= 65535)
}

function admissionCandidate(value: JsonValue | undefined): FlowSpecAdmissionPreview["candidate"] | undefined {
  if (value === null) return null

  if (!isRecord(value) || !isText(value.victim_ip) || !value.victim_ip ||
    !(value.customer_id === null || isText(value.customer_id)) ||
    !(value.service_id === null || isText(value.service_id)) ||
    !isText(value.pop) || !value.pop ||
    !isWholeNumber(value.ttl_seconds) || value.ttl_seconds < 0 ||
    !(value.expires_at_cap === null || (isText(value.expires_at_cap) && Number.isFinite(Date.parse(value.expires_at_cap)))) ||
    !isRecord(value.scope) || !isRecord(value.action)) return undefined

  const scope = value.scope
  const action = value.action
  const scopeKeys = ["dst_prefix", "src_prefix", "protocol", "dst_ports", "src_ports", "fragment", "packet_length"]

  // A future match component must not be silently dropped from an operator preview.
  if (Object.keys(scope).some((key) => !scopeKeys.includes(key)) ||
    Object.keys(action).some((key) => key !== "action_type" && key !== "rate_bps") ||
    !isText(scope.dst_prefix) || !scope.dst_prefix ||
    !(scope.src_prefix === undefined || scope.src_prefix === null || isText(scope.src_prefix)) ||
    !(scope.protocol === null || (isWholeNumber(scope.protocol) && scope.protocol >= 0 && scope.protocol <= 255)) ||
    !isPortList(scope.dst_ports) || !(scope.src_ports === undefined || isPortList(scope.src_ports)) ||
    !(scope.fragment === undefined || scope.fragment === null || scope.fragment === "non_first") ||
    (action.action_type !== "discard" && action.action_type !== "police") ||
    !(action.rate_bps === undefined || action.rate_bps === null || (isWholeNumber(action.rate_bps) && action.rate_bps > 0))) return undefined

  const destination = parseDestination(scope.dst_prefix)
  const source = isText(scope.src_prefix) ? parseDestination(scope.src_prefix) : null

  if (!destination?.isCidr || !destination.networkAligned ||
    (isText(scope.src_prefix) && (!source?.isCidr || !source.networkAligned || source.ipv6 !== destination.ipv6))) return undefined

  let packetLength: PacketLengthRange | null | undefined

  if (scope.packet_length === undefined || scope.packet_length === null) packetLength = scope.packet_length
  else {
    const length = scope.packet_length

    if (!isRecord(length) || Object.keys(length).some((key) => key !== "min" && key !== "max") || !isWholeNumber(length.min) || !isWholeNumber(length.max) || length.min < 0 || length.max < length.min || length.min > 65535 || length.max > 65535) return undefined
    packetLength = { min: length.min, max: length.max }
  }

  if ((action.action_type === "police" && !(isWholeNumber(action.rate_bps) && action.rate_bps > 0)) ||
    (action.action_type === "discard" && action.rate_bps !== undefined && action.rate_bps !== null)) return undefined

  return {
    victim_ip: value.victim_ip, customer_id: value.customer_id, service_id: value.service_id, pop: value.pop,
    ttl_seconds: value.ttl_seconds, expires_at_cap: value.expires_at_cap,
    scope: {
      dst_prefix: scope.dst_prefix, src_prefix: scope.src_prefix, protocol: scope.protocol,
      dst_ports: scope.dst_ports, src_ports: scope.src_ports, fragment: scope.fragment, packet_length: packetLength,
    },
    action: { action_type: action.action_type, rate_bps: action.rate_bps },
  }
}

/** A malformed, contradictory or newer unsupported result is never shown as passing. */
export function parseFlowSpecAdmissionPreview(value: JsonValue, status: number): FlowSpecAdmissionPreview | null {
  if (!isRecord(value) || !isText(value.checked_at) || !Number.isFinite(Date.parse(value.checked_at)) ||
    (value.mode !== "dry-run" && value.mode !== "enforced") || value.speaker_state !== "unobserved" ||
    (value.reason !== null && !isText(value.reason))) return null

  const outcome = value.outcome

  if (!((outcome === "admissible" && status === 200) ||
    (outcome === "refused" && [400, 409, 422].includes(status)) || (outcome === "unavailable" && status === 503))) return null

  const failedCheck = value.failed_check

  if (!(failedCheck === null || failedCheck === "input" || failedCheck === "target" || failedCheck === "ownership" ||
    failedCheck === "safelist" || failedCheck === "guardrails" || failedCheck === "creation_rate" || failedCheck === "capability" || failedCheck === "lifetime" || failedCheck === "timeout")) return null

  if (failedCheck === "timeout" && outcome !== "unavailable") return null

  const candidate = admissionCandidate(value.candidate)

  if (candidate === undefined || (outcome === "admissible" && (candidate === null || failedCheck !== null || value.reason !== null)) ||
    (outcome !== "admissible" && (failedCheck === null || !value.reason))) return null

  return { outcome, checked_at: value.checked_at, mode: value.mode, speaker_state: "unobserved", candidate, failed_check: failedCheck, reason: value.reason }
}

/** Read-only snapshot. Creation always repeats admission; a preview reserves nothing. */
export async function previewFlowSpecAdmission(request: CreateFlowSpecRequest): Promise<FlowSpecAdmissionPreview> {
  const response = await fetch(`${API_BASE}/v1/mitigations/preview`, {
    method: "POST", credentials: "include", headers: { "Content-Type": "application/json" }, body: JSON.stringify(request),
  })

  if (response.status === 401 && typeof window !== "undefined") dispatchAuthExpired()
  const body = await response.text()
  let result: FlowSpecAdmissionPreview | null = null

  try {
    const value: JsonValue = JSON.parse(body)
    result = parseFlowSpecAdmissionPreview(value, response.status)
  } catch {
    // A proxy, authentication boundary or old controller may return plain text.
  }

  if (result) return result
  throw new Error(response.status === 404
    ? "This controller does not provide admission checks. Upgrade the controller or create the rule with its usual guardrails."
    : `Admission check unavailable (HTTP ${response.status}). Retry the check; no preview result is available.`)
}

/** Manual FlowSpec rule; the controller applies the same guardrails as playbooks. */
export async function createMitigation(request: CreateFlowSpecRequest): Promise<Mitigation> {
  // Older controllers ignore unknown request fields. Never send a source
  // constraint unless a fresh capability read confirms it will be preserved.
  if (request.src_prefix !== undefined) {
    const health = await getHealthDetail()

    if (health.speaker?.capabilities.flowspec_match?.source_prefix !== true) {
      throw new Error("This controller does not support source prefix matching. Upgrade the controller before creating this rule.")
    }
  }

  return fetchApi<Mitigation>("/v1/mitigations", {
    method: "POST",
    body: JSON.stringify(request),
  })
}

export interface ExtendMitigationResponse {
  extended: boolean
  previous_expires_at: string
  mitigation: Mitigation
}

/** Update saved lifetime only; router enforcement remains independently observed. */
export async function extendMitigation(id: string, ttl_seconds: number, reason: string): Promise<ExtendMitigationResponse> {
  return fetchApi<ExtendMitigationResponse>(`/v1/mitigations/${encodeURIComponent(id)}/extend`, {
    method: "POST",
    body: JSON.stringify({ ttl_seconds, reason }),
  })
}

export interface BulkWithdrawResult {
  mitigation_id: string
  status: string
  error?: string
}

export interface BulkWithdrawResponse {
  withdrawn: number
  failed: number
  results: BulkWithdrawResult[]
}

export async function bulkWithdrawMitigations(
  ids: string[],
  reason: string,
  operator: string
): Promise<BulkWithdrawResponse> {
  return fetchApi<BulkWithdrawResponse>("/v1/mitigations/withdraw", {
    method: "POST",
    body: JSON.stringify({ mitigation_ids: ids, reason, operator_id: operator }),
  })
}

export interface BulkAcknowledgeResult {
  mitigation_id: string
  status: string
  error?: string
}

export interface BulkAcknowledgeResponse {
  acknowledged: number
  failed: number
  results: BulkAcknowledgeResult[]
}

export async function bulkAcknowledgeMitigations(
  ids: string[],
  operator: string
): Promise<BulkAcknowledgeResponse> {
  return fetchApi<BulkAcknowledgeResponse>("/v1/mitigations/acknowledge", {
    method: "POST",
    body: JSON.stringify({ mitigation_ids: ids, operator_id: operator }),
  })
}

export interface IngestEventRequest {
  victim_ip: string
  vector: string
  source: string
  timestamp: string
  bps?: number | null
  pps?: number | null
  top_dst_ports?: number[]
  confidence?: number | null
  action?: string
}

export interface EventResponse {
  /** This creation request had no successful speaker reply; not persisted status. */
  announcement_outcome?: AnnouncementOutcome
  event_id: string
  mitigation_id: string | null
  status: string
}

export async function ingestEvent(input: IngestEventRequest): Promise<EventResponse> {
  return fetchApi<EventResponse>("/v1/events", {
    method: "POST",
    body: JSON.stringify(input),
  })
}

export interface EventsResponse {
  events: Event[]
  count: number
  next_cursor: string | null
  has_more: boolean
}

export async function getEvents(params?: {
  limit?: number
  cursor?: string
  start?: string
  end?: string
}): Promise<EventsResponse> {
  const searchParams = new URLSearchParams()

  if (params?.limit) searchParams.set("limit", params.limit.toString())

  if (params?.cursor) searchParams.set("cursor", params.cursor)

  if (params?.start) searchParams.set("start", params.start)

  if (params?.end) searchParams.set("end", params.end)

  const query = searchParams.toString()

  return fetchApi<EventsResponse>(`/v1/events${query ? `?${query}` : ""}`)
}

export interface AuditEntry {
  audit_id: string
  timestamp: string
  schema_version: number
  actor_type: "system" | "detector" | "operator"
  actor_id: string | null
  action: string
  target_type: string | null
  target_id: string | null
  details: AuditDetails
}

/** Action-specific audit context. Fields the dashboard reads are typed; the rest render as JSON. */
export type AuditDetails = { victim_ip?: string; reason?: string; operation_id?: string } & { [key: string]: JsonValue }

export interface AuditResponse {
  entries: AuditEntry[]
  count: number
  next_cursor: string | null
  has_more: boolean
}

export async function getAuditLog(params?: {
  limit?: number
  cursor?: string
  start?: string
  end?: string
}): Promise<AuditResponse> {
  const searchParams = new URLSearchParams()

  if (params?.limit) searchParams.set("limit", params.limit.toString())

  if (params?.cursor) searchParams.set("cursor", params.cursor)

  if (params?.start) searchParams.set("start", params.start)

  if (params?.end) searchParams.set("end", params.end)

  const query = searchParams.toString()

  return fetchApi<AuditResponse>(`/v1/audit${query ? `?${query}` : ""}`)
}

export async function getSafelist(): Promise<SafelistEntry[]> {
  return fetchApi<SafelistEntry[]>("/v1/safelist")
}

export async function addSafelist(
  prefix: string,
  reason: string,
  operator: string
): Promise<void> {
  await fetchApi("/v1/safelist", {
    method: "POST",
    body: JSON.stringify({ prefix, reason, operator_id: operator }),
  })
}

export async function removeSafelist(prefix: string): Promise<void> {
  await fetchApi(`/v1/safelist/${encodeURIComponent(prefix)}`, {
    method: "DELETE",
  })
}

export async function getPops(): Promise<PopInfo[]> {
  return fetchApi<PopInfo[]>("/v1/pops")
}

export async function reloadConfig(): Promise<void> {
  await fetchApi("/v1/config/reload", { method: "POST" })
}

// Parallel fetch for dashboard data (async-parallel pattern)
export async function getDashboardData(): Promise<{
  health: HealthResponse
  stats: Stats
  mitigations: Mitigation[]
}> {
  const [health, stats, mitigationsResp] = await Promise.all([
    getHealthDetail(),
    getStats(),
    getMitigations({ status: ["active", "escalated"], limit: 100 }),
  ])

  return { health, stats, mitigations: mitigationsResp.mitigations }
}

// Operator management (admin only)

export interface OperatorInfo {
  operator_id: string
  username: string
  role: "admin" | "operator" | "viewer"
  created_at: string
  created_by: string | null
  last_login_at: string | null
}

export interface OperatorListResponse {
  operators: OperatorInfo[]
  count: number
}

export async function getOperators(): Promise<OperatorInfo[]> {
  const response = await fetchApi<OperatorListResponse>("/v1/operators")

  return response.operators
}

export async function createOperator(
  username: string,
  password: string,
  role: "admin" | "operator" | "viewer"
): Promise<OperatorInfo> {
  return fetchApi<OperatorInfo>("/v1/operators", {
    method: "POST",
    body: JSON.stringify({ username, password, role }),
  })
}

export async function deleteOperator(id: string): Promise<void> {
  await fetchApi(`/v1/operators/${id}`, { method: "DELETE" })
}

export async function changePassword(
  id: string,
  newPassword: string,
  currentPassword?: string
): Promise<void> {
  const body = currentPassword
    ? { new_password: newPassword, current_password: currentPassword }
    : { new_password: newPassword }

  await fetchApi(`/v1/operators/${id}/password`, {
    method: "PUT",
    body: JSON.stringify(body),
  })
}

// Config endpoints (read-only)

export interface ConfigSettingsResponse {
  settings: { [key: string]: JsonValue }
  loaded_at: string
}

export interface ConfigCustomer {
  customer_id: string
  name: string
  prefixes: string[]
  policy_profile: "strict" | "normal" | "relaxed"
  services: ConfigService[]
}

export interface ConfigService {
  service_id: string
  name: string
  assets: ConfigAsset[]
  allowed_ports: {
    udp?: number[]
    tcp?: number[]
  }
}

export interface ConfigAsset {
  ip: string
  role?: string
}

export interface ConfigInventoryResponse {
  customers: ConfigCustomer[]
  total_customers: number
  total_services: number
  total_assets: number
  loaded_at: string
}

export interface ConfigPlaybook {
  name: string
  match: {
    vector: string
    require_top_ports?: boolean
  }
  /** Per-playbook correlation override; the API sends null when none is set. Editors must round-trip it. */
  correlation?: {
    min_sources?: number | null
    confidence_threshold?: number | null
    confidence_decay_half_life_seconds?: number | null
  } | null
  steps: PlaybookStep[]
}

/**
 * A step has either one `action` or `rules` (ADR 028, udp_amplification only). Editors keep
 * keys this type does not name as sent, so saving never drops a field they do not know.
 */
export interface PlaybookStep {
  action?: "police" | "discard" | "blackhole" | null
  rate_bps?: number | null
  ttl_seconds: number
  rules?: PlaybookRule[] | null
  require_confidence_at_least?: number | null
  require_persistence_seconds?: number | null
}

export interface PlaybookRule {
  match: {
    /** `from_event`: the event's source ports intersected with the reflector-port library. */
    src_ports?: "from_event" | number[]
    fragment?: FragmentMatch
    packet_length?: PacketLengthRange
  }
  action: "police" | "discard"
  rate_bps?: number | null
}

export interface ConfigPlaybooksResponse {
  playbooks: ConfigPlaybook[]
  total_playbooks: number
  loaded_at: string
}

export async function getConfigSettings(): Promise<ConfigSettingsResponse> {
  return fetchApi<ConfigSettingsResponse>("/v1/config/settings")
}

export async function getConfigInventory(): Promise<ConfigInventoryResponse> {
  return fetchApi<ConfigInventoryResponse>("/v1/config/inventory")
}

export async function getConfigPlaybooks(): Promise<ConfigPlaybooksResponse> {
  return fetchApi<ConfigPlaybooksResponse>("/v1/config/playbooks")
}

export async function updatePlaybooks(playbooks: ConfigPlaybook[]): Promise<ConfigPlaybooksResponse> {
  return fetchApi<ConfigPlaybooksResponse>("/v1/config/playbooks", {
    method: "PUT",
    body: JSON.stringify({ playbooks }),
  })
}

// Timeseries

export interface TimeseriesBucket {
  bucket: string
  count: number
}

export interface TimeseriesResponse {
  metric: string
  buckets: TimeseriesBucket[]
}

export async function getTimeseries(params?: {
  metric?: string
  range?: string
  bucket?: string
}): Promise<TimeseriesResponse> {
  const searchParams = new URLSearchParams()

  if (params?.metric) searchParams.set("metric", params.metric)

  if (params?.range) searchParams.set("range", params.range)

  if (params?.bucket) searchParams.set("bucket", params.bucket)
  const query = searchParams.toString()

  return fetchApi<TimeseriesResponse>(`/v1/stats/timeseries${query ? `?${query}` : ""}`)
}

// IP History

export interface IpHistoryResponse {
  ip: string
  customer: { customer_id: string; name: string; policy_profile: string } | null
  service: { service_id: string; name: string } | null
  events: IpHistoryEvent[]
  mitigations: Mitigation[]
}

export interface IpHistoryEvent {
  event_id: string
  source: string
  event_timestamp: string
  ingested_at: string
  vector: string
  bps: number | null
  pps: number | null
  confidence: number | null
}

// Alerting

export interface AlertingDestination {
  type: "slack" | "discord" | "teams" | "telegram" | "pagerduty" | "opsgenie" | "generic"
  webhook_url?: string
  channel?: string
  chat_id?: string
  bot_token?: string
  routing_key?: string
  events_url?: string
  api_key?: string
  region?: string
  url?: string
  secret?: string
  headers?: Record<string, string>
  events?: string[]
}

export interface AlertingConfigResponse {
  destinations: AlertingDestination[]
  events: string[]
}

export interface AlertingTestResult {
  destination: string
  status: "ok" | "error"
  error: string | null
}

export interface AlertingTestResponse {
  results: AlertingTestResult[]
}

export async function getAlertingConfig(): Promise<AlertingConfigResponse> {
  return fetchApi<AlertingConfigResponse>("/v1/config/alerting")
}

export async function testAlerting(): Promise<AlertingTestResponse> {
  return fetchApi<AlertingTestResponse>("/v1/config/alerting/test", { method: "POST" })
}

export interface UpdateAlertingRequest {
  destinations: AlertingDestination[]
  events: string[]
}

export async function updateAlertingConfig(config: UpdateAlertingRequest): Promise<AlertingConfigResponse> {
  return fetchApi<AlertingConfigResponse>("/v1/config/alerting", {
    method: "PUT",
    body: JSON.stringify(config),
  })
}

export async function getIpHistory(ip: string, limit?: number): Promise<IpHistoryResponse> {
  const searchParams = new URLSearchParams()

  if (limit) searchParams.set("limit", limit.toString())
  const query = searchParams.toString()

  return fetchApi<IpHistoryResponse>(`/v1/ip/${encodeURIComponent(ip)}/history${query ? `?${query}` : ""}`)
}

// Notification preferences

export interface NotificationPreferences {
  muted_events: string[]
  quiet_hours_start: number | null
  quiet_hours_end: number | null
}

// Incident reports

export async function getIncidentReport(params: { mitigation_id?: string; ip?: string }): Promise<string> {
  const searchParams = new URLSearchParams()

  if (params.mitigation_id) searchParams.set("mitigation_id", params.mitigation_id)

  if (params.ip) searchParams.set("ip", params.ip)

  const res = await fetch(`${API_BASE}/v1/reports/incident?${searchParams}`, {
    credentials: "include",
  })

  if (!res.ok) {
    if (res.status === 401 && typeof window !== "undefined") dispatchAuthExpired()
    throw new Error(`API error ${res.status}: ${await res.text()}`)
  }

  return res.text()
}

export async function getNotificationPreferences(): Promise<NotificationPreferences> {
  return fetchApi<NotificationPreferences>("/v1/preferences")
}

export async function updateNotificationPreferences(prefs: NotificationPreferences): Promise<void> {
  await fetchApi<void>("/v1/preferences", {
    method: "PUT",
    body: JSON.stringify(prefs),
  })
}

// Signal Groups (Correlation Engine)

export interface SignalGroup {
  group_id: string
  victim_ip: string
  vector: string
  created_at: string
  window_expires_at: string
  derived_confidence: number
  source_count: number
  status: "open" | "resolved" | "expired"
  corroboration_met: boolean
}

export interface SignalGroupEvent {
  group_id: string
  event_id: string
  source: string
  confidence: number | null
  source_weight: number
  ingested_at: string | null
  victim_ip: string
  vector: string
  is_corroborating?: boolean
}

export interface SignalGroupsResponse {
  groups: SignalGroup[]
  count: number
  next_cursor: string | null
  has_more: boolean
}

export interface SignalGroupDetailResponse extends SignalGroup {
  events: SignalGroupEvent[]
  /** Linked mitigation ID (present when group status is resolved) */
  mitigation_id?: string | null
}

export async function getSignalGroups(params?: {
  status?: string
  vector?: string
  limit?: number
  cursor?: string
  start?: string
  end?: string
}): Promise<SignalGroupsResponse> {
  const searchParams = new URLSearchParams()

  if (params?.status) searchParams.set("status", params.status)

  if (params?.vector) searchParams.set("vector", params.vector)

  if (params?.limit) searchParams.set("limit", params.limit.toString())

  if (params?.cursor) searchParams.set("cursor", params.cursor)

  if (params?.start) searchParams.set("start", params.start)

  if (params?.end) searchParams.set("end", params.end)

  const query = searchParams.toString()

  return fetchApi<SignalGroupsResponse>(`/v1/signal-groups${query ? `?${query}` : ""}`)
}

export async function getSignalGroupDetail(id: string): Promise<SignalGroupDetailResponse> {
  return fetchApi<SignalGroupDetailResponse>(`/v1/signal-groups/${id}`)
}

// Correlation Config

export type SourceMode = "primary" | "corroborating"

export type MatchDimension = "customer_id" | "pop" | "service_id" | "interface"

export interface SourceConfig {
  weight: number
  type: string
  confidence_mapping: Record<string, number>
  mode?: SourceMode
  match_dimensions?: MatchDimension[]
}

export interface CorroboratorInput {
  source: string
  vector?: string
  customer_id?: string
  pop?: string
  service_id?: string
  interface?: string
  confidence?: number
}

export interface CorroboratorResponse {
  signal_id: string
  status: "attached" | "cached"
  attached_group_ids: string[]
}

export async function sendCorroborator(
  input: CorroboratorInput
): Promise<CorroboratorResponse> {
  return fetchApi<CorroboratorResponse>("/v1/signals/corroborator", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  })
}

export interface WebhookFieldMap {
  victim_ip: string
  vector?: string | null
  timestamp?: string | null
  bps?: string | null
  pps?: string | null
  confidence?: string | null
  source_id?: string | null
  top_dst_ports?: string | null
  top_src_ports?: string | null
  action?: string | null
}

export type WebhookAuth =
  | { type: "hmac"; secret_env: string; header: string; algorithm: string }
  | { type: "bearer" }
  | { type: "none" }

export interface WebhookAdapter {
  name: string
  description: string
  enabled: boolean
  auth: WebhookAuth
  root_path?: string | null
  fields: WebhookFieldMap
  vector_map?: Record<string, string>
  default_vector?: string | null
  confidence_scale?: number | null
  source_id_prefix?: string | null
}

export interface CorrelationConfig {
  enabled: boolean
  window_seconds: number
  min_sources: number
  confidence_threshold: number
  default_weight: number
  confidence_decay_half_life_seconds?: number
  sources: Record<string, SourceConfig>
  webhook_adapters?: WebhookAdapter[]
}

export interface CorrelationConfigResponse {
  config: CorrelationConfig
  loaded_at: string
}

export async function getCorrelationConfig(): Promise<CorrelationConfig> {
  const resp = await fetchApi<CorrelationConfigResponse>("/v1/config/correlation")

  return resp.config
}

export async function updateCorrelationConfig(config: CorrelationConfig): Promise<CorrelationConfig> {
  const resp = await fetchApi<CorrelationConfigResponse>("/v1/config/correlation", {
    method: "PUT",
    body: JSON.stringify(config),
  })

  return resp.config
}

// Signal Sources (derived from correlation config + recent events)

export interface SignalSourceStatus {
  name: string
  type: string
  weight: number
  last_seen: string | null
  event_count: number
  healthy: boolean
}

interface CorroboratorActivityEntry {
  source: string
  last_seen: string | null
  count: number
}

interface CorroboratorActivityResponse {
  since: string
  sources: CorroboratorActivityEntry[]
}

export interface CachedCorroboratorSignal {
  signal_id: string
  source: string
  vector: string | null
  customer_id: string | null
  pop: string | null
  service_id: string | null
  interface: string | null
  confidence: number | null
  weight: number
  ingested_at: string
  expires_at: string
  raw_details: unknown
  attached_group_ids: string[]
}

export interface CachedCorroboratorBySource {
  source: string
  count: number
}

export interface CachedCorroboratorsResponse {
  now: string
  total: number
  by_source: CachedCorroboratorBySource[]
  signals: CachedCorroboratorSignal[]
}

export async function getCachedCorroborators(
  params: { source?: string; limit?: number } = {},
): Promise<CachedCorroboratorsResponse> {
  const qs = new URLSearchParams()

  if (params.source) qs.set("source", params.source)

  if (params.limit) qs.set("limit", String(params.limit))
  const suffix = qs.toString() ? `?${qs}` : ""

  return fetchApi<CachedCorroboratorsResponse>(
    `/v1/signals/corroborator/cache${suffix}`,
  )
}

export async function getSignalSources(): Promise<SignalSourceStatus[]> {
  // Signal source status is derived from correlation config + recent
  // events + corroborator activity. Corroborating-only sources never hit
  // /v1/events, so we also fetch per-source activity from
  // /v1/signals/corroborator/activity and merge it in. Without this step
  // mode=corroborating sources would always render as "never seen /
  // unhealthy" even while posting.
  const [config, eventsResp, corroboratorResp] = await Promise.all([
    getCorrelationConfig(),
    getEvents({ limit: 1000 }),
    fetchApi<CorroboratorActivityResponse>(
      "/v1/signals/corroborator/activity?minutes=60",
    ).catch(() => ({ since: new Date().toISOString(), sources: [] })),
  ])

  const sourceMap = new Map<string, SignalSourceStatus>()

  // Initialize from config sources
  for (const [name, src] of Object.entries(config.sources ?? {})) {
    sourceMap.set(name, {
      name,
      type: src.type || "unknown",
      weight: src.weight,
      last_seen: null,
      event_count: 0,
      healthy: false,
    })
  }

  // Enrich with event data
  for (const event of eventsResp.events) {
    const existing = sourceMap.get(event.source)

    if (existing) {
      existing.event_count++

      if (!existing.last_seen || event.ingested_at > existing.last_seen) {
        existing.last_seen = event.ingested_at
      }
    } else {
      sourceMap.set(event.source, {
        name: event.source,
        type: "unknown",
        weight: config.default_weight,
        last_seen: event.ingested_at,
        event_count: 1,
        healthy: false,
      })
    }
  }

  // Merge corroborator activity (backend-aggregated across both
  // corroborating_signals cache and attached signal_group_events).
  for (const row of corroboratorResp.sources ?? []) {
    const existing = sourceMap.get(row.source)

    if (existing) {
      existing.event_count += row.count

      if (
        row.last_seen &&
        (!existing.last_seen || row.last_seen > existing.last_seen)
      ) {
        existing.last_seen = row.last_seen
      }
    } else {
      sourceMap.set(row.source, {
        name: row.source,
        type: "unknown",
        weight: config.default_weight,
        last_seen: row.last_seen,
        event_count: row.count,
        healthy: false,
      })
    }
  }

  // Determine health: seen within last 10 minutes
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString()

  for (const source of sourceMap.values()) {
    source.healthy = source.last_seen != null && source.last_seen > tenMinutesAgo
  }

  return Array.from(sourceMap.values())
}
