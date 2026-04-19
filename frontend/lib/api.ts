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

export interface Mitigation {
  mitigation_id: string
  scope_hash: string
  status: "pending" | "active" | "escalated" | "expired" | "withdrawn" | "rejected"
  customer_id: string | null
  service_id: string | null
  pop: string
  victim_ip: string
  vector: string
  action_type: "police" | "discard"
  rate_bps: number | null
  dst_prefix: string
  protocol: number | null
  dst_ports: number[]
  created_at: string
  updated_at: string
  expires_at: string
  withdrawn_at: string | null
  triggering_event_id: string
  last_event_id: string
  reason: string
  acknowledged_at: string | null
  acknowledged_by: string | null
  /** Correlation context (present when mitigation was created via corroboration) */
  correlation?: CorrelationContext | null
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
  // Computed from gobgp.status for UI convenience
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
    if (cached) return cached as Promise<T>
    
    const promise = doFetch<T>(url, { ...options, headers })
    requestCache.set(cacheKey, promise)
    
    // Remove from cache after request completes
    promise.finally(() => {
      setTimeout(() => requestCache.delete(cacheKey), 100)
    })
    
    return promise
  }

  return doFetch<T>(url, { ...options, headers })
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

  return res.json()
}

export async function getHealth(): Promise<PublicHealthResponse> {
  return fetchApi<PublicHealthResponse>("/v1/health")
}

export async function getHealthDetail(): Promise<HealthResponse> {
  const data = await fetchApi<Omit<HealthResponse, 'bgp_session_up'>>("/v1/health/detail")
  const sessions = Object.values(data.bgp_sessions ?? {})
  return {
    ...data,
    bgp_session_up: sessions.length > 0 && sessions.every((s) => s === "established"),
  }
}

export async function getStats(): Promise<Stats> {
  return fetchApi<Stats>("/v1/stats")
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
  details: Record<string, unknown>
}

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
  newPassword: string
): Promise<void> {
  await fetchApi(`/v1/operators/${id}/password`, {
    method: "PUT",
    body: JSON.stringify({ new_password: newPassword }),
  })
}

// Config endpoints (read-only)

export interface ConfigSettingsResponse {
  settings: Record<string, unknown>
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
  steps: {
    action: "police" | "discard"
    rate_bps?: number
    ttl_seconds: number
    require_confidence_at_least?: number
    require_persistence_seconds?: number
  }[]
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
  cached: boolean
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

export async function getSignalSources(): Promise<SignalSourceStatus[]> {
  // Signal source status is derived from correlation config + recent events.
  // We fetch correlation config and recent events, then combine them.
  const [config, eventsResp] = await Promise.all([
    getCorrelationConfig(),
    getEvents({ limit: 1000 }),
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

  // Determine health: seen within last 10 minutes
  const tenMinutesAgo = new Date(Date.now() - 10 * 60 * 1000).toISOString()
  for (const source of sourceMap.values()) {
    source.healthy = source.last_seen != null && source.last_seen > tenMinutesAgo
  }

  return Array.from(sourceMap.values())
}
