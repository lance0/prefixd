// Use relative URL to proxy through Next.js API route
// This allows the dashboard to work on any host without hardcoded URLs
const API_BASE = "/api/prefixd"

// Cache for deduplicating in-flight requests (client-swr-dedup pattern)
const requestCache = new Map<string, Promise<unknown>>()

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
  reason: string
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
  const token = process.env.NEXT_PUBLIC_PREFIXD_TOKEN
  const headers: HeadersInit = {
    "Content-Type": "application/json",
    ...(token && { Authorization: `Bearer ${token}` }),
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
    const error = await res.text()
    throw new Error(`API error ${res.status}: ${error}`)
  }

  return res.json()
}

export async function getHealth(): Promise<HealthResponse> {
  const data = await fetchApi<Omit<HealthResponse, 'bgp_session_up'>>("/v1/health")
  return {
    ...data,
    bgp_session_up: data.gobgp?.status === "connected",
  }
}

export async function getStats(): Promise<Stats> {
  return fetchApi<Stats>("/v1/stats")
}

export async function getMitigations(params?: {
  status?: string[]
  customer_id?: string
  pop?: string
  limit?: number
  offset?: number
}): Promise<Mitigation[]> {
  const searchParams = new URLSearchParams()
  if (params?.status && params.status.length > 0) {
    // Backend expects comma-separated status values
    searchParams.set("status", params.status.join(","))
  }
  if (params?.customer_id) searchParams.set("customer_id", params.customer_id)
  if (params?.pop) searchParams.set("pop", params.pop)
  if (params?.limit) searchParams.set("limit", params.limit.toString())
  if (params?.offset) searchParams.set("offset", params.offset.toString())

  const query = searchParams.toString()
  const response = await fetchApi<{ mitigations: Mitigation[]; count: number }>(`/v1/mitigations${query ? `?${query}` : ""}`)
  return response.mitigations
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

export async function getEvents(params?: {
  limit?: number
  offset?: number
}): Promise<Event[]> {
  const searchParams = new URLSearchParams()
  if (params?.limit) searchParams.set("limit", params.limit.toString())
  if (params?.offset) searchParams.set("offset", params.offset.toString())

  const query = searchParams.toString()
  const response = await fetchApi<{ events: Event[]; count: number }>(`/v1/events${query ? `?${query}` : ""}`)
  return response.events
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

export async function getAuditLog(params?: {
  limit?: number
  offset?: number
}): Promise<AuditEntry[]> {
  const searchParams = new URLSearchParams()
  if (params?.limit) searchParams.set("limit", params.limit.toString())
  if (params?.offset) searchParams.set("offset", params.offset.toString())

  const query = searchParams.toString()
  return fetchApi<AuditEntry[]>(`/v1/audit${query ? `?${query}` : ""}`)
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
  const [health, stats, mitigations] = await Promise.all([
    getHealth(),
    getStats(),
    getMitigations({ status: ["active", "escalated"], limit: 100 }),
  ])
  return { health, stats, mitigations }
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
