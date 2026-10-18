import { type ReactElement, type ReactNode } from "react"
import { act, render } from "@testing-library/react"
import { AppRouterContext, type AppRouterInstance } from "next/dist/shared/lib/app-router-context.shared-runtime"
import { PathnameContext, SearchParamsContext } from "next/dist/shared/lib/hooks-client-context.shared-runtime"
import { Toaster, toast } from "sonner"
import { SWRConfig, useSWRConfig, type ScopedMutator } from "swr"
import { afterEach, beforeEach, vi } from "vitest"
import { AuthProvider } from "@/hooks/use-auth"
import type { Operator, OperatorResponse } from "@/lib/auth"

/** One request the dashboard sent to the controller, relative to the `/api/prefixd` proxy. */
export interface ApiRequest {
  method: string
  path: string
  query: URLSearchParams
  body: string | null
}

export type ApiHandler = (request: ApiRequest) => Response | Promise<Response>

export function json<T>(data: T, status = 200): Response {
  return new Response(JSON.stringify(data), { status, headers: { "Content-Type": "application/json" } })
}

export function failure(status: number, message = "fake controller failure"): Response {
  return new Response(message, { status })
}

export interface Deferred<T> {
  promise: Promise<T>
  resolve: (value: T) => void
  reject: (reason: Error) => void
}

export function deferred<T>(): Deferred<T> {
  const { promise, resolve, reject } = Promise.withResolvers<T>()

  return { promise, resolve, reject }
}

/**
 * A scripted controller behind the dashboard's real fetch path. Routes are keyed by
 * method and path ("GET /v1/health"); an unrouted request answers 404 like a missing
 * resource. Requests still pending when a test ends are aborted, so nothing leaks into
 * the next test through the API client's in-flight request cache.
 */
export interface FakeController {
  /** Every request received, in order. */
  requests: ApiRequest[]
  route: (method: string, path: string, handler: ApiHandler) => void
  /** Requests received for one route. */
  calls: (method: string, path: string) => ApiRequest[]
}

export function useFakeController(): FakeController {
  let routes = new Map<string, ApiHandler>()
  let aborted = new AbortController()

  const controller: FakeController = {
    requests: [],
    route: (method, path, handler) => { routes.set(`${method} ${path}`, handler) },
    calls: (method, path) => controller.requests.filter((r) => r.method === method && r.path === path),
  }

  const fakeFetch: typeof fetch = async (input, init) => {
    const url = new URL(String(input), "http://dashboard.test")
    const method = init?.method ?? "GET"
    const path = url.pathname.replace(/^\/api\/prefixd/, "")
    const request: ApiRequest = { method, path, query: url.searchParams, body: init?.body ? String(init.body) : null }
    controller.requests.push(request)
    const handler = routes.get(`${method} ${path}`)

    if (!handler) return failure(404, `no fake route for ${method} ${path}`)
    const signal = aborted.signal

    return Promise.race([
      handler(request),
      new Promise<never>((_, reject) => {
        signal.addEventListener("abort", () => reject(new DOMException("test ended", "AbortError")))
      }),
    ])
  }

  beforeEach(() => {
    routes = new Map()
    aborted = new AbortController()
    controller.requests = []
    // A plain function, not a spy, so a test file resetting its own mocks cannot strip the fake.
    vi.stubGlobal("fetch", fakeFetch)
  })

  afterEach(async () => {
    // Toasts live in a module-wide queue that a new Toaster replays; retire this test's.
    toast.dismiss()
    aborted.abort()
    // Let aborted requests settle and leave the API client's request cache.
    await act(async () => {})
    vi.unstubAllGlobals()
  })

  return controller
}

/** Lets settled responses reach React: resolved fetches, SWR updates and effects. */
export async function settle() {
  await act(() => new Promise<void>((resolve) => { setTimeout(resolve, 0) }))
}

export function operatorResponse(role: Operator["role"], username = "alice"): OperatorResponse {
  return { operator_id: `${username}-id`, username, role }
}

/** Routes the session endpoints: an auth mode from /v1/health and the signed-in operator, if any. */
export function signIn(controller: FakeController, authMode: string, operator: OperatorResponse | null) {
  controller.route("GET", "/v1/health", () => json({ status: "ok", version: "test", auth_mode: authMode }))
  controller.route("GET", "/v1/auth/me", () => operator ? json(operator) : failure(401, "unauthorized"))
}

export interface RouterSpies extends AppRouterInstance {
  push: ReturnType<typeof vi.fn<AppRouterInstance["push"]>>
  replace: ReturnType<typeof vi.fn<AppRouterInstance["replace"]>>
  back: ReturnType<typeof vi.fn<AppRouterInstance["back"]>>
}

export function routerSpies(): RouterSpies {
  return {
    back: vi.fn(), forward: vi.fn(), refresh: vi.fn(), push: vi.fn(), replace: vi.fn(), prefetch: vi.fn(), bfcacheId: "test",
  }
}

export interface AppOptions {
  /** Current route; the query string feeds useSearchParams. */
  url?: string
  router?: RouterSpies
  /** Render without the AuthProvider, for trees that do not read the session. */
  withoutAuth?: boolean
}

export interface AppHandles {
  router: RouterSpies
  /** The SWR mutator scoped to this render's cache. */
  mutate: () => ScopedMutator
}

function MutatorProbe({ onMutator }: { onMutator: (mutate: ScopedMutator) => void }) {
  onMutator(useSWRConfig().mutate)

  return null
}

export interface AppWrapper {
  wrapper: (props: { children: ReactNode }) => ReactElement
  handles: AppHandles
}

/** Wraps a dashboard tree in the providers the app shell supplies: router, SWR cache, auth and toasts. */
export function appWrapper(options: AppOptions = {}): AppWrapper {
  const url = new URL(options.url ?? "/", "http://dashboard.test")
  const router = options.router ?? routerSpies()
  const cache = new Map()
  let mutator: ScopedMutator | null = null

  const handles: AppHandles = {
    router,
    mutate: () => {
      if (!mutator) throw new Error("render the app before using its mutator")

      return mutator
    },
  }

  function Wrapper({ children }: { children: ReactNode }) {
    const tree = options.withoutAuth ? children : <AuthProvider>{children}</AuthProvider>

    return (
      <AppRouterContext.Provider value={router}>
        <PathnameContext.Provider value={url.pathname}>
          <SearchParamsContext.Provider value={url.searchParams}>
            <SWRConfig value={{ provider: () => cache, dedupingInterval: 0, focusThrottleInterval: 0, shouldRetryOnError: false }}>
              <MutatorProbe onMutator={(m) => { mutator = m }} />
              {tree}
              <Toaster />
            </SWRConfig>
          </SearchParamsContext.Provider>
        </PathnameContext.Provider>
      </AppRouterContext.Provider>
    )
  }

  return { wrapper: Wrapper, handles }
}

/** Renders a dashboard tree inside the app providers. */
export function renderApp(ui: ReactElement, options: AppOptions = {}) {
  const { wrapper, handles } = appWrapper(options)

  return { ...render(ui, { wrapper }), ...handles }
}
