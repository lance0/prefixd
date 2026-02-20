# ADR 006: Derive Frontend URLs at Runtime, Not Build Time

## Status

Accepted

## Date

2026-02-18

## Context

Next.js `NEXT_PUBLIC_*` environment variables are baked into the JavaScript bundle at build time. This meant:

1. `NEXT_PUBLIC_PREFIXD_API` had to be set when building the Docker image, coupling the image to a specific deployment URL
2. `NEXT_PUBLIC_PREFIXD_WS` required the same -- and was added as a Docker build arg
3. Moving the dashboard to a different host required rebuilding the image
4. The same Docker image couldn't be used across environments (dev, staging, prod)

## Decision

Derive all URLs from `window.location` at runtime:

- **HTTP API**: Proxied through Next.js API route (`/api/prefixd/[...path]`), so the browser just talks to its own origin
- **WebSocket**: `getWsBase()` derives `ws:`/`wss:` from `window.location.protocol` and uses `window.location.host`
- **Both**: With nginx in front (ADR 005), the browser's origin is always correct for both HTTP and WS

```typescript
function getWsBase(): string {
  if (typeof window === "undefined") return "ws://127.0.0.1"
  const proto = window.location.protocol === "https:" ? "wss:" : "ws:"
  return `${proto}//${window.location.host}`
}
```

## Consequences

**Positive:**
- One Docker image works in any environment without rebuild
- No build-time environment variables for URLs
- Works behind any reverse proxy (nginx, caddy, traefik, cloud LB) without configuration
- `docker compose up` just works -- no `.env` file needed for URLs

**Negative:**
- Server-side rendering can't access the API via `window.location` (uses `PREFIXD_API` env var server-side instead, which is a runtime env var set in docker-compose)
- The SSR fallback (`ws://127.0.0.1`) is only used during server rendering and is never sent to the browser
