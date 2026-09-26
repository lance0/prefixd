import { NextRequest, NextResponse } from "next/server"

export const dynamic = "force-dynamic"

// Backend URL - only accessed server-side, so no NEXT_PUBLIC_ needed
const PREFIXD_API = process.env.PREFIXD_API || "http://prefixd:8080"

// Next.js hands over already percent-decoded segments, so path separators that
// arrived encoded (e.g. the `%2F` in a CIDR: /v1/safelist/8.9.8.9%2F32) would
// otherwise be re-sent as real separators and 404 in the backend router.
function upstreamPath(path: string[], search = ""): string {
  return "/" + path.map(encodeURIComponent).join("/") + search
}

async function proxyRequest(request: NextRequest, path: string) {
  const url = `${PREFIXD_API}${path}`
  
  // Forward headers, excluding host
  const headers = new Headers()
  request.headers.forEach((value, key) => {
    if (key.toLowerCase() !== "host") {
      headers.set(key, value)
    }
  })

  try {
    const response = await fetch(url, {
      method: request.method,
      headers,
      body: request.body,
      // @ts-expect-error duplex is required for streaming body
      duplex: "half",
    })

    // Forward response headers
    const responseHeaders = new Headers()
    response.headers.forEach((value, key) => {
      // Don't forward these headers
      if (!["content-encoding", "transfer-encoding"].includes(key.toLowerCase())) {
        responseHeaders.set(key, value)
      }
    })

    return new NextResponse(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders,
    })
  } catch (error) {
    console.error("Proxy error:", error)
    return NextResponse.json(
      { error: "Failed to connect to backend" },
      { status: 502 }
    )
  }
}

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, upstreamPath(path, request.nextUrl.search || ""))
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, upstreamPath(path))
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, upstreamPath(path))
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  return proxyRequest(request, upstreamPath(path))
}
