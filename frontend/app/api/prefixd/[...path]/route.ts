import { NextRequest, NextResponse } from "next/server"

// Backend URL - only accessed server-side, so no NEXT_PUBLIC_ needed
const PREFIXD_API = process.env.PREFIXD_API || "http://prefixd:8080"

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
  const fullPath = "/" + path.join("/") + (request.nextUrl.search || "")
  return proxyRequest(request, fullPath)
}

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  const fullPath = "/" + path.join("/")
  return proxyRequest(request, fullPath)
}

export async function PUT(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  const fullPath = "/" + path.join("/")
  return proxyRequest(request, fullPath)
}

export async function DELETE(
  request: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
) {
  const { path } = await params
  const fullPath = "/" + path.join("/")
  return proxyRequest(request, fullPath)
}
