import { describe, it, expect, vi } from "vitest"

// Import the module to test the escapeCsvField logic via downloadCsv
// Since escapeCsvField is not exported, we test it through downloadCsv behavior
// by intercepting the Blob constructor

describe("CSV export", () => {
  it("generates correct CSV with headers and rows", () => {
    let capturedContent = ""
    const originalBlob = globalThis.Blob
    globalThis.Blob = class MockBlob {
      constructor(parts: BlobPart[]) {
        capturedContent = parts[0] as string
      }
    } as any

    globalThis.URL.createObjectURL = vi.fn(() => "blob:mock")
    globalThis.URL.revokeObjectURL = vi.fn()

    // Dynamic import to get fresh module
    return import("@/lib/csv").then(({ downloadCsv }) => {
      downloadCsv("test.csv", ["id", "name", "value"], [
        ["1", "Alice", "100"],
        ["2", "Bob", "200"],
      ])

      expect(capturedContent).toBe("id,name,value\n1,Alice,100\n2,Bob,200")
      globalThis.Blob = originalBlob
    })
  })

  it("escapes fields with commas", () => {
    let capturedContent = ""
    const originalBlob = globalThis.Blob
    globalThis.Blob = class MockBlob {
      constructor(parts: BlobPart[]) {
        capturedContent = parts[0] as string
      }
    } as any

    globalThis.URL.createObjectURL = vi.fn(() => "blob:mock")
    globalThis.URL.revokeObjectURL = vi.fn()

    return import("@/lib/csv").then(({ downloadCsv }) => {
      downloadCsv("test.csv", ["name"], [["hello, world"]])

      expect(capturedContent).toBe('name\n"hello, world"')
      globalThis.Blob = originalBlob
    })
  })

  it("escapes fields with quotes", () => {
    let capturedContent = ""
    const originalBlob = globalThis.Blob
    globalThis.Blob = class MockBlob {
      constructor(parts: BlobPart[]) {
        capturedContent = parts[0] as string
      }
    } as any

    globalThis.URL.createObjectURL = vi.fn(() => "blob:mock")
    globalThis.URL.revokeObjectURL = vi.fn()

    return import("@/lib/csv").then(({ downloadCsv }) => {
      downloadCsv("test.csv", ["name"], [['say "hi"']])

      expect(capturedContent).toBe('name\n"say ""hi"""')
      globalThis.Blob = originalBlob
    })
  })

  it("handles null/undefined fields gracefully", () => {
    let capturedContent = ""
    const originalBlob = globalThis.Blob
    globalThis.Blob = class MockBlob {
      constructor(parts: BlobPart[]) {
        capturedContent = parts[0] as string
      }
    } as any

    globalThis.URL.createObjectURL = vi.fn(() => "blob:mock")
    globalThis.URL.revokeObjectURL = vi.fn()

    return import("@/lib/csv").then(({ downloadCsv }) => {
      downloadCsv("test.csv", ["a", "b"], [
        [undefined as any, null as any],
        ["", "ok"],
      ])

      expect(capturedContent).toBe("a,b\n,\n,ok")
      globalThis.Blob = originalBlob
    })
  })
})
