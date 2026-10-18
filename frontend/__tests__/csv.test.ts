import { afterEach, describe, expect, it, vi } from "vitest"

const originalBlob = globalThis.Blob
const originalCreateObjectURL = globalThis.URL.createObjectURL
const originalRevokeObjectURL = globalThis.URL.revokeObjectURL

function mockCsvEnvironment() {
  let capturedContent = ""
  globalThis.Blob = class MockBlob {
    constructor(parts: BlobPart[]) {
      capturedContent = parts[0] as string
    }
  } as any
  globalThis.URL.createObjectURL = vi.fn(() => "blob:mock")
  globalThis.URL.revokeObjectURL = vi.fn()

  return () => capturedContent
}

afterEach(() => {
  globalThis.Blob = originalBlob
  globalThis.URL.createObjectURL = originalCreateObjectURL
  globalThis.URL.revokeObjectURL = originalRevokeObjectURL
})

describe("CSV export", () => {
  it("generates correct CSV with headers and rows", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["id", "name", "value"], [
      ["1", "Alice", "100"],
      ["2", "Bob", "200"],
    ])

    expect(getContent()).toBe("id,name,value\n1,Alice,100\n2,Bob,200")
  })

  it("escapes fields with commas", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["name"], [["hello, world"]])

    expect(getContent()).toBe('name\n"hello, world"')
  })

  it("escapes fields with quotes", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["name"], [['say "hi"']])

    expect(getContent()).toBe('name\n"say ""hi"""')
  })

  it("sanitizes formula injection characters", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["data"], [
      ['=CMD("calc")'],
      ["+1234"],
      ["-5678"],
      ["@SUM(A1)"],
      [" \t=SUM(A1)"],
      ["normal"],
    ])

    const lines = getContent().split("\n")
    expect(lines[0]).toBe("data")
    expect(lines[1]).toBe("\"'=CMD(\"\"calc\"\")\"")
    expect(lines[2]).toBe("'+1234")
    expect(lines[3]).toBe("'-5678")
    expect(lines[4]).toBe("'@SUM(A1)")
    expect(lines[5]).toBe("' \t=SUM(A1)")
    expect(lines[6]).toBe("normal")
  })

  it("handles null/undefined fields gracefully", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["a", "b"], [
      [undefined as any, null as any],
      ["", "ok"],
    ])

    expect(getContent()).toBe("a,b\n,\n,ok")
  })
})
