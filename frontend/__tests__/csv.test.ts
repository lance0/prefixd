import { afterEach, describe, expect, it, vi } from "vitest"

const originalCreateObjectURL = globalThis.URL.createObjectURL
const originalRevokeObjectURL = globalThis.URL.revokeObjectURL

/** Captures the Blob handed to the download link and returns a reader for its text. */
function mockCsvEnvironment() {
  let captured = new Blob()

  globalThis.URL.createObjectURL = vi.fn((blob: Blob) => {
    captured = blob

    return "blob:mock"
  })
  globalThis.URL.revokeObjectURL = vi.fn()

  return () => captured.text()
}

afterEach(() => {
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

    expect(await getContent()).toBe("id,name,value\n1,Alice,100\n2,Bob,200")
  })

  it("escapes fields with commas", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["name"], [["hello, world"]])

    expect(await getContent()).toBe('name\n"hello, world"')
  })

  it("escapes fields with quotes", async () => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["name"], [['say "hi"']])

    expect(await getContent()).toBe('name\n"say ""hi"""')
  })

  it.each(["\r", "\r\n", "\n"])("quotes record separators %j within one field", async (separator) => {
    const getContent = mockCsvEnvironment()
    const { downloadCsv } = await import("@/lib/csv")

    downloadCsv("test.csv", ["source"], [[`normal${separator}=1+1`]])

    expect(await getContent()).toBe(`source\n"normal${separator}=1+1"`)
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

    const lines = (await getContent()).split("\n")
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
      [undefined, null],
      ["", "ok"],
    ])

    expect(await getContent()).toBe("a,b\n,\n,ok")
  })
})
