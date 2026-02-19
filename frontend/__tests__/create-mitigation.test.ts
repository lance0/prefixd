import { describe, it, expect } from "vitest"

const IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/

function parsePorts(input: string): number[] | null {
  if (!input.trim()) return []
  const parts = input.split(",").map((s) => s.trim())
  const parsed = parts.map(Number)
  if (parsed.some((n) => isNaN(n) || n < 1 || n > 65535)) return null
  if (parsed.length > 8) return null
  return parsed
}

describe("Create Mitigation validation", () => {
  describe("IP validation", () => {
    it("accepts valid IPv4", () => {
      expect(IP_REGEX.test("192.0.2.1")).toBe(true)
      expect(IP_REGEX.test("10.0.0.1")).toBe(true)
      expect(IP_REGEX.test("255.255.255.255")).toBe(true)
    })

    it("rejects invalid IPs", () => {
      expect(IP_REGEX.test("")).toBe(false)
      expect(IP_REGEX.test("192.0.2")).toBe(false)
      expect(IP_REGEX.test("192.0.2.1/32")).toBe(false)
      expect(IP_REGEX.test("not-an-ip")).toBe(false)
      expect(IP_REGEX.test("2001:db8::1")).toBe(false)
    })
  })

  describe("Port parsing", () => {
    it("parses valid ports", () => {
      expect(parsePorts("80")).toEqual([80])
      expect(parsePorts("80, 443")).toEqual([80, 443])
      expect(parsePorts("80,443,53")).toEqual([80, 443, 53])
    })

    it("returns empty array for empty input", () => {
      expect(parsePorts("")).toEqual([])
      expect(parsePorts("   ")).toEqual([])
    })

    it("rejects invalid ports", () => {
      expect(parsePorts("abc")).toBeNull()
      expect(parsePorts("0")).toBeNull()
      expect(parsePorts("65536")).toBeNull()
      expect(parsePorts("-1")).toBeNull()
    })

    it("rejects more than 8 ports", () => {
      expect(parsePorts("1,2,3,4,5,6,7,8,9")).toBeNull()
    })

    it("accepts exactly 8 ports", () => {
      expect(parsePorts("1,2,3,4,5,6,7,8")).toEqual([1, 2, 3, 4, 5, 6, 7, 8])
    })
  })
})
