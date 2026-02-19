import { describe, it, expect } from "vitest"

function isValidIPv4(ip: string): boolean {
  const parts = ip.split(".")
  if (parts.length !== 4) return false
  return parts.every((p) => {
    const n = Number(p)
    return /^\d{1,3}$/.test(p) && n >= 0 && n <= 255
  })
}

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
      expect(isValidIPv4("192.0.2.1")).toBe(true)
      expect(isValidIPv4("10.0.0.1")).toBe(true)
      expect(isValidIPv4("255.255.255.255")).toBe(true)
      expect(isValidIPv4("0.0.0.0")).toBe(true)
    })

    it("rejects invalid IPs", () => {
      expect(isValidIPv4("")).toBe(false)
      expect(isValidIPv4("192.0.2")).toBe(false)
      expect(isValidIPv4("192.0.2.1/32")).toBe(false)
      expect(isValidIPv4("not-an-ip")).toBe(false)
      expect(isValidIPv4("2001:db8::1")).toBe(false)
    })

    it("rejects out-of-range octets", () => {
      expect(isValidIPv4("999.1.1.1")).toBe(false)
      expect(isValidIPv4("256.0.0.1")).toBe(false)
      expect(isValidIPv4("1.2.3.999")).toBe(false)
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
