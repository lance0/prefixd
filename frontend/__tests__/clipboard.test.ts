import { afterEach, describe, expect, it, vi } from "vitest"
import { copyText } from "@/lib/clipboard"

const originalExecCommand = document.execCommand
const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard")
const originalSecureContext = Object.getOwnPropertyDescriptor(window, "isSecureContext")
const originalPermissions = navigator.permissions

function setClipboardWritePermission(state: PermissionState | "unsupported") {
  Object.defineProperty(navigator, "permissions", {
    configurable: true,
    value: {
      query: async () => {
        if (state === "unsupported") {
          throw new TypeError("clipboard-write is not a supported permission name")
        }
        return { state } as PermissionStatus
      },
    },
  })
}

function setSecureContext(value: boolean) {
  Object.defineProperty(window, "isSecureContext", { value, configurable: true })
}

function setClipboard(clipboard: unknown) {
  Object.defineProperty(navigator, "clipboard", { value: clipboard, configurable: true })
}

/** Captures the text handed to execCommand and returns its result. */
function stubExecCommand(result: boolean) {
  let copied = ""
  document.execCommand = vi.fn(() => {
    copied = document.querySelector("textarea")?.value ?? ""
    return result
  }) as unknown as typeof document.execCommand
  return () => copied
}

afterEach(() => {
  document.execCommand = originalExecCommand
  Object.defineProperty(navigator, "permissions", { configurable: true, value: originalPermissions })
  if (originalClipboard) {
    Object.defineProperty(navigator, "clipboard", originalClipboard)
  } else {
    delete (navigator as { clipboard?: unknown }).clipboard
  }
  if (originalSecureContext) {
    Object.defineProperty(window, "isSecureContext", originalSecureContext)
  }
})

describe("copyText", () => {
  // Plain-HTTP deployments have no navigator.clipboard at all; copy actions
  // used to fail silently (incident report "not in clipboard").
  it("falls back to execCommand when the Clipboard API is unavailable", async () => {
    setSecureContext(false)
    setClipboard(undefined)
    setClipboardWritePermission("granted")
    const copiedValue = stubExecCommand(true)

    await expect(copyText("incident report body")).resolves.toBe(true)

    expect(copiedValue()).toBe("incident report body")
    expect(document.execCommand).toHaveBeenCalledWith("copy")
    expect(document.querySelectorAll("textarea")).toHaveLength(0)
  })

  it("reports failure when the fallback copy is rejected", async () => {
    setSecureContext(false)
    setClipboard(undefined)
    setClipboardWritePermission("granted")
    stubExecCommand(false)

    await expect(copyText("body")).resolves.toBe(false)
  })

  // Chrome denies clipboard writes on insecure origins but still returns true
  // from the legacy copy command.
  it("reports failure when the browser denies clipboard writes", async () => {
    setSecureContext(false)
    setClipboard(undefined)
    setClipboardWritePermission("denied")
    const execCommand = stubExecCommand(true)

    await expect(copyText("body")).resolves.toBe(false)

    expect(execCommand()).toBe("")
  })

  it("still attempts a copy when the permissions API cannot answer", async () => {
    setSecureContext(false)
    setClipboard(undefined)
    setClipboardWritePermission("unsupported")
    const copiedValue = stubExecCommand(true)

    await expect(copyText("body")).resolves.toBe(true)

    expect(copiedValue()).toBe("body")
  })

  it("uses the Clipboard API in a secure context", async () => {
    setSecureContext(true)
    const writeText = vi.fn(async () => {})
    setClipboard({ writeText })

    await expect(copyText("body")).resolves.toBe(true)

    expect(writeText).toHaveBeenCalledWith("body")
  })

  it("falls back when the Clipboard API rejects", async () => {
    setSecureContext(true)
    setClipboard({
      writeText: vi.fn(async () => {
        throw new Error("NotAllowedError")
      }),
    })
    const copiedValue = stubExecCommand(true)

    await expect(copyText("body")).resolves.toBe(true)

    expect(copiedValue()).toBe("body")
  })
})
