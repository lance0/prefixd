/**
 * Copy text to the clipboard.
 *
 * Returns false when the text could not be copied, so callers can surface the
 * failure instead of reporting a copy that never happened.
 */
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && window.isSecureContext && navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text)

      return true
    } catch {
      // Permission denied or no transient activation -- try the legacy path.
    }
  }

  // Chrome denies clipboard writes outright for insecure origins (plain-HTTP
  // dashboards) while still reporting a successful legacy copy, which is how
  // "nothing was copied" used to look like a working button.
  try {
    // SAFETY: Chromium accepts "clipboard-write" although lib.dom omits it from PermissionName;
    // browsers that reject the name throw, and the catch below attempts the copy anyway.
    const status = await navigator.permissions.query({ name: "clipboard-write" as PermissionName })

    if (status.state === "denied") {
      return false
    }
  } catch {
    // Permissions API unavailable (or query unsupported): attempt the copy.
  }

  const textarea = document.createElement("textarea")

  try {
    textarea.value = text
    textarea.setAttribute("readonly", "")
    textarea.style.position = "fixed"
    textarea.style.top = "-1000px"
    textarea.style.opacity = "0"
    document.body.appendChild(textarea)
    textarea.select()

    return document.execCommand("copy")
  } catch {
    return false
  } finally {
    // The copied text can be a secret, such as a new API token: never leave it in the DOM.
    textarea.remove()
  }
}
