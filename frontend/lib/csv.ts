const CSV_FORMULA_CHARS = ["=", "+", "-", "@", "\t", "\r"]

function escapeCsvField(field: string): string {
  if (!field) return ""
  let safe = field
  if (CSV_FORMULA_CHARS.some((c) => safe.startsWith(c))) {
    safe = "'" + safe
  }
  if (safe.includes(",") || safe.includes('"') || safe.includes("\n")) {
    return `"${safe.replace(/"/g, '""')}"`
  }
  return safe
}

export function downloadCsv(filename: string, headers: string[], rows: string[][]) {
  const headerLine = headers.map(escapeCsvField).join(",")
  const dataLines = rows.map((row) => row.map(escapeCsvField).join(","))
  const csv = [headerLine, ...dataLines].join("\n")

  const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}
