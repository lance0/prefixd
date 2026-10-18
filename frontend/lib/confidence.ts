export function isConfidence(value: number | null | undefined): value is number {
  return value != null && Number.isFinite(value) && value >= 0 && value <= 1
}

export function formatConfidence(value: number | null | undefined): string {
  if (value == null) return "Unavailable"

  return isConfidence(value) ? `${Math.round(value * 100)}%` : "Invalid"
}
