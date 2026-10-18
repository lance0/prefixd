"use client"

import { useState, useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/hooks/use-auth"
import { useHealth } from "@/hooks/use-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { AlertCircle, Loader2 } from "lucide-react"

export default function LoginPage() {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { login, isAuthenticated, isLoading: authLoading } = useAuth()
  const { data: health, isLoading: healthLoading } = useHealth()
  const settled = !authLoading && !healthLoading && !!health
  const authDisabled = health?.auth_mode === "none"
  const router = useRouter()

  // Redirect if already authenticated or auth is disabled
  useEffect(() => {
    if (settled && (isAuthenticated || authDisabled)) {
      router.push("/")
    }
  }, [settled, isAuthenticated, authDisabled, router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsLoading(true)

    try {
      await login({ username, password })
      router.push("/")
    } catch (err) {
      setError(err instanceof Error ? err.message : "Login failed")
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-dvh flex items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <div className="mb-2 flex items-center gap-2.5">
            <span className="flex size-7 items-center justify-center rounded-md bg-primary font-mono text-xs font-semibold text-primary-foreground" aria-hidden="true">P</span>
            <span className="font-semibold">prefixd</span>
          </div>
          <CardTitle>
            <h1 className="text-xl font-semibold">Sign in</h1>
          </CardTitle>
          <CardDescription>
            Use your operator account to manage mitigations.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {!settled || authDisabled || isAuthenticated ? (
            <p role="status" className="text-sm text-muted-foreground">
              {healthLoading || authLoading
                ? "Checking authentication…"
                : !health
                  ? "Unable to determine authentication mode. Reload to try again."
                  : "Opening dashboard…"}
            </p>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <div className="flex items-center gap-2 p-3 text-sm text-destructive bg-destructive/10 rounded-md">
                  <AlertCircle className="h-4 w-4" />
                  {error}
                </div>
              )}
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input
                  id="username"
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={isLoading}
                  required
                  autoComplete="username"
                  autoFocus
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={isLoading}
                  required
                  autoComplete="current-password"
                />
              </div>
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Signing in…
                  </>
                ) : (
                  "Sign in"
                )}
              </Button>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
