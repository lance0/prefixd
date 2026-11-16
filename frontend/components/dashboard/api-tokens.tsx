"use client"

import { useId, useRef, useState, type FormEvent } from "react"
import { Copy, Plus, RefreshCw, Ban } from "lucide-react"
import { toast } from "sonner"
import { Card, CardContent, CardDescription, CardHeader } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { StatusPill, Tag } from "@/components/dashboard/status-pill"
import { useTimeFormat } from "@/components/time-zone-provider"
import { useApiTokens, useCorrelationConfig } from "@/hooks/use-api"
import { createApiToken, revokeApiToken, serverErrors, type ApiToken, type NewApiToken, type TokenScope } from "@/lib/api"
import { copyText } from "@/lib/clipboard"
import { MISSING, formatRelative } from "@/lib/format"

const NAME_PATTERN = /^[a-z0-9][a-z0-9-]{0,57}$/
const SOURCE_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/
const BUILT_IN_SOURCES = ["fastnetmon", "fastnetmon-hostgroup", "alertmanager"]
const EXPIRY_DAYS = ["never", "30", "90", "365"] as const

// Not a valid username (`^[A-Za-z0-9_-]{1,64}$`), so it never collides with a creator.
const ANY_CREATOR = "*"

type TokenState = "active" | "expired" | "revoked"

function tokenState(token: ApiToken, now: number): TokenState {
  if (token.revoked_at) return "revoked"

  return token.expires_at && new Date(token.expires_at).getTime() <= now ? "expired" : "active"
}

export interface TokenSnippet {
  title: string
  text: string
}

/** The account each known client runs as; it alone may read the token file. */
function clientUser(token: Pick<ApiToken, "scope" | "source">): string {
  if (token.scope === "ingest" && (token.source === "fastnetmon" || token.source === "fastnetmon-hostgroup")) return "fastnetmon"

  if (token.scope === "ingest" && token.source === "alertmanager") return "alertmanager"

  return "<the client's account>"
}

/**
 * Ready-to-paste setup for a new token's client (ADR 034 §13). Every snippet reads the token
 * from a file only the client's account can read, so the secret itself never appears here: it
 * is shown once, in its own field.
 */
export function tokenSnippets(token: Pick<ApiToken, "name" | "scope" | "source">, origin: string, bearerAdapters: string[] = []): TokenSnippet[] {
  const file = `/etc/prefixd/${token.name}.token`
  // The file is the client's alone, so a test from a login shell reads it through sudo.
  const header = `printf 'header = "Authorization: Bearer %s"\\n' "$(sudo cat ${file})" |`
  const user = clientUser(token)

  const fileSetup = [
    "# Paste the token, press Enter, then Ctrl-D. Only CLIENT_USER can read the file.",
    `CLIENT_USER="${user}"`,
    "sudo install -d -m 0755 /etc/prefixd",
    `sudo sh -c 'umask 077 && cat > ${file}'`,
    `sudo chown "$CLIENT_USER" ${file}`,
    `sudo chmod 0400 ${file}`,
  ]

  if (token.scope === "ingest" && token.source === "alertmanager") {
    fileSetup.splice(1, 0,
      "# CLIENT_USER is the account Alertmanager runs as: prometheus on Debian and Ubuntu packages.",
      "# In a container, mount the file read-only and owned by the container's user (nobody in the",
      "# official image); never make it world-readable.")
  }

  const snippets: TokenSnippet[] = [{ title: "Token file", text: fileSetup.join("\n") }]

  if (token.scope !== "ingest") {
    snippets.push({
      title: "prefixdctl",
      text: [
        "# As CLIENT_USER, which owns the token file:",
        `export PREFIXD_API=${origin}`,
        `export PREFIXD_TOKEN="$(cat ${file})"`,
        "prefixdctl status",
      ].join("\n"),
    }, {
      title: "Test with curl",
      text: [
        "# The header goes to curl on stdin (-K -), never on the command line.",
        header,
        `  curl -K - --fail-with-body ${origin}/v1/health/detail`,
      ].join("\n"),
    })

    return snippets
  }

  if (token.source === "fastnetmon") {
    snippets.push({
      title: "FastNetMon notify script (/etc/default/prefixd)",
      text: [`PREFIXD_API="${origin}"`, `PREFIXD_TOKEN_FILE="${file}"`].join("\n"),
    })
  } else if (token.source === "fastnetmon-hostgroup") {
    snippets.push({
      title: "Hostgroup shim, one event per attacked network",
      text: [
        "# As fastnetmon. Each network needs its own event ID.",
        `printf 'header = "Authorization: Bearer %s"\\n' "$(cat ${file})" |`,
        `  curl -K - -X POST "${origin}/v1/events" -H "Content-Type: application/json" \\`,
        `    -d '{"event_id": "<unique id>", "timestamp": "<RFC 3339 time>", "source": "fastnetmon-hostgroup", "victim_ip": "<network CIDR>", "vector": "udp_flood", "confidence": 0.9}'`,
      ].join("\n"),
    })
  } else if (token.source === "alertmanager") {
    snippets.push({
      title: "Alertmanager receiver",
      text: [
        "receivers:",
        "  - name: prefixd",
        "    webhook_configs:",
        `      - url: "${origin}/v1/signals/alertmanager"`,
        "        send_resolved: true",
        "        http_config:",
        "          authorization:",
        "            type: Bearer",
        `            credentials_file: ${file}`,
      ].join("\n"),
    })
  } else if (token.source && bearerAdapters.includes(token.source)) {
    snippets.push({
      title: "Webhook or Grafana contact point",
      text: [
        `URL:            ${origin}/v1/signals/webhook/${token.source}`,
        "Authorization:  Bearer <the token>",
        "# Grafana: authorization_scheme Bearer, authorization_credentials <the token>",
      ].join("\n"),
    })
  }

  snippets.push({
    title: "Test with curl",
    text: [
      "# The header goes to curl on stdin (-K -), never on the command line. An empty event is",
      "# refused after authentication: 400 or 422 means the token works, 401 or 403 means it does not.",
      header,
      `  curl -K - -sS -o /dev/null -w '%{http_code}\\n' -X POST -H 'Content-Type: application/json' -d '{}' ${origin}/v1/events`,
    ].join("\n"),
  })

  return snippets
}

async function copy(text: string, what: string): Promise<boolean> {
  const copied = await copyText(text)

  if (copied) toast.success(`${what} copied`)
  else toast.error("Copy failed: clipboard unavailable. Select the text and copy it instead.")

  return copied
}

/** API tokens (ADR 034 §9). Rendered only for an Admin session; the controller refuses everyone else. */
export function ApiTokensPanel() {
  const { formatTime, timeZone } = useTimeFormat()
  const { data: tokens, error, isLoading, mutate } = useApiTokens()
  const { data: correlation } = useCorrelationConfig()
  const [createOpen, setCreateOpen] = useState(false)
  const [revokeTarget, setRevokeTarget] = useState<ApiToken | null>(null)
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [isRevoking, setIsRevoking] = useState(false)
  const [creator, setCreator] = useState(ANY_CREATOR)
  const createButton = useRef<HTMLButtonElement | null>(null)
  const revoked = useRef(false)
  const now = Date.now()

  const bearerAdapters = (correlation?.webhook_adapters ?? [])
    .filter((adapter) => adapter.enabled && adapter.auth.type === "bearer")
    .map((adapter) => adapter.name)

  const sourceSuggestions = [...new Set([...BUILT_IN_SOURCES, ...bearerAdapters, ...Object.keys(correlation?.sources ?? {})])]
    .filter((source) => SOURCE_PATTERN.test(source))

  const creators = [...new Set((tokens ?? []).map((token) => token.created_by))].sort()
  const order: Record<TokenState, number> = { active: 0, expired: 1, revoked: 2 }

  const rows = (tokens ?? [])
    .filter((token) => creator === ANY_CREATOR || token.created_by === creator)
    .sort((a, b) => order[tokenState(a, now)] - order[tokenState(b, now)] || a.name.localeCompare(b.name))

  const handleRevoke = async () => {
    if (!revokeTarget) return
    setIsRevoking(true)
    setRevokeError(null)

    try {
      await revokeApiToken(revokeTarget.name)
      toast.success(`Token ${revokeTarget.name} revoked`)
      // Its revoke button disappears, so focus moves to the next action instead.
      revoked.current = true
      setRevokeTarget(null)
      await mutate()
    } catch (e) {
      setRevokeError(e instanceof Error ? serverErrors(e.message).join(" ") : "Failed to revoke the token")
    } finally {
      setIsRevoking(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardDescription className="max-w-prose text-pretty">
            Named credentials for detectors and automation. An ingest token posts events only as its
            source; operator and admin tokens act as those roles. Revoking takes effect on the next request.
          </CardDescription>
          <Button ref={createButton} size="sm" onClick={() => setCreateOpen(true)}>
            <Plus className="size-4" aria-hidden="true" />
            Create token
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {creators.length > 1 && (
          <div className="flex items-center gap-2 text-sm">
            <Label htmlFor="token-creator">Created by</Label>
            <Select value={creator} onValueChange={setCreator}>
              <SelectTrigger id="token-creator" className="h-8 w-48"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value={ANY_CREATOR}>Anyone</SelectItem>
                {creators.map((name) => <SelectItem key={name} value={name}>{name}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        )}
        {isLoading ? (
          <LoadingRows label="Loading API tokens" rows={3} />
        ) : error ? (
          <ErrorState
            title="Unable to load API tokens"
            detail="Tokens keep working; this view could not be refreshed. Retry before creating or revoking one."
            onRetry={() => { void mutate() }}
          />
        ) : rows.length > 0 ? (
          // relative keeps the sr-only header inside the scroller, so it cannot widen the page.
          <div className="relative overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs text-muted-foreground">
                  <th className="h-9 px-2 font-medium">Name</th>
                  <th className="h-9 px-2 font-medium">Scope</th>
                  <th className="h-9 px-2 font-medium">Source</th>
                  <th className="h-9 px-2 font-medium">POP</th>
                  <th className="h-9 px-2 font-medium">Created by</th>
                  <th className="h-9 px-2 font-medium">Created ({timeZone})</th>
                  <th className="h-9 px-2 font-medium">Last used</th>
                  <th className="h-9 px-2 font-medium">Expires</th>
                  <th className="h-9 px-2 font-medium">State</th>
                  <th className="w-10"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {rows.map((token) => {
                  const state = tokenState(token, now)

                  return (
                    <tr key={token.token_id} className="border-b border-border/50">
                      <td className="px-2 py-2 font-mono">{token.name}</td>
                      <td className="px-2 py-2"><Tag>{token.scope}</Tag></td>
                      <td className="px-2 py-2 font-mono">{token.source ?? MISSING}</td>
                      <td className="px-2 py-2 font-mono">{token.pop ?? "any"}</td>
                      <td className="px-2 py-2 text-muted-foreground">{token.created_by}</td>
                      <td className="px-2 py-2 text-xs tabular-nums text-muted-foreground"><time dateTime={token.created_at}>{formatTime(token.created_at)}</time></td>
                      <td className="px-2 py-2 text-xs tabular-nums text-muted-foreground">
                        {token.last_used_at ? <time dateTime={token.last_used_at} title={formatTime(token.last_used_at)}>{formatRelative(token.last_used_at, now)}</time> : "never"}
                      </td>
                      <td className="px-2 py-2 text-xs tabular-nums text-muted-foreground">
                        {token.expires_at ? <time dateTime={token.expires_at}>{formatTime(token.expires_at)}</time> : "never"}
                      </td>
                      <td className="px-2 py-2">
                        {state === "revoked" ? (
                          <StatusPill tone="neutral">
                            Revoked{token.revoked_by ? ` by ${token.revoked_by}` : ""}
                          </StatusPill>
                        ) : state === "expired" ? <StatusPill tone="warning">Expired</StatusPill> : <StatusPill tone="success">Active</StatusPill>}
                      </td>
                      <td className="px-2 py-2">
                        {state !== "revoked" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            className="size-8 p-0 text-muted-foreground hover:text-destructive"
                            aria-label={`Revoke ${token.name}`}
                            onClick={() => { setRevokeError(null); setRevokeTarget(token) }}
                          >
                            <Ban className="size-4" aria-hidden="true" />
                          </Button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="rounded-md border border-dashed">
            <EmptyState
              title={tokens && tokens.length > 0 ? "No tokens from this creator" : "No API tokens"}
              description={tokens && tokens.length > 0 ? "Choose another creator to see their tokens." : "Create one token per detector and per automation. A token is shown once, when it is created."}
            />
          </div>
        )}
      </CardContent>

      <CreateTokenDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        sources={sourceSuggestions}
        bearerAdapters={bearerAdapters}
        onCreated={() => { void mutate() }}
      />

      <AlertDialog open={revokeTarget !== null} onOpenChange={(open) => { if (!open && !isRevoking) setRevokeTarget(null) }}>
        <AlertDialogContent onCloseAutoFocus={(event) => {
          if (!revoked.current) return
          revoked.current = false
          event.preventDefault()
          createButton.current?.focus()
        }}>
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke {revokeTarget?.name}?</AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="space-y-2 text-pretty">
                <p>
                  {revokeTarget?.scope === "ingest" ? <>Bound to source <span className="font-mono">{revokeTarget.source}</span>. </> : <>Scope {revokeTarget?.scope}. </>}
                  Last used {revokeTarget?.last_used_at ? <time dateTime={revokeTarget.last_used_at}>{formatTime(revokeTarget.last_used_at)}</time> : "never"}.
                </p>
                <p>Every request with this token gets 401 from its next request on. Revoking cannot be undone, and the name is never reused.</p>
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          {revokeError && <p role="alert" className="break-words text-sm text-destructive">{revokeError}</p>}
          <AlertDialogFooter>
            <AlertDialogCancel disabled={isRevoking}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(event) => { event.preventDefault(); void handleRevoke() }}
              disabled={isRevoking}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {isRevoking ? <RefreshCw className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : null}
              Revoke
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Card>
  )
}

interface CreatedSecret {
  name: string
  scope: TokenScope
  source: string | null
  token: string
}

function CreateTokenDialog({ open, onOpenChange, sources, bearerAdapters, onCreated }: {
  open: boolean
  onOpenChange: (open: boolean) => void
  sources: string[]
  bearerAdapters: string[]
  onCreated: () => void
}) {
  const id = useId()
  const [name, setName] = useState("")
  const [scope, setScope] = useState<TokenScope>("ingest")
  const [source, setSource] = useState("")
  const [pop, setPop] = useState("")
  const [expiry, setExpiry] = useState<(typeof EXPIRY_DAYS)[number]>("never")
  const [submitted, setSubmitted] = useState(false)
  const [isCreating, setIsCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)
  // The secret lives only here, and only until the dialog closes (ADR 034 §9).
  const [created, setCreated] = useState<CreatedSecret | null>(null)
  const [copied, setCopied] = useState(false)
  const [confirmDiscard, setConfirmDiscard] = useState(false)

  const nameError = !NAME_PATTERN.test(name) ? "Lowercase letters, digits and hyphens, starting with a letter or digit; at most 58 characters." : null
  const sourceError = scope === "ingest" && !SOURCE_PATTERN.test(source) ? "An ingest token needs a source: lowercase letters, digits, hyphens and underscores." : null
  const popError = pop !== "" && !/^[!-~]{1,64}$/.test(pop) ? "1 to 64 printable characters without spaces." : null

  const reset = () => {
    setName("")
    setScope("ingest")
    setSource("")
    setPop("")
    setExpiry("never")
    setSubmitted(false)
    setError(null)
    setCreated(null)
    setCopied(false)
    setConfirmDiscard(false)
  }

  const close = () => {
    reset()
    onOpenChange(false)
  }

  const requestClose = () => {
    if (isCreating) return

    // Closing before the secret is copied loses it for good: ask once.
    if (created && !copied && !confirmDiscard) {
      setConfirmDiscard(true)

      return
    }

    close()
  }

  const handleSubmit = async (event: FormEvent) => {
    event.preventDefault()
    setSubmitted(true)

    if (nameError || sourceError || popError || isCreating) return
    setIsCreating(true)
    setError(null)

    const request: NewApiToken = { name, scope }

    if (scope === "ingest") request.source = source

    if (pop) request.pop = pop

    if (expiry !== "never") request.expires_at = new Date(Date.now() + Number(expiry) * 86_400_000).toISOString()

    try {
      const response = await createApiToken(request)

      setCreated({ name: response.name, scope: response.scope, source: response.source, token: response.token })
      // Refetch the list; the create response, which holds the secret, never enters the cache.
      onCreated()
    } catch (e) {
      setError(e instanceof Error ? serverErrors(e.message).join(" ") : "Failed to create the token")
    } finally {
      setIsCreating(false)
    }
  }

  const origin = typeof window === "undefined" ? "" : window.location.origin
  const snippets = created ? tokenSnippets(created, origin, bearerAdapters) : []

  return (
    <Dialog open={open} onOpenChange={(next) => { if (next) onOpenChange(true); else requestClose() }}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto bg-card sm:max-w-2xl">
        {created ? (
          // min-w-0 lets the snippets scroll inside the dialog instead of widening it.
          <div className="grid min-w-0 gap-4 [&>*]:min-w-0">
            <DialogHeader>
              <DialogTitle className="text-sm">Token {created.name} created</DialogTitle>
              <DialogDescription className="text-pretty text-xs">
                Copy the token now. It is shown only once: prefixd stores only its hash, and closing this dialog clears it.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5">
              <Label htmlFor={`${id}-secret`}>Token</Label>
              <div className="flex gap-2">
                <Input id={`${id}-secret`} readOnly value={created.token} className="h-9 font-mono text-xs" spellCheck={false} autoComplete="off" onFocus={(event) => event.currentTarget.select()} />
                <Button type="button" size="sm" className="h-9 shrink-0" autoFocus onClick={async () => {
                  if (await copy(created.token, "Token")) {
                    setCopied(true)
                    setConfirmDiscard(false)
                  }
                }}>
                  <Copy className="size-4" aria-hidden="true" />
                  Copy token
                </Button>
              </div>
            </div>
            <section aria-labelledby={`${id}-snippets`} className="space-y-3">
              <h3 id={`${id}-snippets`} className="text-xs font-semibold">Set up the client</h3>
              {snippets.map((snippet) => (
                <div key={snippet.title} className="space-y-1">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-xs font-medium">{snippet.title}</p>
                    <Button type="button" variant="ghost" size="sm" className="h-7" onClick={() => { void copy(snippet.text, snippet.title) }} aria-label={`Copy ${snippet.title}`}>
                      <Copy className="size-3.5" aria-hidden="true" />
                    </Button>
                  </div>
                  <pre className="whitespace-pre-wrap break-all rounded-md border bg-muted/40 p-2 font-mono text-xs">{snippet.text}</pre>
                </div>
              ))}
            </section>
            {confirmDiscard && (
              <div role="alert" className="space-y-2 rounded-md border border-warning/50 bg-warning/10 p-3 text-xs">
                <p>The token has not been copied. Once this dialog closes it cannot be shown again; you would have to create another token.</p>
                <div className="flex gap-2">
                  <Button type="button" size="sm" variant="outline" onClick={() => setConfirmDiscard(false)}>Keep it open</Button>
                  <Button type="button" size="sm" variant="destructive" onClick={close}>Close without copying</Button>
                </div>
              </div>
            )}
            <DialogFooter>
              <Button type="button" size="sm" onClick={requestClose}>Done</Button>
            </DialogFooter>
          </div>
        ) : (
          <form onSubmit={handleSubmit} noValidate className="grid min-w-0 gap-4">
            <DialogHeader>
              <DialogTitle className="text-sm">Create API token</DialogTitle>
              <DialogDescription className="text-pretty text-xs">
                Use one token per detector or automation, so each can be revoked on its own and audited as{" "}
                <span className="font-mono">token:&lt;name&gt;</span>.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-1.5">
              <Label htmlFor={`${id}-name`}>Name</Label>
              <Input id={`${id}-name`} value={name} onChange={(event) => setName(event.target.value)} placeholder="fnm-pop1" className="h-9 font-mono" spellCheck={false} autoComplete="off"
                aria-invalid={submitted && Boolean(nameError)} aria-describedby={`${id}-name-help`} />
              <p id={`${id}-name-help`} className={submitted && nameError ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
                {submitted && nameError ? nameError : "Unique forever: a revoked name is never reused."}
              </p>
            </div>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor={`${id}-scope`}>Scope</Label>
                <Select value={scope} onValueChange={(value) => { if (value === "ingest" || value === "operator" || value === "admin") setScope(value) }}>
                  <SelectTrigger id={`${id}-scope`} className="h-9"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ingest">ingest (a detector)</SelectItem>
                    <SelectItem value="operator">operator</SelectItem>
                    <SelectItem value="admin">admin</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              {scope === "ingest" && (
                <div className="space-y-1.5">
                  <Label htmlFor={`${id}-source`}>Source</Label>
                  <Input id={`${id}-source`} list={`${id}-sources`} value={source} onChange={(event) => setSource(event.target.value)} placeholder="fastnetmon" className="h-9 font-mono" spellCheck={false} autoComplete="off"
                    aria-invalid={submitted && Boolean(sourceError)} aria-describedby={`${id}-source-help`} />
                  <datalist id={`${id}-sources`}>
                    {sources.map((candidate) => <option key={candidate} value={candidate} />)}
                  </datalist>
                  <p id={`${id}-source-help`} className={submitted && sourceError ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
                    {submitted && sourceError ? sourceError : "The only source this token can post as."}
                  </p>
                </div>
              )}
            </div>
            {scope !== "ingest" && (
              <p className="text-xs text-muted-foreground">
                {scope === "admin" ? "An admin token reaches every Admin route except tokens, operator accounts and passwords." : "An operator token reaches what the Operator role reaches, except the ingest routes."}
              </p>
            )}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor={`${id}-pop`}>POP (optional)</Label>
                <Input id={`${id}-pop`} value={pop} onChange={(event) => setPop(event.target.value)} placeholder="any POP" className="h-9 font-mono" spellCheck={false} autoComplete="off"
                  aria-invalid={submitted && Boolean(popError)} aria-describedby={`${id}-pop-help`} />
                <p id={`${id}-pop-help`} className={submitted && popError ? "text-xs text-destructive" : "text-xs text-muted-foreground"}>
                  {submitted && popError ? popError : "Accepted only by controllers with this POP. Empty means every POP on this database."}
                </p>
              </div>
              <div className="space-y-1.5">
                <Label htmlFor={`${id}-expiry`}>Expiry</Label>
                <Select value={expiry} onValueChange={(value) => { const match = EXPIRY_DAYS.find((days) => days === value)

                  if (match) setExpiry(match) }}>
                  <SelectTrigger id={`${id}-expiry`} className="h-9" aria-describedby={`${id}-expiry-help`}><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="never">Never</SelectItem>
                    <SelectItem value="30">30 days</SelectItem>
                    <SelectItem value="90">90 days</SelectItem>
                    <SelectItem value="365">365 days</SelectItem>
                  </SelectContent>
                </Select>
                <p id={`${id}-expiry-help`} className="text-xs text-muted-foreground">A detector token that expires during an attack leaves it unmitigated.</p>
              </div>
            </div>
            {error && <p role="alert" className="break-words rounded-md border border-destructive/50 bg-destructive/10 p-2 text-xs text-destructive">{error}</p>}
            <DialogFooter>
              <Button type="button" variant="outline" size="sm" onClick={requestClose} disabled={isCreating}>Cancel</Button>
              <Button type="submit" size="sm" disabled={isCreating}>
                {isCreating ? <RefreshCw className="size-4 animate-spin motion-reduce:animate-none" aria-hidden="true" /> : null}
                Create token
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  )
}
