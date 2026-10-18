"use client"

import { useState } from "react"
import { useSWRConfig } from "swr"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { StatusPill, healthTone } from "@/components/dashboard/status-pill"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { useHealthDetail, useSafelist, useStats, usePops, useOperators } from "@/hooks/use-api"
import { addSafelist, removeSafelist, reloadConfig, createOperator, deleteOperator, changePassword, type OperatorInfo } from "@/lib/api"
import { usePermissions } from "@/hooks/use-permissions"
import { useAuth } from "@/hooks/use-auth"
import { useTabParam } from "@/hooks/use-tab-param"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  AlertCircle,
  RefreshCw,
  Plus,
  Trash2,
  Key,
} from "lucide-react"
import { PageHeader } from "@/components/dashboard/page-header"
import { EmptyState, ErrorState, LoadingRows } from "@/components/dashboard/states"
import { Tag } from "@/components/dashboard/status-pill"
import { MISSING, formatUtc } from "@/lib/format"

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor((seconds % 86400) / 3600)
  const mins = Math.floor((seconds % 3600) / 60)

  if (days > 0) return `${days}d ${hours}h`

  if (hours > 0) return `${hours}h ${mins}m`

  return `${mins}m`
}

function LoadingCard({ title }: { title: string }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <LoadingRows label={`Loading ${title.toLowerCase()}`} rows={2} />
    </Card>
  )
}

function ErrorCard({ title, error, onRetry }: { title: string; error: string; onRetry: () => void }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <ErrorState
        title={error}
        detail="This does not mean the service is down. Retrying automatically; retry now, or check that the controller is reachable."
        onRetry={onRetry}
      />
    </Card>
  )
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-3 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd>{children}</dd>
    </div>
  )
}

const TABS = ["status", "safelist", "users"] as const
const TABS_WITHOUT_USERS = ["status", "safelist"] as const

export default function AdminPage() {
  const { mutate } = useSWRConfig()
  const { operator } = useAuth()
  const permissions = usePermissions()
  const [activeTab, setActiveTab] = useTabParam(permissions.canManageUsers ? TABS : TABS_WITHOUT_USERS)
  const { data: health, error: healthError, isLoading: healthLoading, isStale: healthStale, mutate: mutateHealth } = useHealthDetail()
  const { data: stats, error: statsError, isLoading: statsLoading, mutate: mutateStats } = useStats()
  const { data: safelist, error: safelistError, isLoading: safelistLoading, mutate: mutateSafelist } = useSafelist()
  const { data: pops, error: popsError, isLoading: popsLoading, mutate: mutatePops } = usePops()
  const { data: operators, error: operatorsError, isLoading: operatorsLoading, mutate: mutateOperators } = useOperators()

  const [newPrefix, setNewPrefix] = useState("")
  const [newReason, setNewReason] = useState("")
  const [isAddingSafelist, setIsAddingSafelist] = useState(false)
  const [safelistError2, setSafelistError2] = useState<string | null>(null)
  const [isReloading, setIsReloading] = useState(false)
  const [reloadStatus, setReloadStatus] = useState<"idle" | "success" | "error">("idle")

  // User management state
  const [showCreateUser, setShowCreateUser] = useState(false)
  const [newUsername, setNewUsername] = useState("")
  const [newPassword, setNewPassword] = useState("")
  const [newRole, setNewRole] = useState<"admin" | "operator" | "viewer">("operator")
  const [isCreatingUser, setIsCreatingUser] = useState(false)
  const [userError, setUserError] = useState<string | null>(null)

  // Change password state
  const [passwordTarget, setPasswordTarget] = useState<OperatorInfo | null>(null)
  const [newUserPassword, setNewUserPassword] = useState("")
  const [currentPassword, setCurrentPassword] = useState("")
  const [isChangingPassword, setIsChangingPassword] = useState(false)

  const handleAddSafelist = async () => {
    if (!newPrefix.trim()) return
    
    setIsAddingSafelist(true)
    setSafelistError2(null)
    
    try {
      await addSafelist(newPrefix.trim(), newReason.trim(), "dashboard")
      await mutateSafelist()
      setNewPrefix("")
      setNewReason("")
    } catch (err) {
      setSafelistError2(err instanceof Error ? err.message : "Failed to add prefix")
    } finally {
      setIsAddingSafelist(false)
    }
  }

  const handleRemoveSafelist = async (prefix: string) => {
    try {
      await removeSafelist(prefix)
      await mutateSafelist()
    } catch (err) {
      setSafelistError2(err instanceof Error ? err.message : "Failed to remove prefix")
    }
  }

  const handleReloadConfig = async () => {
    setIsReloading(true)
    setReloadStatus("idle")
    
    try {
      await reloadConfig()
      setReloadStatus("success")
      // Refresh all data
      mutate(() => true)
      setTimeout(() => setReloadStatus("idle"), 3000)
    } catch {
      setReloadStatus("error")
      setTimeout(() => setReloadStatus("idle"), 3000)
    } finally {
      setIsReloading(false)
    }
  }

  const handleCreateUser = async () => {
    if (!newUsername.trim() || !newPassword.trim()) return
    
    setIsCreatingUser(true)
    setUserError(null)
    
    try {
      await createOperator(newUsername.trim(), newPassword, newRole)
      await mutateOperators()
      setShowCreateUser(false)
      setNewUsername("")
      setNewPassword("")
      setNewRole("operator")
    } catch (err) {
      setUserError(err instanceof Error ? err.message : "Failed to create user")
    } finally {
      setIsCreatingUser(false)
    }
  }

  const handleDeleteUser = async (op: OperatorInfo) => {
    try {
      await deleteOperator(op.operator_id)
      await mutateOperators()
    } catch (err) {
      setUserError(err instanceof Error ? err.message : "Failed to delete user")
    }
  }

  const handleChangePassword = async () => {
    if (!passwordTarget || !newUserPassword.trim()) return

    if (operator?.id === passwordTarget.operator_id && !currentPassword.trim()) return

    setIsChangingPassword(true)
    setUserError(null)

    try {
      await changePassword(
        passwordTarget.operator_id,
        newUserPassword,
        operator?.id === passwordTarget.operator_id ? currentPassword : undefined
      )
      setPasswordTarget(null)
      setNewUserPassword("")
      setCurrentPassword("")
    } catch (err) {
      setUserError(err instanceof Error ? err.message : "Failed to change password")
    } finally {
      setIsChangingPassword(false)
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Administration"
        description="Controller health, the safelist and operator accounts."
        actions={
          <>
            {reloadStatus !== "idle" && (
              <span role="status" className={reloadStatus === "error" ? "text-sm text-destructive" : "text-sm text-muted-foreground"}>
                {reloadStatus === "success" ? "Configuration reloaded" : "Reload failed"}
              </span>
            )}
            <Button variant="outline" size="sm" onClick={handleReloadConfig} disabled={isReloading}>
              <RefreshCw className={isReloading ? "size-4 animate-spin" : "size-4"} aria-hidden="true" />
              Reload configuration
            </Button>
          </>
        }
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="status">Status</TabsTrigger>
          <TabsTrigger value="safelist">
            Safelist
            {safelist && safelist.length > 0 && (
              <Badge variant="secondary">{safelist.length}</Badge>
            )}
          </TabsTrigger>
          {permissions.canManageUsers && (
            <TabsTrigger value="users">Users</TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="status" className="mt-4 space-y-6">
          <section aria-labelledby="system-status" className="space-y-3">
            <h2 id="system-status" className="text-sm font-semibold">System status</h2>
            <div className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
              {healthLoading ? (
                <LoadingCard title="Daemon status" />
              ) : healthError ? (
                <ErrorCard title="Daemon status" error="Unable to reach the controller" onRetry={() => { void mutateHealth() }} />
              ) : healthStale ? (
                <ErrorCard title="Daemon status" error="Health observation is stale" onRetry={() => { void mutateHealth() }} />
              ) : health ? (
                <Card>
                  <CardHeader>
                    <CardTitle>Daemon status</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <dl className="space-y-2">
                      <Row label="Status"><StatusPill tone={healthTone(health.status)}>{health.status}</StatusPill></Row>
                      <Row label="Version"><span className="font-mono">{health.version || "dev"}</span></Row>
                      <Row label="POP"><span className="font-mono">{health.pop}</span></Row>
                      <Row label="Uptime"><span className="tabular-nums">{formatUptime(health.uptime_seconds)}</span></Row>
                    </dl>
                  </CardContent>
                </Card>
              ) : null}

              {healthLoading ? (
                <LoadingCard title="BGP peers" />
              ) : healthError ? (
                <ErrorCard title="BGP peers" error="Unable to reach the controller" onRetry={() => { void mutateHealth() }} />
              ) : healthStale ? (
                <ErrorCard title="BGP peers" error="Health observation is stale" onRetry={() => { void mutateHealth() }} />
              ) : health ? (
                <Card>
                  <CardHeader>
                    <CardTitle>BGP peers</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-2">
                    {health.speaker?.capabilities.rule_reader === false && (
                      <p className="text-sm text-muted-foreground">Rule observation is unsupported by this speaker</p>
                    )}
                    {health.gobgp.status === "unsupported" ? (
                      <p className="text-sm text-muted-foreground">BGP peer observation is unsupported by this speaker</p>
                    ) : health.gobgp.status !== "connected" ? (
                      <p className="text-sm text-destructive" role="alert">BGP peer observation failed{health.gobgp.error ? `: ${health.gobgp.error}` : ""}</p>
                    ) : Object.keys(health.bgp_sessions).length > 0 ? (
                      <dl className="space-y-2">
                        {Object.entries(health.bgp_sessions).map(([peer, state]) => (
                          <div key={peer} className="flex items-center justify-between gap-3 text-sm">
                            <dt className="font-mono">{peer}</dt>
                            <dd><StatusPill tone={healthTone(state)}>{state}</StatusPill></dd>
                          </div>
                        ))}
                      </dl>
                    ) : (
                      <p className="text-sm text-muted-foreground">No BGP peers configured</p>
                    )}
                  </CardContent>
                </Card>
              ) : null}

              {statsLoading ? (
                <LoadingCard title="Current usage" />
              ) : statsError ? (
                <ErrorCard title="Current usage" error="Unable to load usage" onRetry={() => { void mutateStats() }} />
              ) : stats ? (
                <Card>
                  <CardHeader>
                    <CardTitle>Current usage</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <dl className="space-y-2">
                      <Row label="Active mitigations"><span className="tabular-nums">{stats.total_active}</span></Row>
                      <Row label="Total mitigations"><span className="tabular-nums">{stats.total_mitigations}</span></Row>
                      <Row label="Total events"><span className="tabular-nums">{stats.total_events}</span></Row>
                    </dl>
                  </CardContent>
                </Card>
              ) : null}
            </div>
          </section>

          <section aria-labelledby="points-of-presence" className="space-y-3">
            <h2 id="points-of-presence" className="text-sm font-semibold">Points of presence</h2>
            {popsLoading ? (
              <LoadingCard title="POPs" />
            ) : popsError ? (
              <ErrorCard title="POPs" error="Unable to load POPs" onRetry={() => { void mutatePops() }} />
            ) : pops && pops.length > 0 ? (
              <Card>
                <CardContent className="flex flex-wrap gap-2">
                  {pops.map((pop) => (
                    <span key={pop.pop} className="inline-flex items-center gap-2 rounded-sm border px-2 py-0.5 text-sm">
                      <span className="font-mono">{pop.pop}</span>
                      <span className="text-muted-foreground tabular-nums">{pop.active_mitigations} active</span>
                    </span>
                  ))}
                </CardContent>
              </Card>
            ) : (
              <Card>
                <EmptyState
                  title="No POPs reported"
                  description="A POP is listed once a mitigation has been recorded for it in this database."
                />
              </Card>
            )}
          </section>
        </TabsContent>

        {/* Safelist Tab */}
        <TabsContent value="safelist" className="mt-4">
          <Card>
            <CardHeader>
              <CardDescription className="text-pretty">
                Protected prefixes that will never be mitigated. Add infrastructure IPs, router loopbacks, and critical services.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Add new entry */}
              <div className="flex gap-2">
                <Input
                  placeholder="Prefix (e.g., 10.0.0.1/32)"
                  value={newPrefix}
                  onChange={(e) => setNewPrefix(e.target.value)}
                  className="font-mono flex-1"
                />
                <Input
                  placeholder="Reason (optional)"
                  value={newReason}
                  onChange={(e) => setNewReason(e.target.value)}
                  className="flex-1"
                />
                <Button
                  onClick={handleAddSafelist}
                  disabled={!newPrefix.trim() || isAddingSafelist}
                  size="sm"
                >
                  {isAddingSafelist ? (
                    <RefreshCw className="size-4 animate-spin" />
                  ) : (
                    <>
                      <Plus className="size-4 mr-1" />
                      Add
                    </>
                  )}
                </Button>
              </div>

              {safelistError2 && (
                <div className="flex items-center gap-2 text-destructive text-sm">
                  <AlertCircle className="size-4" />
                  {safelistError2}
                </div>
              )}

              {/* Safelist table */}
              {safelistLoading ? (
                <LoadingRows label="Loading safelist" rows={3} />
              ) : safelistError ? (
                <ErrorState title="Unable to load the safelist" detail="Safelist entries still apply; this view could not be refreshed. Retry before adding or removing prefixes." onRetry={() => { void mutateSafelist() }} />
              ) : safelist && safelist.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Prefix</th>
                        <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Reason</th>
                        <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Added by</th>
                        <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Added (UTC)</th>
                        <th className="w-10"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {safelist.map((entry) => (
                        <tr key={entry.prefix} className="border-b border-border/50 hover:bg-secondary/50">
                          <td className="py-2 px-2 font-mono text-foreground">{entry.prefix}</td>
                          <td className="py-2 px-2 text-muted-foreground truncate max-w-48">{entry.reason || MISSING}</td>
                          <td className="py-2 px-2 text-muted-foreground">{entry.added_by}</td>
                          <td className="py-2 px-2 text-muted-foreground text-xs tabular-nums">
                            <time dateTime={entry.added_at}>{formatUtc(entry.added_at)}</time>
                          </td>
                          <td className="py-2 px-2">
                            <AlertDialog>
                              <AlertDialogTrigger asChild>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  className="size-8 p-0 text-muted-foreground hover:text-destructive"
                                  aria-label={`Remove ${entry.prefix} from safelist`}
                                >
                                  <Trash2 className="size-4" />
                                </Button>
                              </AlertDialogTrigger>
                              <AlertDialogContent>
                                <AlertDialogHeader>
                                  <AlertDialogTitle>Remove from safelist?</AlertDialogTitle>
                                  <AlertDialogDescription className="text-pretty">
                                    This will allow <span className="font-mono">{entry.prefix}</span> to be mitigated
                                    if an attack is detected. This action cannot be undone.
                                  </AlertDialogDescription>
                                </AlertDialogHeader>
                                <AlertDialogFooter>
                                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                                  <AlertDialogAction
                                    onClick={() => handleRemoveSafelist(entry.prefix)}
                                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                  >
                                    Remove
                                  </AlertDialogAction>
                                </AlertDialogFooter>
                              </AlertDialogContent>
                            </AlertDialog>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="rounded-md border border-dashed">
                  <EmptyState
                    title="No safelist entries"
                    description="Every prefix can be mitigated. Add a prefix above to protect it from automated mitigation."
                  />
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Users Tab (admin only) */}
        {permissions.canManageUsers && (
          <TabsContent value="users" className="mt-4">
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardDescription className="text-pretty">
                    Manage operator accounts and permissions.
                  </CardDescription>
                  <Dialog open={showCreateUser} onOpenChange={setShowCreateUser}>
                    <DialogTrigger asChild>
                      <Button size="sm">
                        <Plus className="size-4 mr-1" />
                        Add user
                      </Button>
                    </DialogTrigger>
                    <DialogContent>
                      <DialogHeader>
                        <DialogTitle>Create operator</DialogTitle>
                        <DialogDescription>
                          Add a new operator account.
                        </DialogDescription>
                      </DialogHeader>
                      <div className="space-y-4 py-4">
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Username</label>
                          <Input
                            placeholder="username"
                            value={newUsername}
                            onChange={(e) => setNewUsername(e.target.value)}
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Password</label>
                          <Input
                            type="password"
                            placeholder="minimum 8 characters"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                          />
                        </div>
                        <div className="space-y-2">
                          <label className="text-sm font-medium">Role</label>
                          <Select value={newRole} onValueChange={(v: "admin" | "operator" | "viewer") => setNewRole(v)}>
                            <SelectTrigger>
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="viewer">Viewer (read-only)</SelectItem>
                              <SelectItem value="operator">Operator (can withdraw)</SelectItem>
                              <SelectItem value="admin">Admin (full access)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        {userError && (
                          <div className="flex items-center gap-2 text-destructive text-sm">
                            <AlertCircle className="size-4" />
                            {userError}
                          </div>
                        )}
                      </div>
                      <DialogFooter>
                        <Button variant="outline" onClick={() => setShowCreateUser(false)}>
                          Cancel
                        </Button>
                        <Button
                          onClick={handleCreateUser}
                          disabled={!newUsername.trim() || newPassword.length < 8 || isCreatingUser}
                        >
                          {isCreatingUser ? (
                            <RefreshCw className="size-4 animate-spin" />
                          ) : (
                            "Create"
                          )}
                        </Button>
                      </DialogFooter>
                    </DialogContent>
                  </Dialog>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {operatorsLoading ? (
                  <LoadingRows label="Loading operators" rows={3} />
                ) : operatorsError ? (
                  <ErrorState title="Unable to load operators" detail="Accounts are unchanged; this view could not be refreshed. Retry to reload." onRetry={() => { void mutateOperators() }} />
                ) : operators && operators.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-border">
                          <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Username</th>
                          <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Role</th>
                          <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Created</th>
                          <th className="h-9 px-2 text-left text-xs font-medium text-muted-foreground">Last login</th>
                          <th className="w-20"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {operators.map((op) => (
                          <tr key={op.operator_id} className="border-b border-border/50 hover:bg-secondary/50">
                            <td className="py-2 px-2 text-foreground">
                              {op.username}
                              {operator?.id === op.operator_id && (
                                <span className="ml-2 text-xs text-muted-foreground">(you)</span>
                              )}
                            </td>
                            <td className="py-2 px-2">
                              <Tag>{op.role}</Tag>
                            </td>
                            <td className="py-2 px-2 text-muted-foreground text-xs tabular-nums">
                              <time dateTime={op.created_at}>{formatUtc(op.created_at)}</time>
                            </td>
                            <td className="py-2 px-2 text-muted-foreground text-xs tabular-nums">
                              {op.last_login_at ? <time dateTime={op.last_login_at}>{formatUtc(op.last_login_at)}</time> : MISSING}
                            </td>
                            <td className="py-2 px-2 flex gap-1">
                              <Button
                                variant="ghost"
                                size="sm"
                                className="size-8 p-0 text-muted-foreground hover:text-foreground"
                                onClick={() => setPasswordTarget(op)}
                                aria-label={`Change password for ${op.username}`}
                              >
                                <Key className="size-4" />
                              </Button>
                              {operator?.id !== op.operator_id && (
                                <AlertDialog>
                                  <AlertDialogTrigger asChild>
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      className="size-8 p-0 text-muted-foreground hover:text-destructive"
                                      aria-label={`Delete ${op.username}`}
                                    >
                                      <Trash2 className="size-4" />
                                    </Button>
                                  </AlertDialogTrigger>
                                  <AlertDialogContent>
                                    <AlertDialogHeader>
                                      <AlertDialogTitle>Delete operator?</AlertDialogTitle>
                                      <AlertDialogDescription className="text-pretty">
                                        This will permanently delete the operator <span className="font-medium">{op.username}</span>.
                                        This action cannot be undone.
                                      </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                      <AlertDialogCancel>Cancel</AlertDialogCancel>
                                      <AlertDialogAction
                                        onClick={() => handleDeleteUser(op)}
                                        className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                                      >
                                        Delete
                                      </AlertDialogAction>
                                    </AlertDialogFooter>
                                  </AlertDialogContent>
                                </AlertDialog>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="rounded-md border border-dashed">
                    <EmptyState
                      title="No operators configured"
                      description="Create an operator account to give someone access to this dashboard."
                    />
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>

      {/* Change Password Dialog (outside tabs - floating dialog) */}
      <Dialog open={!!passwordTarget} onOpenChange={(open) => !open && setPasswordTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Change password</DialogTitle>
            <DialogDescription>
              Set a new password for <span className="font-medium">{passwordTarget?.username}</span>.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            {operator?.id === passwordTarget?.operator_id && (
              <div className="space-y-2">
                <label className="text-sm font-medium">Current password</label>
                <Input
                  type="password"
                  placeholder="enter your current password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                />
              </div>
            )}
            <div className="space-y-2">
              <label className="text-sm font-medium">New password</label>
              <Input
                type="password"
                placeholder="minimum 8 characters"
                value={newUserPassword}
                onChange={(e) => setNewUserPassword(e.target.value)}
              />
            </div>
            {userError && (
              <div className="flex items-center gap-2 text-destructive text-sm">
                <AlertCircle className="size-4" />
                {userError}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setPasswordTarget(null)}>
              Cancel
            </Button>
            <Button
              onClick={handleChangePassword}
              disabled={
                newUserPassword.length < 8 ||
                isChangingPassword ||
                (operator?.id === passwordTarget?.operator_id && currentPassword.length === 0)
              }
            >
              {isChangingPassword ? (
                <RefreshCw className="size-4 animate-spin" />
              ) : (
                "Change password"
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
