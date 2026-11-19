# ADR 035: Map directory groups to dashboard roles

## Status

Proposed, 2026-11-19. Draft implementation. Each installation configures one OIDC issuer.

## Context

A directory administrator wants group membership to determine access to
prefixd. The existing roles are `viewer`, `operator` and `admin`.
For example, a network operations group could receive `operator` access
while an audit group receives `viewer` access.

[ADR 008](008-session-auth-plus-bearer.md) listed AD login as future work.
Credentials mode checks a PostgreSQL operator's password and opens an
axum-login session. The [auth backend](../../src/auth/backend.rs) uses the
operator UUID as the session identity and the password hash for invalidation.
The old LDAP configuration was a placeholder and was removed in version 0.20.0.

## Proposed integration

Configure one issuer in credentials mode and issue the dashboard session in the Rust controller. The [setup guide](../how-to/oidc.md) describes Entra and Keycloak configurations.

- **Microsoft Entra ID or another OIDC issuer backed by AD.** Prefer an OIDC
  authorization-code callback in the Rust controller. With Entra, define app
  roles for prefixd and assign directory groups to them. For example, assign
  the audit group to an app role with value `prefixd.viewer`. The controller
  maps that exact value from the validated ID token to `viewer`. Group-based
  assignment requires an eligible Entra license. [App role setup](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)
- **AD Domain Services with LDAP only.** This requires a separate directory
  integration. Confirm the domain and whether nested or primary group
  membership must count. Direct `memberOf` values omit the primary group.
  AD's computed `tokenGroups` can return transitive security group SIDs,
  including the primary group, and requires a Global Catalog. A direct
  implementation would need authenticated TLS, a verified user identity
  and exact group SID mappings. [AD security attributes](https://learn.microsoft.com/en-us/windows/win32/ad/security-properties)

Better Auth's Microsoft provider could handle the Entra sign-in in the
Next.js service. Rust would then need a trusted exchange binding that identity
and its verified role claims to a prefixd session. The dashboard and API would
also need coordinated expiry and logout. For this one application, putting the
OIDC callback beside the existing session issuer avoids that exchange. The
Microsoft provider itself expects an Entra application registration.
[Better Auth Microsoft provider](https://better-auth.com/docs/authentication/microsoft)

## Authorization and acceptance criteria

- Pin the issuer, tenant and client. Use state, nonce and PKCE, and validate
  the ID token signature, issuer, audience and expiry before reading claims.
  Identify a directory user by issuer and subject. A matching local username
  or email must never link the accounts automatically.
- Grant a session only when the verified assignments resolve to one distinct
  configured role. Two groups mapping to the same role are unambiguous.
  Missing assignments or matches for both viewer and admin deny login.
  For raw group IDs, an overage marker means membership
  is incomplete. [Entra group claims](https://learn.microsoft.com/en-us/security/zero-trust/develop/configure-tokens-group-claims-app-roles)
- Give external identities their own revocable session version. Limit the directory grant to the earlier of the ID token expiry and one hour. At expiry require fresh provider authorization,
  including for an open dashboard WebSocket. Verify local emergency admin
  access during an issuer outage.
- Exercise all three roles through the dashboard and direct API requests.
  Verify access after group removal, conflicting assignments, a wrong tenant,
  a local username collision and logout. Check that audit attributes actions
  to the same operator UUID after a directory display-name change. Keep
  machine credentials under [ADR 034](034-source-bound-api-tokens.md).
