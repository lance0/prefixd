# Connect a dashboard to an OpenID Connect provider

Register prefixd as a confidential web application with the installation's
identity provider. Register the exact callback URL below, replacing
`prefixd.example.org` with the dashboard's public HTTPS hostname. The browser
and controller both need to reach the issuer. Set the client secret in the
controller process environment. For Compose, pass the variable to the selected
controller service and recreate that service.

Add one `oidc` block under the existing `http.auth` in `prefixd.yaml`:

```yaml
http:
  auth:
    mode: credentials
    oidc:
      issuer: https://login.microsoftonline.com/YOUR-TENANT-ID/v2.0
      client_id: YOUR-APPLICATION-ID
      client_secret_env: PREFIXD_OIDC_SECRET
      redirect_uri: https://prefixd.example.org/api/prefixd/v1/auth/oidc/callback
      role_claim: roles
      role_mappings:
        prefixd.viewer: viewer
        prefixd.operator: operator
        prefixd.admin: admin
```

**Entra ID.** Define app roles with the three values above in the app
registration. Under Enterprise applications, assign each directory group to
its intended app role. Entra sends these assignments in the ID token's
`roles` array. Group-based assignment requires an eligible Entra license.
[Microsoft app role setup](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps)

**Keycloak.** Create an OpenID Connect client with client authentication and
standard flow enabled. Register the same callback. Add a Group Membership
mapper on the client's dedicated scope with token claim name `groups`,
inclusion in the ID token enabled and full group path enabled. Replace the
issuer with the realm issuer (such as `https://sso.example.org/realms/network`),
supply the Keycloak client ID and secret, and use the following mapping in
the connection:

```yaml
role_claim: groups
role_mappings:
  /netops/audit: viewer
  /netops/on-call: operator
```

A provider that requires an optional scope to emit the claim can request it
with `extra_scopes: [groups]`. A claim name alone does not imply a scope.
The controller always requests `openid`.

Restart prefixd and choose **Sign in with SSO** on the dashboard. After
login, inspect the account menu or `GET /v1/auth/me` for the effective role.
The controller log distinguishes a missing or malformed claim, no matching
group, and conflicting roles. Use a top-level ID token claim containing an
array of strings. Matching is exact and case-sensitive. Multiple matching
values must grant the same role.

The issuer and subject identify the operator. Its generated `oidc:` username
is stable across subsequent logins. The session expires at the earlier of
the ID token expiry and one hour after login. A successful new login replaces that operator's
previous HTTP session grant with the current role. Removing all mapped groups
denies the next login. An already-issued grant can last until its deadline. An already-open feed closes by its original
deadline. Changing or removing the OIDC configuration invalidates existing SSO
sessions on restart. Local credential login remains available for recovery.

Select a provider that exposes OIDC. An installation with LDAP alone needs
an identity service in front of the directory.
