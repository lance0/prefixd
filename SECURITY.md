# Security Policy

## Supported Versions

Security fixes target the latest released minor series. Upgrade older series
to the [latest release](https://github.com/lance0/prefixd/releases/latest);
older series do not receive backports.

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of these methods:

1. **Email:** [lance@lance0.com](mailto:lance@lance0.com)
2. **GitHub:** Use [private vulnerability reporting](https://github.com/lance0/prefixd/security/advisories/new)

### What to Include

- Type of vulnerability (e.g., authentication bypass, injection, DoS)
- Full paths of source files related to the vulnerability
- Step-by-step instructions to reproduce
- Proof-of-concept or exploit code (if possible)
- Impact assessment

### Response Timeline

- **Initial response**: Within 48 hours
- **Status update**: Within 7 days
- **Fix timeline**: Depends on severity, typically 30-90 days

### Safe Harbor

We consider security research conducted in accordance with this policy to be:

- Authorized and not subject to legal action
- Conducted in good faith
- Helpful to the security of the project

## Security Best Practices

When deploying prefixd:

1. **Configure authentication** - Use operator credentials with named API tokens
   (`prefixdctl tokens create`), or native client-certificate mTLS.
2. **Enable TLS** - Never expose HTTP API without encryption
3. **Network isolation** - Place prefixd on a management network
4. **Least privilege** - Use operator roles appropriately (admin/operator/viewer)
5. **Safelist infrastructure** - Add router loopbacks and critical IPs to safelist
6. **Review the audit trail** - Use the dashboard Audit Log or `GET /v1/audit`
   with operator or administrator access. Production audit entries are stored
   in PostgreSQL, not a JSONL file.
7. **Keep updated** - Watch for security advisories

## Known Security Considerations

### BGP FlowSpec Risks

FlowSpec rules can drop traffic. The default guardrails restrict destinations
to /32 IPv4 and /128 IPv6 hosts, require a TTL, check the safelist and limit rule
counts and ports. Prefix bounds, TTL requirements and quotas are configurable;
review the [running configuration](docs/reference/configuration.md) before
enabling announcements.

Expiry requires a running controller and reconciliation. The separate BGP
speaker can retain advertisements after prefixd stops; a TTL is not a speaker
lease. The shipped rustbgpd config adds FlowSpec rules under the rustbgpd
injection lease, so rustbgpd withdraws them within one lease after prefixd
stops; GoBGP and unleased rules have no such cleanup. See
[controller and speaker failures](docs/adr/003-fail-open-ttl.md).

### Authentication Modes

| Mode | Behavior |
|------|----------|
| `none` | Bypasses authentication and role checks. Use only in an isolated development or test environment. |
| `credentials` | Operator passwords and PostgreSQL-backed sessions with viewer, operator and administrator roles, plus named API tokens stored as hashes, scoped to `ingest`, `operator` or `admin`, optionally bound to a POP and revocable at once. |
| `mtls` | Requires native TLS and verified client certificates; accepted clients receive administrator access. Forwarded certificate headers do not authenticate a client. |

Use TLS for credentials, session cookies and API tokens. See the
[authentication reference](docs/reference/configuration.md#authentication) and
[security model](docs/explanation/architecture.md#security-model) for deployment
details.

### Monitoring Network Boundary

`/metrics` is unauthenticated on the API listener. Default Compose leaves that
listener unpublished and blocks metrics through nginx and the dashboard proxy.
This does not authenticate scrapes: direct API access must stay on a trusted
management network.

Prometheus and Grafana publish only on host loopback by default, at ports 9091
and 3001. Remote access needs an operator-controlled tunnel or authenticated
proxy. These bindings do not restrict other processes on the host.

### Dependencies

We use `cargo audit` in CI to check for known vulnerabilities. Current advisories are documented in the CI workflow with justification for any ignores.
