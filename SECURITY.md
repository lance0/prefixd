# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.8.x   | :white_check_mark: |
| < 0.8   | :x:                |

## Reporting a Vulnerability

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/lance0/prefixd/security)
2. Click "Report a vulnerability"
3. Fill out the form with details

Alternatively, email security concerns to the maintainers directly.

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

1. **Use strong API tokens** - Generate with `openssl rand -hex 32`
2. **Enable TLS** - Never expose HTTP API without encryption
3. **Network isolation** - Place prefixd on a management network
4. **Least privilege** - Use operator roles appropriately (admin/operator/viewer)
5. **Safelist infrastructure** - Add router loopbacks and critical IPs to safelist
6. **Monitor audit logs** - Review `/var/log/prefixd/audit.jsonl` regularly
7. **Keep updated** - Watch for security advisories

## Known Security Considerations

### BGP FlowSpec Risks

FlowSpec rules can drop traffic. Guardrails are in place to prevent:
- Overly broad prefixes (only /32 IPv4, /128 IPv6 allowed)
- Infrastructure disruption (safelist protection)
- Runaway rules (quotas, mandatory TTL)

### Authentication Modes

| Mode | Security Level | Use Case |
|------|---------------|----------|
| `none` | ⚠️ Insecure | Development only |
| `bearer` | ✅ Secure | Production API/CLI |
| `mtls` | ✅ Most Secure | Zero-trust environments |

### Dependencies

We use `cargo audit` in CI to check for known vulnerabilities. Current advisories are documented in the CI workflow with justification for any ignores.
