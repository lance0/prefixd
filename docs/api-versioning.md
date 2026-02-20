# API Versioning Policy

## Overview

All prefixd API endpoints are versioned under a `/v1/` prefix. This document describes the versioning policy, backward compatibility guarantees, and deprecation process.

## Version Format

API versions use a simple integer prefix: `/v1/`, `/v2/`, etc.

The current stable version is **v1**.

## Backward Compatibility

Within a major version (e.g., v1), the following changes are considered **non-breaking** and may be introduced at any time:

- Adding new endpoints
- Adding new optional query parameters
- Adding new fields to JSON response bodies
- Adding new enum values to response fields
- Relaxing validation constraints (e.g., accepting a wider range of values)
- Adding new HTTP headers

The following changes are **breaking** and require a new major version:

- Removing or renaming endpoints
- Removing or renaming response fields
- Changing the type of an existing response field
- Adding required request fields
- Changing authentication requirements
- Changing error response structure

## Deprecation Process

When an endpoint or feature is scheduled for removal:

1. **Announce** — The deprecation is noted in the CHANGELOG and release notes at least **2 minor releases** before removal.
2. **Header** — Deprecated endpoints include a `Sunset` response header with the planned removal date ([RFC 8594](https://www.rfc-editor.org/rfc/rfc8594)).
3. **Docs** — The endpoint is marked as deprecated in `docs/api.md` and the OpenAPI spec.
4. **Remove** — The endpoint is removed in the next major version.

Example `Sunset` header:

```
Sunset: Sat, 01 Jan 2028 00:00:00 GMT
Deprecation: true
```

## Current Status

| Version | Status | Notes |
|---------|--------|-------|
| v1 | **Stable** | Current and only version |

No endpoints are currently deprecated.

## Client Recommendations

- Always specify the version prefix in API calls (`/v1/health`, not `/health`)
- Ignore unknown JSON fields in responses (forward compatibility)
- Check for `Sunset` headers in responses to detect deprecation early
- Pin to a specific API version in automation scripts
