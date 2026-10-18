# Speaker profile qualification — 2026-10-18 UTC

## Earlier local-image checkpoint

Both Compose profiles passed on Linux/amd64 using the same locally built
controller image, `sha256:9a22c93f4a9e18461e1de281ed780ca7cafe658538b425e0a87c44bc1fa166df`.
This identifies the local qualification artifact; it is not a published registry
digest. The 108-file Docker input manifest has SHA-256
`88015e7e99dd0f299285a9d6359e7dbe5cd3f531098626e94d00febf5875fffd`.

The build used the pinned
`rust:1.99.1-trixie@sha256:e259494b14672950a909b4c54527e19d29cae6ebf980672114c8bb85e5594e4a`
builder. Cargo used three jobs; the actual builder, Cargo, Rust and C compiler
processes were observed on CPUs 32–63. This historical checkpoint recorded a
declared Rust 1.88 minimum. The current declared and CI-checked minimum is 1.89.0.
All owned build and runtime resources were cleaned afterward;
the local image and raw successful/failed receipts were retained.

Speaker pins:

- rustbgpd 0.77.0:
  `ghcr.io/lance0/rustbgpd:0.77.0@sha256:6dbfa42c47aa1d063f119f3eff9524aac4585665c0a9c79167ec8d20244bc6c2`.
- GoBGP 4.10.0, independently qualified image:
  `jauderho/gobgp@sha256:42b8d0017237e388c55936efe1f23632365b24a31751f6e8815f93e12c4d18c2`.

### Results

| Check | rustbgpd | GoBGP |
| --- | --- | --- |
| Actual UID/GID 999 controller and speaker | Passed | Passed |
| Private management | Owner-only directory 0700/socket 0600 | Shared namespace, loopback RPC only; no profiling/metrics listener |
| Credentials login and protected operational health | Passed | Passed |
| IPv4 discard and IPv6 policing at 8 Mbps, UDP ports 53/123, TTL 60 | Exact complete local inventories | Exact complete accepted local RIBs |
| Withdrawal, original actor/reason audit and raw absence | Passed; other-family control preserved | Passed; other-family control preserved |
| Inventory reload, playbook/correlation/alerting saves and backups | Passed | Passed |
| Recreated speaker/controller and persisted configuration | Passed | Passed, including namespace-owner recreation |
| Active rule after recreation | Same persisted ID, absolute expiry and exact rule; withdrawal/audit passed | Same persisted ID, absolute expiry and exact rule; withdrawal/audit passed |

The three Compose model/seeding checks passed with the built image, including
mutual-profile rejection before startup and preservation of existing edits.
Configuration tests passed 75 cases with all features and 75 with no default
features plus test utilities. Formatting, both strict Clippy configurations and
the GoBGP-only binary check passed. The shipped rustbgpd configuration passed the
pinned release's `--check --strict` with networking disabled. The dual-family
peer-restart case also passed against released rustbgpd 0.76.0 and 0.77.0.

### Scope and retained failures

The profile runs used preloaded images, an existing published dashboard and an
outbound-isolated network with ephemeral loopback HTTP. They exercised actual
authenticated API requests and local speaker state. Documentation peers remained
Idle; these runs do not establish router forwarding, browser behavior or a cold
quickstart timing guarantee. Rust read-back is retained local intent; GoBGP
read-back is its accepted local RIB.

Earlier failed runs were preserved and diagnosed: Docker copy-up reset private
empty-volume modes, saved correlation settings were ignored at startup, and
private harness assumptions about nginx ingress, numeric CLI spelling and an
`id` utility needed correction. Go now verifies all four kernel UID/GID fields.
The peer restart fixture also exposed Docker reallocating an automatically
published RPC port; reserving the existing fixture port preserves the client
endpoint. No failed oracle was weakened to obtain a passing result.

## Published-image checkpoint — 2026-10-18 UTC

The final Linux/amd64 checkpoint used published images from
[revision `50590d3a1b00d0757c2a0f08d4d727ade55ea7bc`](https://github.com/lance0/prefixd/commit/50590d3a1b00d0757c2a0f08d4d727ade55ea7bc).
[Exact-main CI](https://github.com/lance0/prefixd/actions/runs/39125031936)
passed all 11 jobs, including both image publications. Registry manifests and
OCI source/revision labels matched that revision:

- Controller:
  `ghcr.io/lance0/prefixd@sha256:6f30192f084f6b90582b8f43d7fbca4f527f0997abfe0fdf69536f0114d79eef`.
- Dashboard:
  `ghcr.io/lance0/prefixd-dashboard@sha256:cec82f4587437d50ea6bcb3498d85fc0a3a8e5551049ce1ab1ef78670f6ca01e`.

The profiles used their respective immutable rustbgpd 0.77.0 and GoBGP 4.10.0
pins listed above. Required components passed across separate owned fixtures. The GoBGP
driver exited 0; the rustbgpd driver exited 1 after its real checks because the
synthetic documentation phase failed, as recorded below.

### Published component results

| Check | rustbgpd | GoBGP |
| --- | --- | --- |
| Profile startup, private management, configuration saves/backups and recreation | Passed | Passed |
| Exact local rules, withdrawal/audit and active recovery with the same ID and absolute expiry | Passed; retained local intent | Passed; accepted local RIB |
| Credentials login and protected operational health | Passed | Passed |
| Metrics reachable by Prometheus but rejected through nginx/dashboard proxy, including encoded traversal cases | Passed | Passed |
| Prometheus/Grafana reachable on host loopback; denied through the non-loopback gateway with a reachable control | Passed | Passed |
| Desktop/mobile light and dark display, keyboard navigation/focus and reduced motion | Passed | Passed |
| Selected daemon display | Observed version, uptime and readiness | Process metadata shown as unsupported |
| Real browser login, active mitigation, confirmation kept open with submission disabled while pending, withdrawal, persisted/rendered audit and raw rule absence | Passed | Passed |
| Actual Chrome 200% zoom and keyboard cancellation | Passed | Not run in this checkpoint |
| Retained-cookie credentials/none transitions against the same PostgreSQL instance | Passed | Not run in this checkpoint |

Browser checks used Chrome 152.0.7977.75. The desktop/mobile matrix covered
1440×1080 and 390×844 in both themes. Eight sampled destructive button/badge
states had contrast ratios of at least 5.37:1; this is a targeted check, not an
accessibility certification. Loading, error/retry, correlated and empty states
used explicitly synthetic GET responses. Real withdrawal used the unchanged
[public smoke script](../../../frontend/scripts/smoke-withdraw.ts), SHA-256
`96107adf15da123eabb29641792b6fc24347f6b915c3035e3c0c4303441f402c`;
anonymous audit access returned 401 and confirmed withdrawals returned 200.

The actual zoom check changed Chrome's zoom to 2, with a 720×496.5 CSS visual
viewport. Target, reason, confidence and expiry remained visible; keyboard
cancellation restored focus. The separate 720×540/DPR-2 reflow check is recorded
as viewport emulation. In the same-PostgreSQL auth check, none mode hid the named
operator, returned 401 for identity and 403 for login, and preserved the existing
cookie until logout. Returning to credentials restored that session; logout in
none mode invalidated it, and a fresh credentials login succeeded.

### Retained attempts and documentation capture

All failed and diagnostic attempts remain retained:

- The initial private fixture placed monitoring services only on an internal
  network. Docker reported null runtime host bindings despite correct loopback
  HostConfig settings. Only the fixture's Prometheus/Grafana ingress attachment
  changed; the application images and shipped Compose model stayed unchanged.
- The first genuine 200% zoom probe compared a 496.5-pixel element bottom with
  integer `innerHeight` 496. A diagnostic run measured the actual visual viewport
  and CDP zoom: its height was 496.5 and the element fit exactly. The probe now
  uses strict visual-viewport bounds without an epsilon; no UI change was needed.
- The subsequent rustbgpd driver passed its real profile, visual, withdrawal,
  zoom and auth checks, then exited 1 because its synthetic screenshot fixture
  omitted `GET /v1/preferences`. Its post-documentation backend-isolation check
  was never reached. A separate corrected GET-only dashboard fixture completed
  the screenshot with no controller, PostgreSQL, real identities or backend
  writes. The earlier driver exit remains 1.

The approved overview image was a 1440×1100 light-theme capture from that
separate published-dashboard fixture. Its data is explicitly synthetic and
router installation is labelled unobserved. A later redesign replaced the
README screenshots; this capture remains in Git history under the hash below.
PNG SHA-256: `e3c84de9ea79e49c8105b57b42739a338c5efb280882f52550268055a1bc454b`.
The corrected documentation probe has SHA-256
`241c95e813944eed3f31f8be30892072de4ffeedf148489d86fe8fd83b29bf81`.
The retained aggregate has SHA-256
`2ade988641a7f2fbdc925891eece1c96996c7ce2b6331534a6198e4e5469eeb7`.

All owned browser/Compose containers, volumes and networks were removed,
including failed and diagnostic fixtures. These runs used available images;
controller and speaker networks were outbound-isolated, and example BGP peers
remained Idle. They establish local controller/speaker and browser behavior for
these artifacts, with no claim of
edge export, router installation, hardware forwarding, performance or a timed
cold quickstart.
