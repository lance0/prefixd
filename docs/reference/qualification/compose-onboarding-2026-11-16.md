# Compose onboarding — 2026-11-16 UTC

This receipt walks the [quickstart](../../tutorials/quickstart.md) on a fresh
Compose stack for both speaker profiles:

- the database password from `scripts/compose-bootstrap.sh env`;
- the first Admin and the scoped tokens from `scripts/compose-bootstrap.sh`,
  and a live rerun of it;
- `prefixdctl` in the controller with the operator token read on stdin;
- one detector event with an ingest token through `curl -K -`, and its
  withdrawal in dry-run.

It also records the secret file modes and what a missing password or token
does. Every claim is scoped to the image, configuration and commands below. It
is local control-plane evidence: the sample peer (192.0.2.1) never
established, so no rule left the speaker, and nothing here says anything about
router enforcement.

## Setup

| Item | Value |
| --- | --- |
| Runs | rustbgpd 2026-11-16T11:01:39Z to 11:04:12Z; GoBGP 11:04:55Z to 11:07:28Z. Local Linux host, Docker Compose v5.1.0 |
| Tree | `15c7e80`: this change merged with main `ed830a6` |
| Controller | `prefixd:onboard-local` (`sha256:e5a861abe37b…`), built from that tree with the repository's `Dockerfile`, version 0.27.0. The change alters `prefixdctl`, so the published image could not stand in |
| Dashboard | `ghcr.io/lance0/prefixd-dashboard:main@sha256:5a78aa480e25fab015e406aa3a8c73ca5e50b43dd3404b967cbfff2d06b5111a`, revision `88e3f1d`; not under test |
| Speakers | rustbgpd 0.83.0 and the GoBGP image, both as pinned in `docker-compose.yml` |
| Configuration | Shipped `configs/` and the seeded inventory, playbooks and correlation; `http.auth.mode: credentials`, leased FlowSpec on for rustbgpd |

Each run started with no volumes, no `.env` and no `.prefixd` directory, and
ended with `docker compose down -v` and both removed. A Compose override,
outside the repository, isolated the run on a shared host and changed nothing
the quickstart exercises:

- a unique project name and no fixed container names;
- nginx published on a loopback port instead of 80, which the host already
  used, so the commands used `http://127.0.0.1:<port>` for `http://localhost`;
- BGP published on a loopback port, and Prometheus and Grafana unpublished;
- every container pinned to the same CPU set.

`PREFIXD_IMAGE` selected the local controller image, so `up` ran with
`--pull missing` instead of `--pull always`, as the quickstart's build-from-source
section does. The admin password went to the hidden prompt through a
pseudo-terminal. The edit of `mode:` in the profile's main config was made with
`sed` and reverted with `git checkout`.

## Results

Both profiles gave the same results unless a row says otherwise. `cli` below
is `docker compose exec -T -e PREFIXD_TOKEN_FILE=/dev/stdin prefixd-<p>
prefixdctl ... < .prefixd/cli.token`.

| Step | Command | Result |
| --- | --- | --- |
| No password | `docker compose --profile <p> up -d` with no `.env` | Exit 1, `required variable POSTGRES_PASSWORD is missing a value: set POSTGRES_PASSWORD in .env; scripts/compose-bootstrap.sh env generates one`; no container created |
| Exported password | `POSTGRES_PASSWORD=override-canary scripts/compose-bootstrap.sh env` | Exit 1, `POSTGRES_PASSWORD is set in your environment, and it overrides .env for every Compose command; run 'unset POSTGRES_PASSWORD' ...`; no `.env` written, and the value is not echoed |
| Password | `scripts/compose-bootstrap.sh env` | `.env` `-rw-------` (600), one line `POSTGRES_PASSWORD=` and 64 hex characters |
| Start | `docker compose --profile <p> up -d --no-build` | Every service up; `GET /v1/health` `{"status":"ok","version":"0.27.0","auth_mode":"credentials"}` |
| Password over a live database | `.env` moved aside, then `scripts/compose-bootstrap.sh env` | Exit 1, `Compose project ... already has a PostgreSQL volume, created with an earlier password`; no `.env` written. With `.env` back, the same command keeps the password |
| CLI endpoint | `env` in the controller | `PREFIXD_API=http://127.0.0.1:8080`; no `PREFIXD_API_TOKEN` |
| CLI without a token | `docker compose exec prefixd-<p> prefixdctl status` | Exit 1, `error: 401 Unauthorized: authentication failed: missing, invalid, revoked or expired credentials (set PREFIXD_TOKEN or PREFIXD_TOKEN_FILE to an API token, or --session-cookie)`. Controller running, 0 restarts |
| Bootstrap | `scripts/compose-bootstrap.sh <p>` | Admin `admin` created at the hidden prompt; ingest token `fastnetmon-<stamp>` bound to `fastnetmon` and operator token `cli-<stamp>` minted, `CREATED BY prefixdctl`. No token printed |
| File modes | `stat` | `.env`, `cli.token`, `cli.token.name`, `fastnetmon.token` and `fastnetmon.token.name` `-rw-------` (600) and `.prefixd` `drwx------` (700), all owned by the invoking user; `git check-ignore` matches `/.env` and `/.prefixd/` |
| Live rerun | `chmod 0644 .prefixd/cli.token`, then `scripts/compose-bootstrap.sh <p>` with no terminal | `An Admin operator already exists; skipping operator creation.` Both tokens kept after `prefixdctl tokens verify` matched each file's secret to its recorded name, scope and source; `cli.token` back to 600; no new token in `tokens list` |
| Verify | `docker compose exec -T prefixd-<p> prefixdctl tokens verify < .prefixd/<file>.token` | `Token 'cli-<stamp>': scope operator, source -, pop any, active` and `Token 'fastnetmon-<stamp>': scope ingest, source fastnetmon, pop any, active` |
| Swapped files | The secrets of `cli.token` and `fastnetmon.token` swapped, then the bootstrap rerun | Exit 1, `.../fastnetmon.token holds token 'cli-<stamp>', which is not an ingest token bound to fastnetmon; were the token files swapped?`. With the files restored, the rerun keeps both again |
| CLI with the token | `cli status` | Exit 0, `Status: healthy`, `Mode: enforced`; rustbgpd reports daemon 0.83.0 ready, GoBGP `Daemon metadata: unsupported` |
| Help | `prefixdctl --help` with the token file in the environment | The token occurs 0 times |
| Dry-run | `mode: dry-run`, `up -d --no-build --force-recreate --no-deps prefixd-<p>`, `cli status` | `Mode: dry-run`; 0 restarts |
| Ban | ingest token, `curl -K -`, `203.0.113.10` `udp_flood` | `202`, `status: accepted`, one mitigation: police, `203.0.113.10/32` UDP port 53 |
| Mitigation | `cli mitigations list`, `cli speaker list-routes` | The mitigation `active`; the speaker holds no rule (rustbgpd "retained local FlowSpec intent", GoBGP "accepted local FlowSpec RIB") |
| Unban | ingest token, `"action":"unban"`, vector `unknown` | `202`, `status: withdrawn`, naming that mitigation; the list shows it `withdrawn` |
| No credential | `POST /v1/events` without `Authorization` | `401 unauthorized: authentication required` |
| Operator token | `POST /v1/events` with the CLI token | `403 forbidden: ingest routes need an ingest token bound to the event source, or an Admin` |
| Other source | ingest token claiming `alertmanager` | `403 forbidden: source "alertmanager" is not bound to this credential (bound to "fastnetmon")` |
| Script without a token or endpoint | `scripts/prefixd-fastnetmon.sh 203.0.113.10 incoming 1000 ban`, first with no token, then with no `PREFIXD_API` | Exit 1 each; log `ERROR: no token: ...` and `ERROR: PREFIXD_API is not set: ...`. Controller running, 0 restarts |
| Enforced | `git checkout` the main config, recreate, `cli status` | `Mode: enforced`, 0 restarts, since the rehearsal mitigation was withdrawn |
| Rule held across a missing token | Ban `203.0.113.11` with the ingest token, then `prefixdctl status` without a token, then 75 s | The rule (`203.0.113.11/32`, UDP 53, police 5 Mbit/s) is in the speaker before and after; the tokenless CLI exits 1 with the 401 above; controller running, 0 restarts throughout. On rustbgpd the 75 s span exceeds one 60 s lease; GoBGP has no lease, so there it shows only that the controller and the rule were undisturbed |
| Status with a rule | `cli status`, `GET /v1/health/detail` | rustbgpd `Status: degraded`: `flowspec_exports.unexported` names the mitigation with reason `no_established_peer`, and the controller logged `last complete export observation has no committed Established peer ... reason: "no_established_peer"`. GoBGP `healthy`, with no export observation |
| Operator withdrawal | `cli mitigations withdraw <id> --reason ...` | `Withdrawn mitigation <id>`; the speaker holds no rule |
| Logs | Controller log of the last container | Neither token nor the database password occurs; no `PREFIXD_API_TOKEN` warning |

The 75-second hold is evidence that a client without a token leaves the
controller and its lease renewal alone. It is not a lease-expiry test.

## Rehearsal left live

A trial of an earlier driver on the previous `main` image (`76a32d3`), before
detector unbans named the victim, left the rehearsal mitigation live: that
image answered the unban `ignored_no_event_id`. Switching back to enforced
then made the controller exit and Compose restart it 10 times, until the
mitigation's 120-second TTL passed. That is the documented refusal
([dry-run rollout](../../cookbook/dry-run-rollout.md#5-switch-to-enforced)),
and the quickstart says so. In the runs above the unban withdrew the
mitigation, and enforced startup had 0 restarts on both profiles.

## Unit checks

`scripts/test-compose-bootstrap.py` runs the bootstrap against a fake `docker`
under umask 022, from a scratch copy of the repository. It covers:

- the 0700 directory, 0600 token and name files, and no token in stdout,
  stderr or any `docker` argument;
- a rerun that keeps live tokens, resets modes and skips an Admin listed with
  unusual JSON spacing;
- a kept token the database lost or revoked, and kept files that were
  swapped (secrets alone, or with their name files), emptied, truncated or
  renamed;
- garbled, two-line and noncanonical mint output, each refused with the
  minted token named for revocation;
- a failed `operators list`, and a failure of only the second mint followed by
  a rerun that mints only the missing token;
- a second run while the first holds the lock, through an explicit handshake;
- a `.lock` that is not a held lock, reported as its own error;
- a relative `PREFIXD_TOKEN_DIR` taken from the caller's directory;
- `env`: a fresh `.env`, appending to an existing one, keeping a set password,
  keeping a published example value with a warning, and refusing an empty
  value, duplicates, a symbolic link, an exported `POSTGRES_PASSWORD` on both
  paths, an existing PostgreSQL volume and a failed volume listing.

`scripts/test-compose.py` checks `PREFIXD_API` on both controller services
and that both profiles refuse to render without `POSTGRES_PASSWORD`.
`tests/integration_cli_lifetime.rs` checks the token file from a path, the
environment and `/dev/stdin`, the 1 KiB cap, the `Mode` line, `Mode:
unavailable` when settings answer 403 or 500, the usage errors and hidden help
values. `tests/integration_postgres.rs` checks `tokens verify` against
PostgreSQL: active, unknown, malformed, noncanonical, empty, revoked and
expired secrets, from stdin and `--token-file`, with no secret or hash in any
output. `tests/fastnetmon_vector.rs` checks that the script posts
nothing without `PREFIXD_API`.

Negative controls, each reverted:

| Seeded defect | Failing check |
| --- | --- |
| The earlier any-line `grep -qxE` token check | Two-line and noncanonical mint output accepted |
| A non-exclusive `mkdir -p` lock | The concurrent run proceeds and mints |
| No resolution of a relative token directory | Tokens land in the repository's `secrets/` |
| No check of kept tokens | A deleted or revoked token is kept silently |
| No `umask 077` and a plain file instead of `mktemp`; then no `chmod 0700` | Token files 0644; then the directory 0755 |
| `PREFIXD_API` removed from Compose | `KeyError: 'PREFIXD_API'` for both profiles |
| The `prefixd_secret` fallback restored | `config` renders without a password for both profiles |
| No token-file conflict check in `prefixdctl` | `--token-file` with `PREFIXD_TOKEN` exits 0 instead of 2 |
| `hide_env_values` removed from the token file option | Help prints the seeded path |
| No `Mode` line in `status` | The status output lacks `Mode: dry-run` |
| The script's `http://localhost:8080` default restored | The script no longer refuses a missing endpoint |
| The volume listing back inside `[[ -n "$(...)" ]]` | A failed listing writes a new password |
| No refusal of an exported `POSTGRES_PASSWORD` | `env` writes `.env` while the export overrides it |
| No scope and source check of kept files | Swapped files pass the rerun |
| `status` failing on an unreadable mode again | `status` exits 1 on a settings 403 or 500 |
| `tokens verify` echoing an unknown secret | The no-echo check fails |

## Not covered

- Router enforcement, BGP export or any established session.
- The dashboard sign-in itself; the Admin was created but not used to sign in.
- FastNetMon itself. The bundled script ran only to show its refusals; the
  [FastNetMon Community interop](fastnetmon-community-2026-11-16.md) covers
  the notify path.
- Upgrading an existing stack to the required `POSTGRES_PASSWORD`; only the
  refusals to replace a live database's password, and to run with an exported
  one, were run.
- Host port 80 and the fixed container names; the isolation override replaced
  both.
