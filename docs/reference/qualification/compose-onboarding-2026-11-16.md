# Compose onboarding — 2026-11-16 UTC

This receipt walks the [quickstart](../../tutorials/quickstart.md) on a fresh
Compose stack for both speaker profiles: bootstrap with
`scripts/compose-bootstrap.sh`, `prefixdctl` in the controller with an
operator token, one detector event with an ingest token through `curl -K -`,
and its withdrawal in dry-run. It also records the secret file modes and what
a missing token does. Every claim is scoped to the images, configuration and
commands below. It is local control-plane evidence: the sample peer
(192.0.2.1) never established, so no rule left the speaker, and nothing here
says anything about router enforcement.

## Setup

| Item | Value |
| --- | --- |
| Runs | rustbgpd 2026-11-16T09:54:55Z to 09:57:30Z; GoBGP 09:58:22Z to 10:00:53Z. Local Linux host, Docker Compose v5.1.0 |
| Tree | `2c18e1b`, this change's Compose file, bootstrap script and quickstart on main `88e3f1d` |
| Controller | `ghcr.io/lance0/prefixd:main@sha256:3d4eeb318c11f62821d6a1c9b9e57ba926578134ade89fba9fb0518f7fc8b4ab`, revision `88e3f1d`, version 0.27.0. This change does not alter the image |
| Dashboard | `ghcr.io/lance0/prefixd-dashboard:main@sha256:5a78aa480e25fab015e406aa3a8c73ca5e50b43dd3404b967cbfff2d06b5111a`, revision `88e3f1d` |
| Speakers | rustbgpd 0.83.0 and the GoBGP image, both as pinned in `docker-compose.yml` |
| Configuration | Shipped `configs/` and the seeded inventory, playbooks and correlation; `http.auth.mode: credentials`, leased FlowSpec on for rustbgpd |

Each run started from no volumes and no `.prefixd` directory and ended with
`docker compose down -v`. A Compose override, outside the repository, isolated
the run on a shared host and changed nothing the quickstart exercises:

- a unique project name and no fixed container names;
- nginx published on a loopback port instead of 80, which the host already
  used, so the commands used `http://127.0.0.1:<port>` for `http://localhost`;
- BGP published on a loopback port, and Prometheus and Grafana unpublished;
- every container pinned to the same CPU set.

The admin password went to the hidden prompt through a pseudo-terminal. The
edit of `mode:` in the profile's main config was made with `sed` and reverted
with `git checkout`.

## Results

Both profiles gave the same results unless a row says otherwise.

| Step | Command | Result |
| --- | --- | --- |
| Start | `docker compose --profile <p> up -d --pull always --no-build` | Every service up; `GET /v1/health` `{"status":"ok","version":"0.27.0","auth_mode":"credentials"}` |
| CLI endpoint | `env` in the controller | `PREFIXD_API=http://127.0.0.1:8080`; no `PREFIXD_API_TOKEN` |
| CLI without a token | `docker compose exec prefixd-<p> prefixdctl status` | Exit 1, `error: 401 Unauthorized: authentication failed: missing, invalid, revoked or expired credentials (set PREFIXD_TOKEN to an API token, or --session-cookie)`. Controller running, 0 restarts |
| Bootstrap | `scripts/compose-bootstrap.sh <p>` | Admin `admin` created at the hidden prompt; ingest token `fastnetmon-<stamp>` bound to `fastnetmon` and operator token `cli-<stamp>` minted, `CREATED BY prefixdctl`. No token printed |
| File modes | `stat` | `.prefixd` `drwx------` (700), `cli.token` and `fastnetmon.token` `-rw-------` (600), owned by the invoking user; `git check-ignore` matches `/.prefixd/` and `/.env` |
| CLI with the token | `export PREFIXD_TOKEN=...; docker compose exec -e PREFIXD_TOKEN prefixd-<p> prefixdctl status` | Exit 0, `Status: healthy`; rustbgpd reports daemon 0.83.0 ready, GoBGP `Daemon metadata: unsupported` |
| Help | `prefixdctl --help` with the token in the environment | The token occurs 0 times |
| Dry-run | `mode: dry-run`, `up -d --no-build --force-recreate --no-deps prefixd-<p>` | `GET /v1/config/settings` reports `dry-run`; 0 restarts |
| Ban | ingest token, `curl -K -`, `203.0.113.10` `udp_flood` | `202`, `status: accepted`, one mitigation: police, `203.0.113.10/32` UDP port 53 |
| Mitigation | `prefixdctl mitigations list`, `speaker list-routes` | The mitigation `active`; the speaker holds no rule (rustbgpd "retained local FlowSpec intent", GoBGP "accepted local FlowSpec RIB") |
| Unban | ingest token, `"action":"unban"`, vector `unknown` | `202`, `status: withdrawn`, naming that mitigation; the list shows it `withdrawn` |
| No credential | `POST /v1/events` without `Authorization` | `401 unauthorized: authentication required` |
| Operator token | `POST /v1/events` with the CLI token | `403 forbidden: ingest routes need an ingest token bound to the event source, or an Admin` |
| Other source | ingest token claiming `alertmanager` | `403 forbidden: source "alertmanager" is not bound to this credential (bound to "fastnetmon")` |
| Script without a token | `scripts/prefixd-fastnetmon.sh 203.0.113.10 incoming 1000 ban`, no token configured | Exit 1; log `ERROR: no token: set PREFIXD_TOKEN_FILE or PREFIXD_TOKEN ...`. Controller running, 0 restarts |
| Enforced | `git checkout` the main config, recreate | `enforced`, 0 restarts, since the rehearsal mitigation was withdrawn |
| Rule held across a missing token | Ban `203.0.113.11` with the ingest token, then `prefixdctl status` without a token, then 75 s (longer than one 60 s lease) | The rule (`203.0.113.11/32`, UDP 53, police 5 Mbit/s) is in the speaker before and after; the tokenless CLI exits 1 with the 401 above; controller running, 0 restarts throughout. with one active mitigation, rustbgpd's `prefixdctl status` read `degraded` and GoBGP's `healthy`; this receipt does not diagnose the difference |
| Operator withdrawal | `prefixdctl mitigations withdraw <id> --reason ...` with the CLI token | `Withdrawn mitigation <id>`; the speaker holds no rule |
| Logs | Controller log of the last container | Neither token occurs; no `PREFIXD_API_TOKEN` warning |

The 75-second hold is evidence that a client without a token leaves the
controller and its lease renewal alone. It is not a lease-expiry test.

## Rehearsal left live

A trial of the same driver on the previous `main` image (`76a32d3`), before
detector unbans named the victim, left the rehearsal mitigation live: that
image answered the unban `ignored_no_event_id`. Switching back to enforced
then made the controller exit and Compose restart it 10 times, until the
mitigation's 120-second TTL passed. That is the documented refusal
([dry-run rollout](../../cookbook/dry-run-rollout.md#5-switch-to-enforced)),
and the quickstart now says so. On `88e3f1d` the unban withdrew the
mitigation, and enforced startup had 0 restarts on both profiles.

## Unit checks

`scripts/test-compose-bootstrap.py` runs the bootstrap against a fake `docker`
under umask 022. It checks the 0700 directory and 0600 files, that no token
reaches stdout, stderr or any `docker` argument, that a rerun keeps tokens and
an existing Admin, that a failed or garbled mint leaves no file, and that a
stopped service or bad profile fails before anything is written. Negative
controls, each reverted:

- Removing `umask 077` and replacing `mktemp` with a plain file left the token
  files 0644; the mode check failed.
- Also removing `chmod 0700` left the directory 0755; the check failed.
- Removing the token-format check let a garbled mint become a token file; the
  failure check failed.

`scripts/test-compose.py` checks that both controller services set
`PREFIXD_API=http://127.0.0.1:8080`; with the variable removed it fails with
`KeyError: 'PREFIXD_API'` for both profiles.

## Not covered

- Router enforcement, BGP export or any established session.
- The dashboard sign-in itself; the Admin was created but not used to sign in.
- FastNetMon itself. The bundled script ran only to show its no-token refusal;
  the [FastNetMon Community interop](fastnetmon-community-2026-11-16.md)
  covers the notify path.
- Host port 80 and the fixed container names; the isolation override replaced
  both.
