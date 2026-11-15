# Alerting

prefixd can post a notification when a mitigation is created, withdrawn or
expires. It sends them to Slack, Discord, Microsoft Teams, Telegram, PagerDuty,
Opsgenie or a generic HTTPS webhook. Alerts are one-way: nobody can acknowledge,
extend or withdraw a mitigation from a chat message. Delivery is best effort;
see [current limits](#current-limits).

Use the dashboard, the API or the audit log as the record of what happened.
An alert tells someone to look.

## Quick path: Slack in five steps

This path uses the Compose stack from the
[quickstart](../tutorials/quickstart.md) and the `rustbgpd` profile. For GoBGP,
replace `prefixd-rustbgpd` with `prefixd-gobgp`.

1. In Slack, create an incoming webhook for your alert channel and copy its URL;
   see [Slack](#slack).
2. Add the URL to `.env` in the repository root:

   ```bash
   SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
   ```

3. Pass the variable to the controller in `docker-compose.override.yml`. Compose
   reads this file automatically; if `.env` sets `COMPOSE_FILE`, add
   `docker-compose.override.yml` to that list.

   ```yaml
   services:
     prefixd-rustbgpd:  # or prefixd-gobgp
       environment:
         SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL:?set SLACK_WEBHOOK_URL in .env}
   ```

4. Write `alerting.yaml` with this content and copy it into the configuration
   volume as shown in [write alerting.yaml with Compose](#write-alertingyaml-with-compose):

   ```yaml
   destinations:
     - type: slack
       webhook_url_env: SLACK_WEBHOOK_URL
   ```

5. Recreate the controller so it gets the new variable, check that it started,
   then [send a test alert](#send-a-test-alert):

   ```bash
   docker compose --profile rustbgpd up -d
   docker compose logs --tail 20 prefixd-rustbgpd
   ```

If the controller refuses the configuration, it exits and names the file, the
destination and the key; see [troubleshooting](#troubleshooting).

## Where the configuration lives

prefixd reads alert destinations from `alerting.yaml` in its configuration
directory, `/etc/prefixd`. Without that file, it uses the `alerting` section of
`prefixd.yaml`. A present `alerting.yaml` replaces the inline section
completely; the two are never merged.

| | `alerting.yaml` | Inline `alerting` in `prefixd.yaml` |
|---|---|---|
| Read at | Startup and [reload](../reference/configuration.md#hot-reload) | Startup only |
| Written by the dashboard editor | Yes | No; the first editor save creates `alerting.yaml`, which then wins |
| Compose location | `prefixd-config` volume | `configs/prefixd.yaml` (GoBGP: `configs/prefixd-gobgp.yaml`) in the checkout, mounted read-only |
| systemd location | `/etc/prefixd/alerting.yaml` | `/etc/prefixd/prefixd.yaml` |

Use `alerting.yaml`. The file has two keys:

```yaml
destinations:
  - type: slack
    webhook_url_env: SLACK_WEBHOOK_URL
  - type: pagerduty
    routing_key_env: PAGERDUTY_ROUTING_KEY
    events:
      - mitigation.created
      - mitigation.withdrawn
      - mitigation.expired
# Optional. Events for destinations without their own events list; empty or
# absent sends every event.
events:
  - mitigation.created
  - mitigation.withdrawn
```

Each secret is written inline or through its `*_env` key, never both. A
`*_env` key names an environment variable in the controller's environment.
prefixd reads it when it sends an alert and never writes its value to
`alerting.yaml` or returns it from the API. Prefer `*_env`: the file then holds
no secret, and backups or copies of `/etc/prefixd` leak nothing. The
[configuration reference](../reference/configuration.md#alert-destination-secrets)
lists every secret key.

The process environment is fixed when the controller starts. Adding a variable
or changing its value needs a controller restart; a reload is not enough.
prefixd does not expand `${VAR}` placeholders and refuses a value written
entirely as `${...}`.

### Write alerting.yaml with Compose

The initializer does not seed `alerting.yaml`, and editing a file in the
checkout does not change the volume. Stream your local file into the volume as
the controller's user, keeping a backup of any existing file:

```bash
docker compose exec -T prefixd-rustbgpd sh -ec '
  umask 077
  temporary=$(mktemp /etc/prefixd/.alerting.XXXXXX)
  trap "rm -f \"$temporary\"" EXIT
  cat > "$temporary"
  if [ -e /etc/prefixd/alerting.yaml ]; then
    cp /etc/prefixd/alerting.yaml /etc/prefixd/alerting.yaml.bak
  fi
  mv "$temporary" /etc/prefixd/alerting.yaml
' < alerting.yaml
```

Read the running file back with
`docker compose exec -T prefixd-rustbgpd cat /etc/prefixd/alerting.yaml`.

If you changed only the file and every variable it names is already set, apply
it with **Config** > **Reload** in the dashboard or `prefixdctl reload`. If you
added a variable, recreate the controller instead.

### Pass variables with Compose

The shipped Compose file sets only `RUST_LOG`, `PREFIXD_API_TOKEN`,
`PREFIXD_API` and `DATABASE_URL` in the controller. Other `.env` entries reach
it only when you name them in the controller's `environment`, as in step 3 of
the [quick path](#quick-path-slack-in-five-steps). Add one line per variable:

```yaml
services:
  prefixd-rustbgpd:  # or prefixd-gobgp
    environment:
      SLACK_WEBHOOK_URL: ${SLACK_WEBHOOK_URL:?set SLACK_WEBHOOK_URL in .env}
      PAGERDUTY_ROUTING_KEY: ${PAGERDUTY_ROUTING_KEY:?set PAGERDUTY_ROUTING_KEY in .env}
```

The `:?` form makes Compose stop with that message when the variable is missing
from `.env`, instead of passing an empty value that the controller then refuses.
Run `docker compose --profile rustbgpd up -d` after each change.

### Pass variables with systemd

The shipped unit reads `/etc/default/prefixd`, the root-only file that also
holds `PREFIXD_API_TOKEN`; see [Systemd Service](deployment.md#systemd-service).
Add one line per variable:

```bash
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T000/B000/XXXX
PAGERDUTY_ROUTING_KEY=your-integration-key
```

Write `alerting.yaml` to `/etc/prefixd/` with the same owner as the rest of
that directory, so dashboard saves can replace it. Then restart:

```bash
sudo systemctl restart prefixd
sudo journalctl -u prefixd -n 20
```

## Destinations

Each section gives the platform-side steps, then the `alerting.yaml` entry.
Platform menus change; each section links to the platform's own instructions.
prefixd's tests check the payload each destination builds, not delivery to a
live account, so send a [test alert](#send-a-test-alert) after setup.
Put each variable in `.env` and the override file for Compose, or in
`/etc/default/prefixd` for systemd, as described above.

### Slack

1. Follow Slack's
   [incoming webhooks guide](https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/):
   create a Slack app, turn on **Activate Incoming Webhooks**, select
   **Add New Webhook to Workspace** and pick the channel.
2. Copy the URL, which starts with `https://hooks.slack.com/services/`.

```yaml
destinations:
  - type: slack
    webhook_url_env: SLACK_WEBHOOK_URL
```

An app's webhook always posts to the channel chosen when it was created. Slack
documents that the payload cannot override it, so prefixd's optional `channel`
key does not move app webhook messages. Create one webhook per channel instead.
Slack revokes webhook URLs it finds published, so keep the URL out of
repositories.

### Discord

1. Open **Server Settings** > **Integrations** > **Webhooks** and select
   **New Webhook**. This needs the Manage Webhooks permission; see Discord's
   [intro to webhooks](https://support.discord.com/hc/en-us/articles/228383668-Intro-to-Webhooks).
2. Choose the channel, then **Copy Webhook URL**. It looks like
   `https://discord.com/api/webhooks/<id>/<token>`.

```yaml
destinations:
  - type: discord
    webhook_url_env: DISCORD_WEBHOOK_URL
```

Messages are posted as `prefixd`, whatever name the webhook was given.

### Microsoft Teams

Microsoft retired Office 365 connectors in Teams, including connector-based
incoming webhooks, in May 2026. Use a Workflows webhook; see Microsoft's
[incoming webhook guide](https://learn.microsoft.com/en-us/microsoftteams/platform/webhooks-and-connectors/how-to/add-incoming-webhook).

1. In Teams, open **More options (...)** next to the channel and select
   **Workflows**.
2. Choose the **Send webhook alerts to a channel** template, confirm the team
   and channel, and select **Save**.
3. Copy the webhook URL from the workflow's details.

```yaml
destinations:
  - type: teams
    webhook_url_env: TEAMS_WEBHOOK_URL
```

prefixd posts a `message` with one Adaptive Card 1.4 attachment, the format
Microsoft's Workflows examples use. It sends no Microsoft sign-in token, so the
workflow must accept requests from anyone with the URL. The templates limited
to specific people or to people in your organization need a sign-in token. A
workflow belongs to the user who created it; add a co-owner so it keeps
working when that user leaves.

### Telegram

1. Message [@BotFather](https://t.me/BotFather), send `/newbot` and follow the
   prompts. Copy the bot token, which looks like `123456789:AA...`; see
   Telegram's [bot tutorial](https://core.telegram.org/bots/tutorial).
2. Add the bot to the group, or as an administrator to the channel. Bots
   cannot start a conversation. In a group, send a command addressed to the
   bot, such as `/start@your_bot_username`: by default a bot in a group sees
   only commands and replies; see Telegram's
   [bot FAQ](https://core.telegram.org/bots/faq#what-messages-will-my-bot-get).
   In a channel, post any message.
3. Find the chat ID with the Bot API's
   [`getUpdates`](https://core.telegram.org/bots/api#getupdates). Group and
   channel IDs are negative, often starting with `-100`. Enter the token at the
   hidden prompt, since `.env` does not set shell variables:

   ```bash
   read -rs TELEGRAM_BOT_TOKEN
   curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" |
     jq '.result[] | (.message // .channel_post).chat | {id, title}'
   ```

```yaml
destinations:
  - type: telegram
    bot_token_env: TELEGRAM_BOT_TOKEN
    chat_id: "-1001234567890"
```

Quote `chat_id`: it is a string of at most 64 bytes, and startup refuses an
unquoted number with `invalid type, expected a string`. It has no `*_env` form
because it is not a secret. A public channel's `@channelname` also works.

### PagerDuty

1. In PagerDuty, open **Services** > **Service Directory**, select the service,
   then the **Integrations** tab and **Add another integration**.
2. Choose **Events API V2** and select **Add**.
3. Copy the integration's **Integration Key**, which the Events API calls the
   routing key; see PagerDuty's
   [services and integrations](https://docs.pagerduty.com/incident-management/services/services-and-integrations).

```yaml
destinations:
  - type: pagerduty
    routing_key_env: PAGERDUTY_ROUTING_KEY
    events:
      - mitigation.created
      - mitigation.withdrawn
      - mitigation.expired
```

`mitigation.created` triggers an incident whose deduplication key is the
mitigation ID. `mitigation.withdrawn` and `mitigation.expired` resolve it with
the same key, so include all three events or incidents stay open.
`events_url` defaults to `https://events.pagerduty.com/v2/enqueue`. An account
in PagerDuty's EU service region sets
`events_url: "https://events.eu.pagerduty.com/v2/enqueue"`.

### Opsgenie

Atlassian ended Opsgenie sales in June 2025 and ends support on April 5, 2027.
Existing accounts work until then.

1. Open **Settings** > **Integrations**, search for **API** and name the
   integration. On plans without that page, open **Teams**, select the team,
   then **Integrations** > **Add integration**.
2. Expand **Steps to configure the integration**, copy the API key and select
   **Turn on integration**; see Atlassian's
   [API integration guide](https://support.atlassian.com/opsgenie/docs/create-a-default-api-integration/).

```yaml
destinations:
  - type: opsgenie
    api_key_env: OPSGENIE_API_KEY
    region: us  # or eu
```

`region: eu` sends to `api.eu.opsgenie.com`; anything else is refused. prefixd
creates an alert whose alias is the mitigation ID and never closes it. A later
`mitigation.withdrawn` or `mitigation.expired` alert reuses the alias. Opsgenie
folds it into the alert while that is open and raises its count, or opens a new
alert if it was closed. Close alerts in Opsgenie, and send only
`mitigation.created` there to avoid the follow-up alerts.

### Generic webhook

Use a generic destination for any HTTPS endpoint that accepts JSON.

```yaml
destinations:
  - type: generic
    url_env: ALERT_WEBHOOK_URL
    secret_env: ALERT_WEBHOOK_SECRET
    headers:
      X-Team: noc
```

prefixd POSTs the alert as JSON with `Content-Type: application/json` and
`User-Agent: prefixd-webhook/1.0`:

```json
{
  "event_type": "mitigation.created",
  "severity": "warning",
  "title": "Mitigation Created",
  "message": "discard mitigation for 203.0.113.10 (udp_flood) in iad1",
  "source": "prefixd",
  "timestamp": "2026-11-15T12:00:00.000000Z",
  "mitigation_id": "0b7e6a52-6f1e-4a3b-9c1d-2f5a8e4b7c90",
  "victim_ip": "203.0.113.10",
  "customer_id": "cust_example",
  "vector": "udp_flood",
  "action_type": "discard",
  "pop": "iad1"
}
```

Fields without a value, such as `customer_id` for an address with no customer,
are left out. With `secret` or `secret_env`, prefixd adds
`X-Prefixd-Signature: sha256=<hex>`, the HMAC-SHA256 of the raw request body
keyed by the secret. Verify it against the exact bytes received before parsing.
`url` and `url_env` are alternatives; `secret` is optional. `headers` values
are stored as written and have no `*_env` form, so don't put credentials there
when the signature can do the job.

## Use the dashboard editor

Open **Config** > **Alerting**. Anyone signed in can see the destinations with
secrets shown as `***`. Editing and sending a test alert need the admin role.

1. Select **Edit**, then **Add destination** and the platform.
2. Fill in the fields. A secret you type is saved inline in `alerting.yaml`.
3. Choose events per destination, or leave them unset to use the global list.
4. Select **Save**. The controller validates the whole configuration, writes
   `alerting.yaml`, keeps the previous file as `alerting.yaml.bak` and applies
   it at once. The audit log records the change and who made it.

An existing secret stays `***` in the form; leave it to keep the stored value.
The editor cannot add a `*_env` key or point one at a new destination, because
that would let an administrator send any controller variable, such as
`DATABASE_URL`, to a URL of their choosing. Write `*_env` keys in
`alerting.yaml` on the controller host. The editor keeps an existing one, and
can change its events, as long as the destination's type, variable and
`chat_id`, `events_url`, `region` or generic `url` stay the same.

The same operations are available as `GET` and `PUT /v1/config/alerting`; see
the [API reference](../reference/api.md#alerting-config).

## Choose events per destination

prefixd sends these events:

| Event | Sent when |
|-------|-----------|
| `mitigation.created` | A new mitigation is admitted, from a detector or by hand. Also sent in dry-run. Not sent when an event extends an existing mitigation. |
| `mitigation.withdrawn` | An operator withdraws a mitigation, a detector sends an unban, a safelist addition withdraws one, or the controller completes a pending withdrawal. |
| `mitigation.expired` | A mitigation's TTL expires and the controller withdraws it. Expiry needs the running controller. |

Filters also accept `config.reloaded` and `guardrail.rejected`, and the editor
offers them, but prefixd sends no alert for either today. `mitigation.escalated`
is accepted so older files still load; it is never sent.

A destination with a nonempty `events` list receives only those events. A
destination whose list is absent or empty, including `events: []`, uses the
top-level `events` list, and an empty or absent top-level list means every
event. Emptying a destination's list does not silence it. For example, page only on new mitigations and
send everything to chat:

```yaml
destinations:
  - type: pagerduty
    routing_key_env: PAGERDUTY_ROUTING_KEY
    events: [mitigation.created, mitigation.withdrawn, mitigation.expired]
  - type: opsgenie
    api_key_env: OPSGENIE_API_KEY
    region: eu
    events: [mitigation.created]
  - type: slack
    webhook_url_env: SLACK_WEBHOOK_URL
```

There is no switch to pause a destination; remove it to stop its alerts.

## Send a test alert

Sign in as an administrator, open **Config** > **Alerting** and select **Test**.
From a shell, sign in as an administrator first: the shared bearer token has
only the `operator` role, and this endpoint requires `admin`:

```bash
curl -sS -c cookies.txt -X POST http://localhost/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"your_password_here"}'
curl -sS -b cookies.txt -X POST http://localhost/v1/config/alerting/test | jq
```

`prefixdctl` has no test command.

```json
{
  "results": [
    {"destination": "slack", "status": "ok", "error": null},
    {"destination": "pagerduty", "status": "error", "error": "pagerduty returned 400 Bad Request — ..."}
  ]
}
```

The test is a `mitigation.created` alert titled **Test Alert** at `info`
severity, for `203.0.113.1`, `udp_flood`, `discard`, customer `test_customer`
and POP `test`. It goes only to destinations whose filter includes
`mitigation.created`, and `results` lists only those, in configuration order. A
destination missing from the list did not receive it. The request waits for
every delivery, including [retries](#current-limits), so a failing destination
can hold it for up to about 36 seconds.

A test opens a real PagerDuty incident and a real Opsgenie alert, keyed by the
title `Test Alert`. No later event resolves them; close them by hand.

## What alerts look like

Every alert has a title, a severity, a one-line message and the mitigation's
details.

| Event | Title | Severity | Message |
|-------|-------|----------|---------|
| `mitigation.created` | Mitigation Created | warning | `discard mitigation for 203.0.113.10 (udp_flood) in iad1` |
| `mitigation.withdrawn` | Mitigation Withdrawn | info | `Withdrawn discard for 203.0.113.10` |
| `mitigation.expired` | Mitigation Expired | info | `TTL expired for 203.0.113.10 (udp_flood)` |

| Destination | Format |
|-------------|--------|
| Slack | Header, message, then severity, event, victim IP, vector, customer and POP fields, a timestamp and the mitigation ID |
| Discord | Embed colored orange for warning and green for info, with victim IP, vector, action, customer and POP |
| Microsoft Teams | Adaptive Card with the title colored by severity, the message and a fact list that includes the mitigation ID |
| Telegram | HTML message with a colored circle for severity, the details and a UTC timestamp |
| PagerDuty | Event with summary `<title>: <message>`, severity and the details in `custom_details` |
| Opsgenie | Alert with priority P3 for warning and P5 for info, tags `prefixd` and the event, and the details |
| Generic | The JSON [shown above](#generic-webhook) |

Customer and POP appear only when the mitigation has them. Alerts do not say who
acted, whether the controller is in dry-run, or whether a router enforced the
rule.

## Rules prefixd enforces

Startup, [reload](../reference/configuration.md#hot-reload) and the dashboard
editor apply the same checks, and refuse the whole configuration if any
destination fails:

- Slack, Discord and Teams `webhook_url`, PagerDuty `events_url` and generic
  `url` must be `https://` URLs of at most 1024 bytes. The host cannot be
  `localhost`, a name under `.localhost`, or a literal private, loopback,
  link-local, multicast, broadcast, unspecified or documentation address.
  Public hostnames and public IP literals are accepted.
- These are text checks only; prefixd does not resolve names or follow
  redirects to check them. Restrict the controller's egress if a destination
  name could resolve to an internal address; see
  [alert destination URLs](../reference/configuration.md#alert-destination-urls).
- Each destination needs its secret, inline or through `*_env`, but not both.
  The generic `secret` is optional.
- A `*_env` variable must be set and nonempty in the controller's environment.
  Its value gets the URL checks above.
- Telegram needs `chat_id`, at most 64 bytes. Opsgenie `region` must be `us` or
  `eu`.
- No value may be written entirely as `${...}`.

Refusals name the file, the destination's position and type, and the key or
variable. They never include a secret or a URL.

## Troubleshooting

### The controller exits at startup

The log names the file and the problem. For example, a variable missing from
the controller's environment:

```text
Error: failed to load /etc/prefixd/alerting.yaml

Caused by:
    destination[0] (slack): webhook_url_env names environment variable 'SLACK_WEBHOOK_URL', which is not set or empty
```

A URL that fails the rules:

```text
Error: failed to load /etc/prefixd/alerting.yaml: alerting: destination[1] (discord): webhook_url must use https
```

`destination[N]` counts from 0 in file order. For a missing variable, check
`.env`, the override file and `docker compose config`, or
`/etc/default/prefixd`, then restart. For a URL, fix the value at its source.

In Compose the controller restarts in a loop, so `docker compose exec` may not
reach it. Write the corrected file through a one-off container that mounts the
same volume, with the write steps from
[write alerting.yaml with Compose](#write-alertingyaml-with-compose):

```bash
docker compose run --rm --no-deps -T --entrypoint sh prefixd-rustbgpd -ec '
  umask 077
  temporary=$(mktemp /etc/prefixd/.alerting.XXXXXX)
  trap "rm -f \"$temporary\"" EXIT
  cat > "$temporary"
  mv "$temporary" /etc/prefixd/alerting.yaml
' < alerting.yaml
```

### Reload fails

`POST /v1/config/reload` returns `422` with
`reload failed: alerting.yaml is invalid; running configuration unchanged; see
controller log`. The controller logs the detail under `reload_config failed`,
in the same form as a startup refusal.
The running alert configuration stays as it was.

### The test alert returns an error

The `error` field has the form `<type> returned <status> — <response body>`,
so the platform's own error text is in it.

| Error | Likely cause |
|-------|--------------|
| `400` from Slack, Discord or Teams | The platform rejected the payload; check the body text |
| `401` or `403` | Wrong or revoked key or webhook, a Teams workflow that requires sign-in, or a turned-off Opsgenie integration |
| `404` | Deleted webhook, workflow or channel, or a mistyped URL |
| `429` | The platform is rate limiting; see below |
| `... request failed: ...` | prefixd could not connect; check DNS, egress firewall and proxies from the controller host |

### Nothing arrives

- Run a test alert. If `results` is empty, no destination accepts
  `mitigation.created`; check the event filters.
- Check the event filters for the event you expected. Withdrawal and expiry go
  only to destinations that list them, or to all when no filter applies.
- Search the controller log for `alert delivery failed`, which names the
  destination and the error, and for `alert worker queue is saturated`.
- Watch `prefixd_alerts_sent_total{destination,status}`, where `status` is
  `success` or `error`. It counts each final outcome, not each attempt.
- A Slack app webhook ignores `channel`; look in the channel it was created for.
- prefixd ignores keys it does not know inside a destination, without an
  error. A misspelled optional key, such as `event:` for `events:`, silently
  has no effect. Compare the file with `GET /v1/config/alerting`.
- `mitigation.expired` needs the running controller. If prefixd was stopped when
  a TTL passed, the alert is sent when it returns and expires the mitigation.

### Rate limits

Platforms throttle webhooks. Teams Workflows limits follow the workflow's
Power Automate performance profile; see the
[Teams connector limits](https://learn.microsoft.com/en-us/connectors/teams/).
Slack, Discord and Telegram apply their own limits. An attack wave that creates many mitigations sends one alert per
mitigation to each destination. A throttled post counts as a failure and is
retried as described under [current limits](#current-limits). To cut volume, send only `mitigation.created` to
busy chat channels, or point busy events at a generic webhook that aggregates.

## Current limits

- **One way only.** prefixd posts; it reads nothing back. Chat replies,
  reactions, and PagerDuty or Opsgenie acknowledgements do not change a
  mitigation.
- **No durable delivery.** A failed post is retried twice, after 2 and then 4
  more seconds, each attempt with a 10-second timeout. After that the alert is
  dropped and logged. Alerts waiting in memory are lost when the controller
  restarts, and above 64 alerts in flight new ones are dropped. A durable
  outbox with retry and dead-letter visibility is planned.
- **No actor in the payload.** Alerts do not say which operator, detector or
  controller task caused the change. Use the audit log; naming the origin and
  actor in alerts is planned.
- **No dry-run marker.** Dry-run mitigations send the same alerts as enforced
  ones.
- **No router evidence.** An alert reports the controller's decision, not that
  a router installed or enforced the rule.
