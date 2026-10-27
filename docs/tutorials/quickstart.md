# Run prefixd with rustbgpd

This walkthrough starts a local controller and dashboard with rustbgpd as the
speaker. Docker Engine and Docker Compose with profiles are required. The default
uses prebuilt controller/dashboard images from the published `main` build; no
Rust or JavaScript toolchain is needed. Run commands from the repository root.

## Start and log in

```bash
git clone https://github.com/lance0/prefixd.git
cd prefixd
docker compose --profile rustbgpd up -d --pull always --no-build
docker compose --profile rustbgpd ps
curl http://localhost/v1/health

# Uses DATABASE_URL already set inside the controller; password entry is hidden.
docker compose exec prefixd-rustbgpd prefixdctl operators create \
  --username admin --role admin
open http://localhost
```

Log in with that account. The shipped main config enables credentials and
enforced operation. The sample inventory/playbooks are examples: adapt them to
your network before sending real attack events. A healthy local API or speaker
is not proof of a BGP session or router enforcement.

## Build from source

For local development, build the same controller and dashboard images with local
tags. This compiles Rust and the frontend and can take longer than the prebuilt
quickstart:

```bash
export PREFIXD_IMAGE=prefixd:local
export PREFIXD_DASHBOARD_IMAGE=prefixd-dashboard:local
docker compose --profile rustbgpd build
docker compose --profile rustbgpd up -d --pull missing --no-build
```

The controller Dockerfile pins Rust 1.99.1 on Debian trixie by image digest.
This records the container build toolchain. Native builds require Rust 1.89 or
later; see [contributing](../../CONTRIBUTING.md) for the locked compiler checks.
Cargo builds use three jobs by default.

The image overrides apply equally to the initializer and either controller
profile. Use the same values for later Compose commands. To return to published
images, unset both variables and repeat the prebuilt startup command.

Compose defaults to `ghcr.io/lance0/prefixd:main` and
`ghcr.io/lance0/prefixd-dashboard:main`, published by CI after successful main
builds. These tags move. For a controlled deployment, override both with the
specific published commit tags or release references you have qualified; see
[image publication](../how-to/deployment.md#image-publication-and-selection).

## Configure the edge

[rustbgpd](https://github.com/lance0/rustbgpd) is the preferred speaker: a Rust
BGP daemon that prefixd drives over its gRPC API. Its
[documentation](https://github.com/lance0/rustbgpd/blob/main/docs/README.md)
covers peer and policy settings beyond this example.

`configs/rustbgpd.toml` adapts the released rustbgpd DDoS example: both IPv4 and
IPv6 FlowSpec, explicit reject-import/permit-export policy, and no unicast/RTBH
family. Replace the documentation peer `192.0.2.1` and AS numbers with your edge
router. Configure that router to accept the selected FlowSpec families and
appropriate import policy. Check the config before restarting the speaker:

```bash
docker compose run --rm --no-deps rustbgpd rustbgpd --check --strict /etc/rustbgpd/config.toml
docker compose --profile rustbgpd restart rustbgpd
```

The local RPC socket is private to rustbgpd, the controller and the initializer.
Both long-running processes use UID/GID 999; the directory is 0700 and socket
0600. No bearer token or management TCP listener is needed for this owner-only
path. Remote deployments use [verified mTLS](../reference/speaker-backends.md#remote-mtls).

## Configuration and persistence

By default, the initializer seeds **missing** inventory, playbook and correlation
YAML files from the image into the `prefixd-config` named volume. It preserves
existing edits on subsequent starts. The directory stays writable for
administrator saves, backups and atomic renames. Dashboard playbook, correlation
and alerting editors write there. Editing `configs/inventory.yaml` in the checkout
does not change this volume, even after a container or host restart.

The profile overlays only its main configuration read-only:
`configs/prefixd.yaml` for rustbgpd, `configs/prefixd-gobgp.yaml` for GoBGP.
These select the same POP but different immutable speaker targets. Restart the
controller after main-config changes. Choose one inventory workflow below.

### Host-managed inventory

To use `configs/inventory.yaml` directly, enable the supplied
[`docker-compose.inventory.yml`](../../docker-compose.inventory.yml) overlay.
It mounts only inventory read-only, for either speaker profile. Playbooks,
correlation and alerting keep their writable volume storage. The dashboard can
display inventory but does not edit it.

For an existing deployment, preserve its active inventory before switching if
you want to keep it; the overlay will hide the volume's copy. Back up the host
file, then export the running inventory **before enabling the overlay**:

```bash
cp configs/inventory.yaml configs/inventory.yaml.bak
docker compose exec -T prefixd-rustbgpd cat /etc/prefixd/inventory.yaml > configs/inventory.yaml
```

Edit `configs/inventory.yaml` for your network. The file must already exist and
be readable by UID/GID 999 inside the container. A missing source fails mounting
instead of being created as a directory. Add the following setting to your
existing `.env` file (create it if absent), so later Compose commands keep using
the same overlay:

```dotenv
COMPOSE_FILE=docker-compose.yml:docker-compose.inventory.yml
```

Use `;` instead of `:` on Windows. Validate the merged Compose configuration,
then create or recreate the controller to apply the mount:

```bash
docker compose --profile rustbgpd config --quiet
docker compose --profile rustbgpd up -d --no-build --force-recreate prefixd-rustbgpd
docker compose exec -T prefixd-rustbgpd cat /etc/prefixd/inventory.yaml
```

For GoBGP, replace `rustbgpd` with `gobgp` in these commands. Use the profile
already selected for the deployment. Confirm your customers and prefixes appear
under **Inventory → Customer inventory**. Inventory records ownership and service
context; loading prefixes does not start traffic monitoring or create mitigations.

After later edits, use **Config → Reload** and confirm success. Editors that save
by replacing the file can leave a single-file bind mount pointing at the old
copy. If the container's `cat` output differs from the host file, repeat the
`up --force-recreate` command above, then verify the loaded customer inventory.
Reload does not rebind a replaced host file.

Removing the `COMPOSE_FILE` setting and recreating the controller returns to the
preserved volume inventory, which may be older. To carry host edits back, first
copy `configs/inventory.yaml` to `inventory.local.yaml`. After switching back,
skip the initial export in the volume workflow below, stream that saved file
into the volume and reload.

### Volume-managed inventory

Without the overlay, inspect or edit the persisted inventory as follows. For
GoBGP, replace `prefixd-rustbgpd` with `prefixd-gobgp`.

```bash
docker compose exec -T prefixd-rustbgpd cat /etc/prefixd/inventory.yaml > inventory.local.yaml
# Edit inventory.local.yaml, then stream it back as the controller's UID 999.
docker compose exec -T prefixd-rustbgpd sh -ec '
  umask 077
  temporary=$(mktemp /etc/prefixd/.inventory.XXXXXX)
  trap "rm -f \"$temporary\"" EXIT
  cat > "$temporary"
  cp /etc/prefixd/inventory.yaml /etc/prefixd/inventory.yaml.bak
  mv "$temporary" /etc/prefixd/inventory.yaml
' < inventory.local.yaml
```

After the write, sign in to the dashboard as an administrator, open **Config**
and select **Reload**. Confirm that the reload succeeds before relying on the new
inventory. This request uses your authenticated browser session.

`docker compose down` preserves named volumes. `down -v` destroys configuration,
state and history; do not use it as an upgrade or speaker-switch procedure.

## Choose GoBGP instead

For a **fresh** deployment:

```bash
docker compose --profile gobgp up -d --pull always --no-build
docker compose exec prefixd-gobgp prefixdctl operators create \
  --username admin --role admin
```

The controller shares GoBGP's network namespace; management listens only on
`127.0.0.1:50051`. Recreate both together if that namespace owner is recreated:
`docker compose --profile gobgp up -d --force-recreate gobgp prefixd-gobgp`.
Do not select both profiles. Profile selection does not transfer an existing
database's speaker ownership binding.

## Verify and troubleshoot

```bash
docker compose logs prefixd-rustbgpd rustbgpd
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock health
docker compose exec rustbgpd rbgp --addr unix:///run/rustbgpd/grpc.sock neighbor
```

nginx serves HTTP/WebSocket on port 80. The selected speaker publishes BGP port
179; Prometheus publishes 9091 and Grafana 3001 on host loopback only. PostgreSQL,
controller HTTP and speaker management are not published separately. Public
application proxies block metrics. Change conflicting host port
mappings before starting. Use HTTPS at the public ingress for a remote deployment.
The running controller enforces TTLs; stopping it alone does not expire rules.

## Next steps

Adapt the sample policy to your network, then connect a signal source:

1. **Map your address space.** Choose host-managed or volume-managed inventory in
   [configuration and persistence](#configuration-and-persistence). Each
   customer lists its prefixes, and each service lists its assets and allowed
   ports. See the [inventory reference](../reference/configuration.md#inventoryyaml).
2. **Review playbooks.** As an administrator, open **Config → Playbooks**.
   Each playbook matches a vector, and the controller applies its first step's
   action and TTL. See [step selection](../reference/configuration.md#step-selection).
3. **Rehearse.** Run a [manual mitigation and withdrawal](../cookbook/manual-mitigation.md),
   or switch to [dry-run](../cookbook/dry-run-rollout.md) before you connect a
   detector.
4. **Connect a detector.** Use the [FastNetMon](../how-to/detectors/fastnetmon.md)
   notify script, [Alertmanager](../how-to/deployment.md#alertmanager-setup), or a
   [generic webhook adapter](../how-to/detectors/generic-webhook.md). Detectors
   usually authenticate with a bearer token; choose a mode in
   [authentication](../how-to/deployment.md#authentication-setup).
5. **Peer with your routers.** Replace the documentation peer in
   `configs/rustbgpd.toml` (or `configs/gobgp.conf`) and configure FlowSpec
   import on the router. See [router configuration](../how-to/deployment.md#router-configuration)
   and the [speaker semantics and qualification limits](../reference/speaker-backends.md).
