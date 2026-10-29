#!/usr/bin/env python3
"""Own an isolated stack for the existing authenticated withdrawal browser smoke."""

import argparse
import contextlib
import hashlib
import http.cookiejar
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
VICTIM = "203.0.113.10"


def command(*args, combined=False, **kwargs):
    result = subprocess.run(args, check=True, capture_output=True, text=True, timeout=60, **kwargs)
    return (result.stdout + result.stderr if combined else result.stdout).strip()


def interrupted(signum, _frame):
    raise RuntimeError(f"received signal {signum}")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def tcp_ready(port):
    with socket.create_connection(("127.0.0.1", port), timeout=1):
        return True


def wait_ready(probe, processes=()):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        assert all(process.poll() is None for process in processes), "owned process exited"
        try:
            if probe():
                return
        except (OSError, urllib.error.URLError, subprocess.SubprocessError):
            pass
        time.sleep(0.2)
    raise TimeoutError("owned service did not become ready")


def assert_routes(snapshot, present):
    assert snapshot["backend"] == "rustbgpd"
    assert snapshot["observation_scope"] == "retained_local_flow_spec_intent"
    routes = snapshot["routes"]
    assert isinstance(routes, list)
    assert len(routes) == int(present), "unexpected retained local FlowSpec inventory"
    if present:
        assert routes[0]["nlri"]["dst_prefix"] == f"{VICTIM}/32"
        assert routes[0]["nlri"]["protocol"] == 17
        assert routes[0]["nlri"]["dst_ports"] == [53]
        assert routes[0]["actions"][0]["action_type"] == "discard"


class Stack(contextlib.ExitStack):
    def __init__(self, output):
        super().__init__()
        self.output = output
        self.secrets = []
        self.logs = Path(
            self.enter_context(tempfile.TemporaryDirectory(prefix="prefixd-browser-logs-"))
        )

    def retain(self, name, content):
        for secret in self.secrets:
            content = content.replace(secret, "[redacted]")
        (self.output / name).write_text(content)

    def container(self, name, *args):
        def cleanup():
            try:
                owner = command(
                    "docker",
                    "inspect",
                    "--format",
                    '{{index .Config.Labels "io.prefixd.browser-smoke"}}',
                    name,
                )
            except subprocess.CalledProcessError as error:
                if "No such object" in (error.stderr or ""):
                    return  # Creation failed before a container existed.
                raise
            assert owner == name, "refusing to remove an unowned container"
            try:
                self.retain(
                    f"{name.rsplit('-', 1)[-1]}.log", command("docker", "logs", name, combined=True)
                )
            finally:
                command("docker", "rm", "-fv", name)

        # Register before create so a CLI timeout after daemon acceptance still cleans up.
        self.callback(cleanup)
        command(
            "docker", "create", "--name", name, "--label", f"io.prefixd.browser-smoke={name}", *args
        )
        command("docker", "start", name)
        return name

    def process(self, name, args, cwd, env):
        path = self.logs / f"{name}.log"
        with path.open("w") as log:
            process = subprocess.Popen(
                args, cwd=cwd, env=env, stdout=log, stderr=log, start_new_session=True
            )

        def cleanup():
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=10)
            self.retain(f"{name}.log", path.read_text())

        self.callback(cleanup)
        return process


def run(binary_dir, output):
    os.umask(0o077)
    output.mkdir(parents=True)  # Refuse to overwrite earlier evidence.
    stage = "validate build outputs"
    receipt = {"status": "failed", "started_at": time.time()}
    try:
        binaries = [binary_dir / name for name in ("prefixd", "prefixdctl")]
        assert all(path.is_file() and os.access(path, os.X_OK) for path in binaries)
        assert (ROOT / "frontend/.next/BUILD_ID").is_file(), "run just frontend first"
        revision = command("git", "rev-parse", "HEAD", cwd=ROOT)
        release = json.loads((ROOT / "tests/fixtures/rustbgpd/releases.json").read_text())["0.80.1"]
        receipt.update(
            candidate_revision=revision,
            binary_sha256={
                path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in binaries
            },
            ui_build_id=(ROOT / "frontend/.next/BUILD_ID").read_text().strip(),
            speaker_release=release,
        )
        with Stack(output) as stack:
            temporary = stack.enter_context(tempfile.TemporaryDirectory(prefix="prefixd-browser-"))
            private = Path(temporary)
            identity = f"prefixd-browser-{uuid.uuid4().hex}"
            password, token, db_password = (secrets.token_hex(32) for _ in range(3))
            stack.secrets.extend((password, token, db_password))
            affinity = (
                ["--cpuset-cpus", os.environ["PREFIXD_TEST_CPUSET"]]
                if os.environ.get("PREFIXD_TEST_CPUSET")
                else []
            )
            stage = "start PostgreSQL"
            postgres = stack.container(
                f"{identity}-postgres",
                *affinity,
                "--publish",
                "127.0.0.1::5432",
                "--env",
                "POSTGRES_DB=prefixd",
                "--env",
                "POSTGRES_USER=prefixd",
                "--env",
                f"POSTGRES_PASSWORD={db_password}",
                "postgres:16-alpine",
            )
            wait_ready(
                lambda: (
                    command(
                        "docker",
                        "exec",
                        postgres,
                        "pg_isready",
                        "--host",
                        "127.0.0.1",
                        "-U",
                        "prefixd",
                        "-d",
                        "prefixd",
                    )
                    is not None
                )
            )
            pg_port = command("docker", "port", postgres, "5432/tcp").rsplit(":", 1)[1]
            database = f"postgres://prefixd:{db_password}@127.0.0.1:{pg_port}/prefixd"
            (private / "token").write_text(token)
            (private / "runtime").mkdir()
            (private / "speaker.toml").write_text("""config_epoch = 2
[global]
asn = 64512
router_id = "192.0.2.1"
listen_addresses = ["127.0.0.1"]
listen_port = 1179
runtime_state_dir = "/fixture/runtime"
worker_threads = 2
ebgp_requires_policy = true
[global.telemetry]
prometheus_addr = "127.0.0.1:9179"
log_format = "text"
[global.telemetry.grpc_uds]
enabled = false
[global.telemetry.grpc_tcp]
address = "0.0.0.0:50051"
access_mode = "read_write"
token_file = "/fixture/token"
principal = "prefixd-browser"
[security.grpc.roles]
prefixd-browser = "operator"
""")
            stage = "start pinned speaker"
            speaker = stack.container(
                f"{identity}-speaker",
                *affinity,
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--publish",
                "127.0.0.1::50051",
                "--volume",
                f"{private}:/fixture",
                release["image"],
                "rustbgpd",
                "/fixture/speaker.toml",
            )
            rpc_port = command("docker", "port", speaker, "50051/tcp").rsplit(":", 1)[1]
            wait_ready(lambda: tcp_ready(int(rpc_port)))
            endpoint = f"http://127.0.0.1:{rpc_port}"
            receipt["speaker_endpoint"] = endpoint
            config = private / "config"
            config.mkdir()
            for name in ("inventory.yaml", "playbooks.yaml"):
                (config / name).write_bytes((ROOT / "configs" / name).read_bytes())
            # JSON is valid YAML; keep this isolated fixture independent of a YAML dependency.
            settings = {
                "pop": "browser-smoke",
                "mode": "enforced",
                "http": {"listen": f"127.0.0.1:{free_port()}", "auth": {"mode": "credentials"}},
                "bgp": {
                    "backend": "rustbgpd",
                    "rustbgpd": {"endpoint": endpoint, "bearer_token_env": "PREFIXD_BROWSER_TOKEN"},
                    "local_asn": 64512,
                    "router_id": "192.0.2.1",
                    "neighbors": [],
                },
                "guardrails": {
                    "require_ttl": True,
                    "dst_prefix_minlen": 32,
                    "dst_prefix_maxlen": 32,
                    "max_ports": 5,
                },
                "quotas": {
                    "max_active_per_customer": 20,
                    "max_active_per_pop": 200,
                    "max_active_global": 500,
                    "max_new_per_minute": 30,
                },
                "timers": {
                    "default_ttl_seconds": 1800,
                    "min_ttl_seconds": 30,
                    "max_ttl_seconds": 1800,
                    "reconciliation_interval_seconds": 30,
                },
                "storage": {"connection_string": database},
                "observability": {"log_format": "json", "log_level": "info"},
            }
            (config / "prefixd.yaml").write_text(json.dumps(settings))
            env = {**os.environ, "DATABASE_URL": database, "PREFIXD_BROWSER_TOKEN": token}
            stage = "start controller"
            backend = stack.process(
                "controller", [str(binaries[0]), "--config", str(config)], ROOT, env
            )
            api = f"http://{settings['http']['listen']}"
            client = urllib.request.build_opener(
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())
            )

            def request(path, data=None):
                payload = None if data is None else json.dumps(data).encode()
                req = urllib.request.Request(
                    f"{api}/v1{path}", payload, {"Content-Type": "application/json"}
                )
                with client.open(req, timeout=5) as response:
                    return json.load(response)

            wait_ready(lambda: request("/health")["auth_mode"] == "credentials", [backend])
            stage = "create ephemeral operator and active fixture"
            command(
                str(binaries[1]),
                "operators",
                "create",
                "--username",
                "browser-smoke",
                "--password",
                password,
                "--role",
                "operator",
                env=env,
            )
            request("/auth/login", {"username": "browser-smoke", "password": password})
            assert_routes(request("/speaker/routes"), False)
            mitigation = request(
                "/mitigations",
                {
                    "victim_ip": VICTIM,
                    "protocol": "udp",
                    "dst_ports": [53],
                    "action": "discard",
                    "ttl_seconds": 1800,
                    "reason": "isolated browser fixture",
                },
            )
            assert mitigation["status"] == "active"
            before = request("/speaker/routes")
            assert_routes(before, True)
            stack.retain("speaker-before.json", json.dumps(before, indent=2) + "\n")
            port = free_port()
            origin = f"http://127.0.0.1:{port}"
            stage = "start production dashboard"
            frontend = stack.process(
                "dashboard",
                ["bun", "run", "start", "--hostname", "127.0.0.1", "--port", str(port)],
                ROOT / "frontend",
                {**env, "PREFIXD_API": api},
            )

            def dashboard_ready():
                with urllib.request.urlopen(f"{origin}/login", timeout=5) as response:
                    return response.status == 200

            wait_ready(dashboard_ready, [backend, frontend])
            stage = "authenticated browser withdrawal"
            browser_env = {
                **env,
                "PREFIXD_SMOKE_URL": origin,
                "PREFIXD_SMOKE_USERNAME": "browser-smoke",
                "PREFIXD_SMOKE_PASSWORD": password,
                "PREFIXD_SMOKE_MITIGATION_ID": mitigation["mitigation_id"],
                "PREFIXD_SMOKE_OUTPUT_DIR": str(output / "browser"),
                "PREFIXD_SMOKE_UI_SOURCE": f"candidate-local {revision}",
            }
            browser = stack.process(
                "browser", ["bun", "scripts/smoke-withdraw.ts"], ROOT / "frontend", browser_env
            )
            assert browser.wait(timeout=150) == 0, "browser smoke failed"
            assert json.loads((output / "browser/receipt.json").read_text())["status"] == "passed"
            stage = "verify retained local intent absent"
            after = request("/speaker/routes")
            assert_routes(after, False)
            stack.retain("speaker-after.json", json.dumps(after, indent=2) + "\n")
        receipt["status"] = "passed"
    except (Exception, KeyboardInterrupt) as error:
        receipt.update(failed_stage=stage, error_type=type(error).__name__)
        raise RuntimeError(
            f"Browser lifecycle failed at: {stage} ({type(error).__name__})"
        ) from None
    finally:
        receipt["finished_at"] = time.time()
        (output / "lifecycle.json").write_text(json.dumps(receipt, indent=2) + "\n")


class SelfTests(unittest.TestCase):
    def test_observation_refuses_unknown_failed_or_wrong_scope(self):
        empty = {
            "backend": "rustbgpd",
            "observation_scope": "retained_local_flow_spec_intent",
            "routes": [],
        }
        assert_routes(empty, False)
        for bad in (
            {},
            {**empty, "routes": None},
            {**empty, "backend": "gobgp"},
            {**empty, "observation_scope": "adapter_local_flow_spec"},
        ):
            with self.assertRaises((AssertionError, KeyError)):
                assert_routes(bad, False)
        with self.assertRaises(AssertionError):
            assert_routes(empty, True)

    def test_creation_timeout_or_start_failure_cleans_owned_container_and_redacts_logs(self):
        for failure in ("create", "start"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                calls = []

                def fake(*args, failure=failure, calls=calls, **kwargs):
                    calls.append(args)
                    if args[1] == failure:
                        if failure == "create":
                            raise subprocess.TimeoutExpired(args, 60)
                        raise subprocess.CalledProcessError(1, args)
                    if args[1] == "inspect":
                        return "owned-fixture-speaker"
                    return "private-token"

                with (
                    patch(f"{__name__}.command", side_effect=fake),
                    self.assertRaises(subprocess.SubprocessError),
                    Stack(Path(directory)) as stack,
                ):
                    stack.secrets.append("private-token")
                    stack.container("owned-fixture-speaker", "image")
                self.assertEqual(calls[-1], ("docker", "rm", "-fv", "owned-fixture-speaker"))
                self.assertEqual((Path(directory) / "speaker.log").read_text(), "[redacted]")

    def test_cleanup_refuses_an_unowned_container(self):
        with tempfile.TemporaryDirectory() as directory:
            with (
                patch(f"{__name__}.command", return_value="foreign-label") as mocked,
                self.assertRaises(AssertionError),
                Stack(Path(directory)) as stack,
            ):
                stack.container("owned-fixture-speaker", "image")
            self.assertFalse(any(call.args[1] == "rm" for call in mocked.call_args_list))

    def test_sigterm_unwinds_owned_cleanup(self):
        old = signal.signal(signal.SIGTERM, interrupted)
        try:
            with tempfile.TemporaryDirectory() as directory:
                output = Path(directory)
                with self.assertRaises(RuntimeError), Stack(output) as stack:
                    process = stack.process(
                        "child",
                        [sys.executable, "-c", "import time; time.sleep(60)"],
                        ROOT,
                        os.environ.copy(),
                    )
                    wait_ready(lambda: os.kill(os.getpid(), signal.SIGTERM), [process])
                self.assertIsNotNone(process.poll())
                self.assertTrue((output / "child.log").is_file())
                self.assertFalse(stack.logs.exists())
        finally:
            signal.signal(signal.SIGTERM, old)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--binary-dir",
        type=Path,
        default=Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")) / "release",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=ROOT / "target/qualification/browser-smoke"
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        unittest.main(argv=[__file__])
    else:
        signal.signal(signal.SIGTERM, interrupted)
        try:
            run(args.binary_dir.resolve(), args.output_dir.resolve())
        except RuntimeError as error:
            parser.exit(1, f"{error}\n")
        print("Authenticated browser lifecycle passed; owned stack removed")
