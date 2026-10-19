#!/usr/bin/env python3
"""Check profile isolation and missing-only initialization using the built image."""

import json
import os
import subprocess
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_IMAGE = os.environ.get("PREFIXD_IMAGE") or "ghcr.io/lance0/prefixd:main"
DASHBOARD_IMAGE = (
    os.environ.get("PREFIXD_DASHBOARD_IMAGE") or "ghcr.io/lance0/prefixd-dashboard:main"
)


def docker(*args, check=True):
    try:
        return subprocess.run(
            ["docker", *args], cwd=ROOT, text=True, capture_output=True, check=check
        )
    except subprocess.CalledProcessError as error:
        raise RuntimeError(f"{error.stdout}\n{error.stderr}") from error


class Profiles(unittest.TestCase):
    def model(self, profile):
        return json.loads(
            docker("compose", "--profile", profile, "config", "--format", "json").stdout
        )

    def test_profiles_isolate_backends_and_management(self):
        releases = json.loads((ROOT / "tests/fixtures/rustbgpd/releases.json").read_text())
        for profile in ("rustbgpd", "gobgp"):
            with self.subTest(profile=profile):
                services = self.model(profile)["services"]
                selected = f"prefixd-{profile}"
                other = "gobgp" if profile == "rustbgpd" else "rustbgpd"
                self.assertIn(selected, services)
                self.assertNotIn(f"prefixd-{other}", services)
                self.assertNotIn(other, services)
                self.assertEqual(services[selected]["user"], "999:999")
                self.assertEqual(services[selected]["image"], CONTROLLER_IMAGE)
                self.assertEqual(services["init"]["image"], CONTROLLER_IMAGE)
                self.assertEqual(services["dashboard"]["image"], DASHBOARD_IMAGE)
                mounts = {v["target"]: v for v in services[selected]["volumes"]}
                self.assertFalse(mounts["/etc/prefixd"].get("read_only", False))
                self.assertTrue(mounts["/etc/prefixd/prefixd.yaml"]["read_only"])
                for service in services.values():
                    for mount in service.get("volumes", []):
                        if mount["target"] in ("/etc/prefixd", "/data", "/run/rustbgpd"):
                            self.assertTrue(mount["volume"]["nocopy"], mount)
                self.assertTrue(
                    mounts["/etc/prefixd/prefixd.yaml"]["source"].endswith(
                        "prefixd.yaml" if profile == "rustbgpd" else "prefixd-gobgp.yaml"
                    )
                )
                for service in services.values():
                    for port in service.get("ports", []):
                        self.assertNotIn(str(port["target"]), ("8080", "50051", "5432"))
                for name, target, published in (
                    ("prometheus", 9090, "9091"),
                    ("grafana", 3000, "3001"),
                ):
                    ports = services[name]["ports"]
                    self.assertEqual(len(ports), 1)
                    self.assertEqual(ports[0]["host_ip"], "127.0.0.1")
                    self.assertEqual(ports[0]["target"], target)
                    self.assertEqual(ports[0]["published"], published)
                if profile == "rustbgpd":
                    self.assertEqual(services[profile]["image"], releases["0.78.0"]["image"])
                    self.assertEqual(services[profile]["user"], "999:999")
                    self.assertIn("prefixd", services[selected]["networks"]["default"]["aliases"])
                    socket_users = {
                        name
                        for name, service in services.items()
                        if any(v["target"] == "/run/rustbgpd" for v in service.get("volumes", []))
                    }
                    self.assertEqual(socket_users, {"init", "rustbgpd", selected})
                else:
                    self.assertEqual(services[selected]["network_mode"], "service:gobgp")
                    self.assertIn("prefixd", services[profile]["networks"]["default"]["aliases"])
                    self.assertIn("--api-hosts=127.0.0.1:50051", services[profile]["command"])
                    self.assertIn("--pprof-disable", services[profile]["command"])
                    self.assertIn("--metrics-path=", services[profile]["command"])
                    self.assertIn("@sha256:", services[profile]["image"])

    def test_two_profiles_fail_before_startup(self):
        result = docker(
            "compose", "--profile", "rustbgpd", "--profile", "gobgp", "config", check=False
        )
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("prefixd", result.stderr)


class ConfigSeeding(unittest.TestCase):
    def test_recreated_initializer_preserves_edits_and_atomic_writes(self):
        image = CONTROLLER_IMAGE
        volumes = [f"prefixd-init-test-{uuid.uuid4().hex}" for _ in range(3)]
        paths = ["/etc/prefixd", "/data", "/run/rustbgpd"]
        mounts = [
            arg
            for volume, path in zip(volumes, paths, strict=True)
            for arg in ("--mount", f"type=volume,source={volume},target={path},volume-nocopy")
        ]
        cpuset = os.environ.get("PREFIXD_TEST_CPUSET")
        affinity = ["--cpuset-cpus", cpuset] if cpuset else []
        try:
            for volume in volumes:
                docker("volume", "create", volume)
            for iteration in range(2):
                docker(
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    *affinity,
                    "--user",
                    "0:0",
                    *mounts,
                    "--entrypoint",
                    "/usr/local/bin/prefixd-init",
                    image,
                )
                result = docker(
                    "run",
                    "--rm",
                    "--network",
                    "none",
                    *affinity,
                    "--user",
                    "999:999",
                    *mounts,
                    "--entrypoint",
                    "/bin/sh",
                    image,
                    "-exc",
                    """
for directory in /etc/prefixd /data /run/rustbgpd; do
    test "$(stat -c '%u:%g:%a' "$directory")" = '999:999:700'
done
for file in inventory playbooks correlation; do test -r /etc/prefixd/$file.yaml; done
test ! -e /etc/prefixd/prefixd.yaml
if test -f /data/edited; then
    test "$(cat /etc/prefixd/playbooks.yaml)" = 'operator edit'
    test "$(cat /etc/prefixd/alerting.yaml)" = 'saved alerting'
else
    cp /etc/prefixd/playbooks.yaml /etc/prefixd/playbooks.yaml.bak
    printf '%s\\n' 'operator edit' > /etc/prefixd/.playbooks.tmp
    mv /etc/prefixd/.playbooks.tmp /etc/prefixd/playbooks.yaml
    printf '%s\\n' 'saved alerting' > /etc/prefixd/.alerting.tmp
    mv /etc/prefixd/.alerting.tmp /etc/prefixd/alerting.yaml
    touch /data/edited
fi
""",
                )
                self.assertEqual(result.returncode, 0, f"initializer iteration {iteration}")
        finally:
            for volume in volumes:
                docker("volume", "rm", volume, check=False)


if __name__ == "__main__":
    unittest.main()
