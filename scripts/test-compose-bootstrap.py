#!/usr/bin/env python3
"""Check scripts/compose-bootstrap.sh against a fake docker: modes, reruns, races and failures."""

import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/compose-bootstrap.sh"
CANONICAL = re.compile(r"^prefixd_[0-9a-f]{42}A$")

# Records each call's argv, then answers like docker compose + prefixdctl would.
# Each mint appends "name secret scope source" to $FAKE_LOG.tokens, which
# `tokens verify` looks the secret up in.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_LOG"
args="$*"
case "$args" in
    *"config --format yaml"*) echo "name: prefixd" ;;
    "volume ls"*)
        [[ -z "${FAKE_VOLUME_FAIL:-}" ]] || { echo "permission denied" >&2; exit 1; }
        [[ -z "${FAKE_PG_VOLUME:-}" ]] || echo prefixd_postgres-data ;;
    *" ps "*) [[ -n "${FAKE_STOPPED:-}" ]] || echo 0123456789ab ;;
    *"operators list"*)
        [[ -z "${FAKE_LIST_FAIL:-}" ]] || { echo "error: database error" >&2; exit 1; }
        if [[ -n "${FAKE_ADMIN:-}" ]]; then
            printf '[\n  {\n    "username": "a",\n    "role" :  "admin"\n  }\n]\n'
        else
            echo '[]'
        fi ;;
    *"operators create"*) echo "Created operator" ;;
    *"tokens verify"*)
        IFS= read -r secret || true
        [[ -n "$secret" ]] || { echo "error: the token file on stdin must hold one token on one line" >&2; exit 1; }
        [[ "$secret" =~ ^prefixd_[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$ ]] ||
            { echo "error: malformed token" >&2; exit 1; }
        record=
        [[ -n "${FAKE_DB_EMPTY:-}" ]] || record=$(grep -F " $secret " "$FAKE_LOG.tokens" 2>/dev/null)
        [[ -n "$record" ]] || { echo "error: unknown token" >&2; exit 1; }
        read -r name _ scope source <<<"$record"
        status=active
        [[ "$name" != "${FAKE_REVOKED:-}" ]] || status=revoked
        if [[ "$source" == - ]]; then source=null; else source="\"$source\""; fi
        printf '{\n  "name": "%s",\n  "scope": "%s",\n  "source": %s,\n  "status": "%s"\n}\n' \
            "$name" "$scope" "$source" "$status"
        [[ "$status" == active ]] || { echo "error: token '$name' is $status" >&2; exit 1; } ;;
    *"tokens create"*)
        name=$(sed -E 's/.*--name ([^ ]+).*/\1/' <<<"$args")
        scope=$(sed -E 's/.*--scope ([^ ]+).*/\1/' <<<"$args")
        source=-
        [[ "$args" != *--source* ]] || source=$(sed -E 's/.*--source ([^ ]+).*/\1/' <<<"$args")
        if [[ -n "${FAKE_BLOCK:-}" ]]; then
            touch "$FAKE_LOG.blocked"
            for _ in $(seq 300); do [[ -e "$FAKE_LOG.release" ]] && break; sleep 0.1; done
        fi
        [[ "$name" != "${FAKE_FAIL_ON:-none}"* ]] || { echo "error: database error" >&2; exit 1; }
        echo "Created token '$name'. The token below is shown once." >&2
        body="prefixd_$(printf '%s' "$name" | sha256sum | head -c 42)"
        echo "$name ${body}A $scope $source" >> "$FAKE_LOG.tokens"
        case "${FAKE_TOKEN:-}" in
            garbage) echo "not a token" ;;
            extra) printf '%sA\nextra line\n' "$body" ;;
            noncanonical) printf '%sB\n' "$body" ;;
            *) printf '%sA\n' "$body" ;;
        esac ;;
    *) echo "unexpected: $*" >&2; exit 99 ;;
esac
"""


class Harness(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        # A copy, so the repository root the script resolves is a scratch one.
        self.repo = self.home / "repo"
        (self.repo / "scripts").mkdir(parents=True)
        shutil.copy2(SCRIPT, self.repo / "scripts/compose-bootstrap.sh")
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        self.log = self.home / "calls.log"
        self.tokens = self.repo / ".prefixd"
        self.env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_LOG": str(self.log),
            "HOME": str(self.home),
        }

    def command(self, *args, cwd=None, extra=None, **fake):
        env = {**self.env, **(extra or {}), **{f"FAKE_{k.upper()}": v for k, v in fake.items()}}
        script = self.repo / "scripts/compose-bootstrap.sh"
        # A permissive umask must not leak into any secret file.
        argv = ["bash", "-c", 'umask 022; exec "$0" "$@"', str(script), *args]
        return argv, env, cwd or self.home

    def run_script(self, *args, cwd=None, extra=None, **fake):
        argv, env, cwd = self.command(*args, cwd=cwd, extra=extra, **fake)
        return subprocess.run(
            argv,
            env=env,
            cwd=cwd,
            text=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
            timeout=60,
        )

    def calls(self, needle=""):
        lines = self.log.read_text().splitlines() if self.log.exists() else []
        return [line for line in lines if needle in line]

    def files(self, directory=None):
        directory = directory or self.tokens
        if not directory.exists():
            return []
        return sorted(p.name for p in directory.iterdir())

    def assert_private(self, path, mode=0o600):
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode, path)
        self.assertEqual(path.stat().st_uid, os.getuid(), path)


class Bootstrap(Harness):
    def test_fresh_stack_writes_private_token_files(self):
        result = self.run_script("rustbgpd")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_private(self.tokens, 0o700)
        self.assertEqual(
            self.files(),
            ["cli.token", "cli.token.name", "fastnetmon.token", "fastnetmon.token.name"],
        )
        for name in ("cli", "fastnetmon"):
            token = self.tokens / f"{name}.token"
            recorded = self.tokens / f"{name}.token.name"
            self.assert_private(token)
            self.assert_private(recorded)
            self.assertRegex(recorded.read_text(), rf"^{name}-\d{{8}}-\d{{6}}\n$")
            secret = token.read_text().removesuffix("\n")
            self.assertRegex(secret, CANONICAL)
            # The secret is never printed or passed on a command line.
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertNotIn(secret, self.log.read_text())
        calls = self.calls()
        self.assertTrue(all("--profile rustbgpd" in call for call in calls), calls)
        creates = self.calls("operators create")
        self.assertEqual(len(creates), 1)
        self.assertIn(
            "exec prefixd-rustbgpd prefixdctl operators create --username admin", creates[0]
        )
        tokens = self.calls("tokens create")
        self.assertEqual(len(tokens), 2)
        self.assertIn("--scope ingest --source fastnetmon", tokens[0])
        self.assertIn("--scope operator", tokens[1])
        self.assertNotIn("--source", tokens[1])
        self.assertIn(
            "exec -T -e PREFIXD_TOKEN_FILE=/dev/stdin prefixd-rustbgpd prefixdctl status <",
            result.stdout,
        )

    def test_rerun_keeps_live_tokens_fixes_modes_and_skips_existing_admin(self):
        self.assertEqual(self.run_script("gobgp").returncode, 0)
        before = {name: (self.tokens / name).read_text() for name in self.files()}
        (self.tokens / "cli.token").chmod(0o644)
        (self.tokens / "fastnetmon.token.name").chmod(0o644)
        self.log.rename(self.home / "first.log")
        # Pretty-printed with odd spacing: matching must not depend on layout.
        result = self.run_script("gobgp", admin="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({name: (self.tokens / name).read_text() for name in self.files()}, before)
        for name in self.files():
            self.assert_private(self.tokens / name)
        self.assertFalse(self.calls("create"), self.calls())
        self.assertEqual(len(self.calls("tokens verify")), 2)
        self.assertIn("already exists", result.stdout)
        self.assertEqual(result.stdout.count("Keeping"), 2)

    def test_kept_token_the_database_lost_or_revoked_fails_loudly(self):
        self.assertEqual(self.run_script("rustbgpd").returncode, 0)
        result = self.run_script("rustbgpd", admin="1", db_empty="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("does not hold a live token of this database", result.stderr)
        self.assertIn("down -v", result.stderr)
        fnm = (self.tokens / "fastnetmon.token.name").read_text().strip()
        result = self.run_script("rustbgpd", admin="1", revoked=fnm)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f"token '{fnm}' is revoked", result.stderr)
        self.assertIn("does not hold a live token", result.stderr)
        self.assertFalse(self.calls("tokens create")[2:], "a rerun minted")

    def test_swapped_emptied_truncated_or_renamed_files_fail_the_rerun(self):
        self.assertEqual(self.run_script("rustbgpd").returncode, 0)
        files = {n: (self.tokens / n).read_text() for n in self.files()}

        def restore():
            for name, text in files.items():
                (self.tokens / name).write_text(text)

        cases = {
            "swapped secrets": {
                "cli.token": files["fastnetmon.token"],
                "fastnetmon.token": files["cli.token"],
            },
            "swapped secrets and names": {
                "cli.token": files["fastnetmon.token"],
                "cli.token.name": files["fastnetmon.token.name"],
                "fastnetmon.token": files["cli.token"],
                "fastnetmon.token.name": files["cli.token.name"],
            },
            "emptied": {"cli.token": ""},
            "truncated": {"fastnetmon.token": files["fastnetmon.token"][:30] + "\n"},
            "renamed": {"cli.token.name": "cli-20000101-000000\n"},
        }
        expected = {
            "swapped secrets": "were the token files swapped",
            "swapped secrets and names": "were the token files swapped",
            "emptied": "does not hold a live token",
            "truncated": "does not hold a live token",
            "renamed": "records 'cli-20000101-000000'",
        }
        for label, changes in cases.items():
            with self.subTest(label=label):
                restore()
                for name, text in changes.items():
                    (self.tokens / name).write_text(text)
                result = self.run_script("rustbgpd", admin="1")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(expected[label], result.stderr)
                for secret in files["cli.token"], files["fastnetmon.token"]:
                    self.assertNotIn(secret.strip(), result.stdout + result.stderr)
        self.assertFalse(self.calls("tokens create")[2:], "a rerun minted")

    def test_bad_mint_output_is_refused_and_names_the_orphan(self):
        for kind in ("garbage", "extra", "noncanonical"):
            with self.subTest(kind=kind):
                shutil.rmtree(self.tokens, ignore_errors=True)
                result = self.run_script("rustbgpd", token=kind)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(self.files(), [])
                self.assertRegex(
                    result.stderr,
                    r"token 'fastnetmon-\d{8}-\d{6}' was minted but not stored; revoke it: "
                    r"docker compose exec prefixd-rustbgpd prefixdctl tokens revoke fastnetmon-",
                )

    def test_failed_listing_stops_before_any_create(self):
        result = self.run_script("rustbgpd", list_fail="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.calls("create"), self.calls())
        self.assertEqual(self.files(), [])

    def test_second_mint_failure_keeps_the_first_and_a_rerun_finishes(self):
        result = self.run_script("rustbgpd", fail_on="cli")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.files(), ["fastnetmon.token", "fastnetmon.token.name"])
        self.assertIn("minting 'cli-", result.stderr)
        self.assertIn("revoke it: docker compose exec prefixd-rustbgpd", result.stderr)
        first = (self.tokens / "fastnetmon.token").read_text()
        self.log.write_text("")
        result = self.run_script("rustbgpd", admin="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.tokens / "fastnetmon.token").read_text(), first)
        minted = self.calls("tokens create")
        self.assertEqual(len(minted), 1)
        self.assertIn("--name cli-", minted[0])

    def test_concurrent_run_is_refused_while_one_holds_the_lock(self):
        argv, env, cwd = self.command("rustbgpd", block="1")
        first = subprocess.Popen(
            argv, env=env, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        try:
            # Handshake: the first run is inside its first mint, holding the lock.
            blocked = Path(f"{self.log}.blocked")
            deadline = time.monotonic() + 30
            while not blocked.exists():
                if first.poll() is not None:
                    self.fail(f"first run exited early: {first.communicate()[1]}")
                self.assertLess(time.monotonic(), deadline, "first run never reached its mint")
                time.sleep(0.05)
            second = self.run_script("rustbgpd")
            self.assertEqual(second.returncode, 1)
            self.assertIn("another bootstrap holds", second.stderr)
        finally:
            Path(f"{self.log}.release").touch()
            _, err = first.communicate(timeout=60)
        self.assertEqual(first.returncode, 0, err)
        self.assertEqual(len(self.calls("tokens create")), 2)
        self.assertNotIn(".lock", self.files())

    def test_relative_token_dir_is_the_callers(self):
        caller = self.home / "caller"
        caller.mkdir()
        result = self.run_script("rustbgpd", cwd=caller, extra={"PREFIXD_TOKEN_DIR": "secrets"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cli.token", self.files(caller / "secrets"))
        self.assertFalse((self.repo / "secrets").exists())

    def test_a_lock_path_that_is_not_a_held_lock_is_its_own_error(self):
        self.tokens.mkdir(mode=0o700)
        (self.tokens / ".lock").write_text("not a directory")
        result = self.run_script("rustbgpd")
        self.assertEqual(result.returncode, 1)
        self.assertIn("cannot create the lock directory", result.stderr)
        self.assertNotIn("another bootstrap holds", result.stderr)
        self.assertFalse(self.calls("create"))

    def test_stopped_service_and_bad_profile_fail_loudly(self):
        result = self.run_script("rustbgpd", stopped="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("prefixd-rustbgpd is not running", result.stderr)
        self.assertFalse(self.tokens.exists())
        result = self.run_script("both")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertFalse(self.calls("create"))


class EnvFile(Harness):
    def env_file(self):
        return self.repo / ".env"

    def test_fresh_checkout_gets_a_private_random_password(self):
        result = self.run_script("env")
        self.assertEqual(result.returncode, 0, result.stderr)
        text = self.env_file().read_text()
        self.assertRegex(text, r"^POSTGRES_PASSWORD=[0-9a-f]{64}\n$")
        self.assert_private(self.env_file())
        self.assertNotIn(text.split("=")[1].strip(), result.stdout + result.stderr)

    def test_existing_env_is_extended_or_kept(self):
        self.env_file().write_text("COMPOSE_FILE=a.yml:b.yml")
        self.env_file().chmod(0o644)
        self.assertEqual(self.run_script("env").returncode, 0)
        lines = self.env_file().read_text().splitlines()
        self.assertEqual(lines[0], "COMPOSE_FILE=a.yml:b.yml")
        self.assertRegex(lines[1], r"^POSTGRES_PASSWORD=[0-9a-f]{64}$")
        self.assert_private(self.env_file())
        before = self.env_file().read_text()
        self.env_file().chmod(0o644)
        result = self.run_script("env")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.env_file().read_text(), before)
        self.assert_private(self.env_file())

    def test_published_example_values_are_kept_with_a_warning(self):
        for value in ("your-secure-password", "prefixd_secret"):
            with self.subTest(value=value):
                self.env_file().write_text(f"POSTGRES_PASSWORD={value}\n")
                result = self.run_script("env")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("published example value", result.stderr)
                self.assertEqual(self.env_file().read_text(), f"POSTGRES_PASSWORD={value}\n")

    def test_an_exported_password_is_refused_on_both_paths(self):
        exported = {"POSTGRES_PASSWORD": "exported-canary"}
        result = self.run_script("env", extra=exported)
        self.assertEqual(result.returncode, 1)
        self.assertIn("unset POSTGRES_PASSWORD", result.stderr)
        self.assertFalse(self.env_file().exists())
        self.env_file().write_text("POSTGRES_PASSWORD=kept\n")
        result = self.run_script("env", extra=exported)
        self.assertEqual(result.returncode, 1)
        self.assertIn("overrides .env", result.stderr)
        self.assertEqual(self.env_file().read_text(), "POSTGRES_PASSWORD=kept\n")
        self.assertNotIn("exported-canary", result.stdout + result.stderr)
        self.assertFalse(self.calls("volume ls"))

    def test_a_failed_volume_listing_writes_no_password(self):
        result = self.run_script("env", volume_fail="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot list Docker volumes", result.stderr)
        self.assertFalse(self.env_file().exists())

    def test_placeholder_duplicate_symlink_and_existing_database_are_refused(self):
        for content in (
            "POSTGRES_PASSWORD=\n",
            "POSTGRES_PASSWORD=a\nPOSTGRES_PASSWORD=b\n",
        ):
            with self.subTest(content=content):
                self.env_file().write_text(content)
                result = self.run_script("env")
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertEqual(self.env_file().read_text(), content)
        self.env_file().unlink()
        self.env_file().symlink_to(self.home / "elsewhere")
        self.assertEqual(self.run_script("env").returncode, 1)
        self.assertFalse((self.home / "elsewhere").exists())
        self.env_file().unlink()
        result = self.run_script("env", pg_volume="1")
        self.assertEqual(result.returncode, 1)
        self.assertIn("already has a PostgreSQL volume", result.stderr)
        self.assertFalse(self.env_file().exists())


if __name__ == "__main__":
    unittest.main()
