#!/usr/bin/env python3
"""Check scripts/compose-bootstrap.sh against a fake docker: modes, reruns and failures."""

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/compose-bootstrap.sh"

# Records each call's argv, then answers like docker compose + prefixdctl would.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_LOG"
case "$*" in
    *" ps "*) [[ -n "${FAKE_STOPPED:-}" ]] || echo 0123456789ab ;;
    *"operators list"*)
        if [[ -n "${FAKE_ADMIN:-}" ]]; then echo '[{"username": "a", "role": "admin"}]'; else echo '[]'; fi ;;
    *"operators create"*) echo "Created operator" ;;
    *"tokens create"*)
        [[ -z "${FAKE_TOKEN_FAIL:-}" ]] || { echo "error: database error" >&2; exit 1; }
        [[ -z "${FAKE_TOKEN_GARBAGE:-}" ]] || { echo "not a token"; exit 0; }
        name=$(sed -E 's/.*--name ([^ ]+).*/\1/' <<<"$*")
        echo "Created token '$name'. The token below is shown once." >&2
        printf 'prefixd_%s\n' "$(printf '%s' "$name" | sha256sum | head -c 43)" ;;
    *) echo "unexpected: $*" >&2; exit 99 ;;
esac
"""


class Bootstrap(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        docker = bin_dir / "docker"
        docker.write_text(FAKE_DOCKER)
        docker.chmod(0o755)
        self.log = self.home / "calls.log"
        self.tokens = self.home / "tokens"
        self.env = {
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "FAKE_LOG": str(self.log),
            "PREFIXD_TOKEN_DIR": str(self.tokens),
            "HOME": str(self.home),
        }

    def run_script(self, *args, **fake):
        env = {**self.env, **{f"FAKE_{key.upper()}": "1" for key in fake}}
        return subprocess.run(
            # A permissive umask must not leak into the token files.
            ["bash", "-c", 'umask 022; exec "$0" "$@"', str(SCRIPT), *args],
            env=env,
            text=True,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_fresh_stack_writes_private_token_files(self):
        result = self.run_script("rustbgpd")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(self.tokens.stat().st_mode), 0o700)
        self.assertEqual(
            sorted(p.name for p in self.tokens.iterdir()), ["cli.token", "fastnetmon.token"]
        )
        for path in self.tokens.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, path)
            self.assertEqual(path.stat().st_uid, os.getuid())
            secret = path.read_text().strip()
            self.assertRegex(secret, r"^prefixd_[0-9a-f]{43}$")
            # The secret is never printed or passed on a command line.
            self.assertNotIn(secret, result.stdout + result.stderr)
            self.assertNotIn(secret, self.log.read_text())
        calls = self.calls()
        self.assertTrue(all("--profile rustbgpd" in call for call in calls), calls)
        creates = [call for call in calls if "operators create" in call]
        self.assertEqual(len(creates), 1)
        self.assertIn(
            "exec prefixd-rustbgpd prefixdctl operators create --username admin", creates[0]
        )
        tokens = [call for call in calls if "tokens create" in call]
        self.assertEqual(len(tokens), 2)
        self.assertIn("--scope ingest --source fastnetmon", tokens[0])
        self.assertIn("--scope operator", tokens[1])
        self.assertNotIn("--source", tokens[1])
        self.assertIn("exec -e PREFIXD_TOKEN prefixd-rustbgpd prefixdctl status", result.stdout)

    def test_rerun_keeps_tokens_and_existing_admin(self):
        self.assertEqual(self.run_script("gobgp").returncode, 0)
        before = {p.name: p.read_text() for p in self.tokens.iterdir()}
        self.log.unlink()
        result = self.run_script("gobgp", admin=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual({p.name: p.read_text() for p in self.tokens.iterdir()}, before)
        self.assertFalse([c for c in self.calls() if "create" in c], self.calls())
        self.assertIn("already exists", result.stdout)

    def test_failed_or_garbled_mint_leaves_no_token_file(self):
        for fake in ("token_fail", "token_garbage"):
            with self.subTest(fake=fake):
                result = self.run_script("rustbgpd", **{fake: True})
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(list(self.tokens.iterdir()), [])

    def test_stopped_service_and_bad_profile_fail_loudly(self):
        result = self.run_script("rustbgpd", stopped=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("prefixd-rustbgpd is not running", result.stderr)
        self.assertFalse(self.tokens.exists())
        result = self.run_script("both")
        self.assertEqual(result.returncode, 2)
        self.assertIn("usage:", result.stderr)
        self.assertFalse([c for c in self.calls() if "create" in c])


if __name__ == "__main__":
    unittest.main()
