#!/usr/bin/env python3
"""Exercise release admission against disposable Git history and recorded workflow runs."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().with_name("release-check.sh")
FAKE_GH = r"""#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from urllib.parse import parse_qs, urlsplit

assert sys.argv[1] == "api", sys.argv
url = urlsplit(sys.argv[2])
workflow = url.path.split("/")[-2]
query = parse_qs(url.query)
assert query["head_sha"] == [os.environ["TEST_SHA"]], query
assert query["branch"] == ["main"], query
assert query["event"] == ["push"], query
runs = json.loads(os.environ["TEST_RUNS"])[workflow]
if "status" in query:
    runs = [run for run in runs if run["conclusion"] == query["status"][0]]
data = {"total_count": len(runs), "workflow_runs": runs[:int(query["per_page"][0])]}
result = subprocess.run(
    ["jq", "-r", sys.argv[sys.argv.index("--jq") + 1]],
    input=json.dumps(data), text=True, check=False, timeout=5,
)
sys.exit(result.returncode)
"""


def run(conclusion="success", status="completed"):
    return {"status": status, "conclusion": conclusion}


class ReleaseCheckTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        # Git hooks export repository paths; fixtures must never inherit them.
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
        self.git("init", "--quiet", "--initial-branch=main")
        (self.repo / "Cargo.toml").write_text('[package]\nname = "prefixd"\nversion = "0.28.0"\n')
        self.git("add", "Cargo.toml")
        self.git(
            "-c",
            "user.name=Release fixture",
            "-c",
            "user.email=fixture@example.test",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "-m",
            "release fixture",
        )
        self.sha = self.git("rev-parse", "HEAD").stdout.strip()
        self.git("clone", "--quiet", "--bare", str(self.repo), str(self.root / "origin"))
        self.git("remote", "add", "origin", str(self.root / "origin"))
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        self.env = {
            **self.env,
            "PATH": f"{bin_dir}:{os.environ['PATH']}",
            "GITHUB_REPOSITORY": "example/prefixd",
            "TEST_SHA": self.sha,
        }

    def git(self, *args):
        return subprocess.run(
            ["git", *args],
            cwd=self.repo,
            env=self.env,
            text=True,
            capture_output=True,
            check=True,
            timeout=10,
        )

    def check(self, ci=None, interop=None, dry_run=False):
        env = {
            **self.env,
            "TEST_RUNS": json.dumps(
                {
                    "ci.yml": [run()] if ci is None else ci,
                    "interop.yml": [run()] if interop is None else interop,
                }
            ),
            "DRY_RUN": "1" if dry_run else "",
        }
        return subprocess.run(
            ["bash", str(SCRIPT), "v0.28.0", self.sha],
            cwd=self.repo,
            env=env,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_both_exact_commit_workflows_pass(self):
        result = self.check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("ci.yml passed", result.stdout)
        self.assertIn("interop.yml passed", result.stdout)

    def test_interop_must_exist_and_finish_successfully(self):
        for runs in (
            [],
            [run(None, "queued")],
            [run(None, "in_progress")],
            [run("failure")],
            [run("cancelled")],
            [run("skipped")],
        ):
            with self.subTest(runs=runs):
                result = self.check(interop=runs)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("interop.yml", result.stderr)

    def test_older_success_cannot_hide_a_newer_failed_or_pending_run(self):
        for workflow in ("ci", "interop"):
            for latest in (run("failure"), run(None, "in_progress")):
                with self.subTest(workflow=workflow, latest=latest):
                    result = self.check(**{workflow: [latest, run()]})
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn(f"{workflow}.yml", result.stderr)

    def test_dry_run_also_requires_interop(self):
        result = self.check(interop=[], dry_run=True)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn("interop.yml", result.stderr)

    def test_hook_repository_environment_stays_outside_the_fixture(self):
        config = (self.repo / ".git/config").read_bytes()
        index = (self.repo / ".git/index").read_bytes()
        result = subprocess.run(
            [
                "python3",
                str(Path(__file__).resolve()),
                "ReleaseCheckTests.test_both_exact_commit_workflows_pass",
            ],
            env={
                **self.env,
                "GIT_DIR": str(self.repo / ".git"),
                "GIT_WORK_TREE": str(self.repo),
                "GIT_INDEX_FILE": str(self.repo / ".git/index"),
            },
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.repo / ".git/config").read_bytes(), config)
        self.assertEqual((self.repo / ".git/index").read_bytes(), index)
        self.assertEqual(self.git("rev-parse", "HEAD").stdout.strip(), self.sha)


if __name__ == "__main__":
    unittest.main()
