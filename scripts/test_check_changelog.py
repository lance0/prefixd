"""Exercise the PR gate against actual Git histories, including deletions."""

import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("check_changelog", Path(__file__).with_name("check-changelog.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class ChangelogGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        self.write("src/api/routes.rs", "original API\n")
        self.write("changelog.d/fixed-previous.md", "### Fixed\n\n- Previous change.\n")
        self.commit()
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True, stderr=subprocess.PIPE)

    def write(self, path, text):
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture")

    def test_existing_fragment_does_not_cover_new_surface_change(self):
        self.write("src/api/routes.rs", "changed API\n")
        self.commit()
        with self.assertRaisesRegex(ValueError, "add a changelog.d fragment"):
            gate.check(self.root, self.base, "HEAD")

    def test_added_or_updated_note_covers_change(self):
        for note in ["changelog.d/fixed-current.md", "changelog.d/fixed-previous.md"]:
            with self.subTest(note=note):
                self.write("src/api/routes.rs", "changed API\n")
                self.write(note, "### Fixed\n\n- Describe changed API.\n")
                self.commit()
                self.assertIn(note, gate.check(self.root, self.base, "HEAD"))

    def test_deleted_surface_and_deleted_fragment_still_require_note(self):
        (self.root / "src/api/routes.rs").unlink()
        (self.root / "changelog.d/fixed-previous.md").unlink()
        self.commit()
        with self.assertRaisesRegex(ValueError, "Candidate paths: src/api/routes.rs"):
            gate.check(self.root, self.base, "HEAD")

    def test_docs_and_test_only_changes_need_no_empty_release_note(self):
        self.write("docs/reference/api.md", "Correct a typo.\n")
        self.write("tests/integration.rs", "Additional assertion.\n")
        self.commit()
        self.assertIn("no fragment required", gate.check(self.root, self.base, "HEAD"))

    def test_deployment_overrides_and_detector_scripts_need_notes(self):
        for path in ["compose.rustbgpd.yaml", "scripts/prefixd-fastnetmon.sh"]:
            with self.subTest(path=path):
                self.write(path, "changed operator behavior\n")
                self.commit()
                with self.assertRaisesRegex(ValueError, "add a changelog.d fragment"):
                    gate.check(self.root, self.base, "HEAD")

    def test_specific_internal_rationale_is_visible_for_review(self):
        self.write("src/api/routes.rs", "same API with an internal helper\n")
        self.commit()
        reason = gate.no_change_reason("Changelog: not needed: Extract a helper without changing routes, payloads or logs.")
        self.assertIn(reason, gate.check(self.root, self.base, "HEAD", reason))

    def test_crlf_rationale_in_multiline_pr_body_is_recognized(self):
        reason = "Extract a helper without changing routes, payloads or logs."
        body = f"## Description\r\nChangelog: not needed: {reason}\r\n## Testing\r\n"
        self.assertEqual(gate.no_change_reason(body), reason)

    def test_rename_out_of_surface_paths_still_requires_a_note(self):
        self.write("docker-compose.yml", "services: {}\n")
        self.commit()
        base = self.git("rev-parse", "HEAD").strip()
        self.git("config", "diff.renames", "true")
        (self.root / "archive").mkdir()
        self.git("mv", "docker-compose.yml", "archive/compose.yml")
        self.commit()
        with self.assertRaisesRegex(ValueError, "Candidate paths: docker-compose.yml"):
            gate.check(self.root, base, "HEAD")

    def test_placeholders_and_ambiguous_exceptions_are_rejected(self):
        for body in [
            "Changelog: not needed: <specific reason>",
            "Changelog: not needed: N/A",
            "Changelog: not needed: internal refactor",
            "Changelog: not needed: A sufficiently detailed reason.\nChangelog: not needed: A second conflicting reason.",
        ]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                gate.no_change_reason(body)
        self.assertEqual(gate.no_change_reason("Document the format `Changelog: not needed: <specific reason>` here."), "")


if __name__ == "__main__":
    unittest.main()
