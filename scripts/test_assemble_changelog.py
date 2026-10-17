#!/usr/bin/env python3
"""Regression tests for the changelog fragment assembler."""

import importlib.util
import tempfile
import unittest
from pathlib import Path
from unittest import mock

PATH = Path(__file__).with_name("assemble-changelog.py")
SPEC = importlib.util.spec_from_file_location("assemble_changelog", PATH)
assemble = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(assemble)

CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Existing added entry.

### Fixed

- Existing fixed entry, hard-wrapped over
  two lines.
  **Operator-visible:** it stays as written.

## [1.0.0] — 2026-01-01

### Added

- Released entry.
"""
MULTILINE = """### Fixed

- A fix wrapped over several lines with a
  [reference link](https://example.org/reference) and a
  `**bold**`-free `code span`.
  **Operator-visible:** the second paragraph of the bullet.
- A second bullet in the same fragment.
"""


class AssembleChangelogTests(unittest.TestCase):
    def tree(self, changelog: str = CHANGELOG, **fragments: str) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        (root / "CHANGELOG.md").write_text(changelog, encoding="utf-8")
        (root / "changelog.d").mkdir()
        (root / "changelog.d/README.md").write_text("# Fragments\n", encoding="utf-8")
        (root / "docs").mkdir()
        for name in ["x.md", "y.md", "space name.md"]:
            (root / "docs" / name).write_text("# Guide\n", encoding="utf-8")
        for name, text in fragments.items():
            (root / "changelog.d" / name).write_text(text, encoding="utf-8")
        return root

    def test_assembly_is_deterministic_and_keeps_existing_entries_first(self):
        fragments = {
            "fixed-b.md": "### Fixed\n\n- Fragment fix B.\n",
            "added-z.md": "### Added\n\n- Fragment add Z.\n",
            "fixed-a.md": "### Fixed\n\n- Fragment fix A.\n",
            "upgrade-x.md": "### Upgrade notes\n\n- Fragment upgrade note.\n",
            "security-y.md": "### Security\n\n- Fragment security note.\n",
        }
        root = self.tree(**fragments)
        first = assemble.run(root, check=False)
        once = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        second = assemble.run(self.tree(**fragments), check=False)
        self.assertEqual(first, second)
        self.assertEqual(
            once, assemble.assemble(CHANGELOG, assemble.load_fragments(self.tree(**fragments)))
        )
        self.assertEqual(
            once,
            """# Changelog

## [Unreleased]

### Security

- Fragment security note.

### Added

- Existing added entry.
- Fragment add Z.

### Fixed

- Existing fixed entry, hard-wrapped over
  two lines.
  **Operator-visible:** it stays as written.
- Fragment fix A.
- Fragment fix B.

### Upgrade notes

- Fragment upgrade note.

## [1.0.0] — 2026-01-01

### Added

- Released entry.
""",
        )
        self.assertEqual(sorted(p.name for p in (root / "changelog.d").iterdir()), ["README.md"])
        self.assertIn("assembled 5 changelog fragments", first)

    def test_multiline_bullet_and_links_survive_byte_for_byte(self):
        root = self.tree(**{"fixed-multi.md": MULTILINE})
        assemble.run(root, check=False)
        text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(MULTILINE[len("### Fixed\n\n") :], text)
        self.assertEqual(text.count("### Fixed"), 1)

    def test_fragment_relative_link_targets_become_root_relative(self):
        fragment = """### Fixed

- See the [guide](../docs/x.md#anchor), the
  [upstream](https://example.org/../a.md), and [below](#local-anchor).
  The path ../docs/y.md and [a label](plain text) stay as written.
"""
        root = self.tree(**{"fixed-links.md": fragment})
        assemble.run(root, check=False)
        text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(
            """- See the [guide](docs/x.md#anchor), the
  [upstream](https://example.org/../a.md), and [below](#local-anchor).
  The path ../docs/y.md and [a label](plain text) stay as written.
""",
            text,
        )
        self.assertNotIn("](../", text)

    def test_inline_code_spans_keep_their_literal_link_text(self):
        fragment = """### Fixed

- The literal `[guide](../docs/x.md)` and ``a `[b](../c.md)` d`` stay, while
  [`code` text](../docs/y.md) and a span split over `two
  lines [x](../z.md)` behave as Markdown reads them.
"""
        root = self.tree(**{"fixed-code.md": fragment})
        assemble.run(root, check=False)
        text = (root / "CHANGELOG.md").read_text(encoding="utf-8")
        self.assertIn(
            """- The literal `[guide](../docs/x.md)` and ``a `[b](../c.md)` d`` stay, while
  [`code` text](docs/y.md) and a span split over `two
  lines [x](../z.md)` behave as Markdown reads them.
""",
            text,
        )

    def test_escaped_backticks_do_not_open_a_code_span(self):
        cases = {
            # An escaped backtick is literal, so it cannot pair with a later span.
            r"\`[guide](../docs/x.md) and `code`": r"\`[guide](docs/x.md) and `code`",
            r"\\\`[guide](../docs/x.md) and `code`": r"\\\`[guide](docs/x.md) and `code`",
            # An escaped backslash leaves the following backtick run unescaped.
            r"\\`[guide](../docs/x.md)`": r"\\`[guide](../docs/x.md)`",
            r"`x`\\`[guide](../docs/x.md)`": r"`x`\\`[guide](../docs/x.md)`",
            # A backslash inside a span is literal and does not escape the closer.
            r"`C:\` [guide](../docs/x.md) `code`": r"`C:\` [guide](docs/x.md) `code`",
        }
        for fragment, expected in cases.items():
            with self.subTest(fragment=fragment):
                self.assertEqual(assemble.root_relative_links(fragment), expected)

    def test_duplicate_detection_compares_the_root_relative_link(self):
        changelog = CHANGELOG.replace(
            "- Existing fixed entry, hard-wrapped over",
            "- See [the guide](docs/x.md).\n- Existing fixed entry, hard-wrapped over",
        )
        root = self.tree(changelog, **{"fixed-dup.md": "### Fixed\n\n- See [the guide](../docs/x.md).\n"})
        with self.assertRaisesRegex(
            ValueError, r"fixed-dup.md: bullet already present in \[Unreleased\]"
        ):
            assemble.run(root, check=True)

    def test_second_assembly_with_no_fragments_changes_nothing(self):
        root = self.tree(**{"fixed-a.md": "### Fixed\n\n- Fragment fix A.\n"})
        assemble.run(root, check=False)
        once = (root / "CHANGELOG.md").read_bytes()
        self.assertEqual(assemble.run(root, check=False), "no changelog fragments to assemble")
        self.assertEqual((root / "CHANGELOG.md").read_bytes(), once)
        self.assertEqual(once.decode().count("Fragment fix A."), 1)

    def test_check_mode_validates_without_writing(self):
        root = self.tree(**{"fixed-a.md": "### Fixed\n\n- Fragment fix A.\n"})
        self.assertIn("1 changelog fragments assemble cleanly", assemble.run(root, check=True))
        self.assertEqual((root / "CHANGELOG.md").read_text(encoding="utf-8"), CHANGELOG)
        self.assertTrue((root / "changelog.d/fixed-a.md").exists())
        with self.assertRaisesRegex(ValueError, "bad.md: first line"):
            assemble.run(self.tree(**{"bad.md": "- no heading\n"}), check=True)

    def test_empty_unreleased_gains_the_subsection(self):
        changelog = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] — 2026-01-01\n\n- Old.\n"
        root = self.tree(changelog, **{"changed-a.md": "### Changed\n\n- New.\n"})
        assemble.run(root, check=False)
        self.assertEqual(
            (root / "CHANGELOG.md").read_text(encoding="utf-8"),
            "# Changelog\n\n## [Unreleased]\n\n### Changed\n\n- New.\n\n"
            "## [1.0.0] — 2026-01-01\n\n- Old.\n",
        )

    def test_malformed_fragments_are_refused_by_name(self):
        cases = {
            "bad-heading.md": ("### Bogus\n\n- Bullet.\n", "bad-heading.md: first line"),
            "trailing-space.md": ("### Fixed \n\n- Bullet.\n", "trailing-space.md: first line"),
            "no-heading.md": ("- Bullet.\n", "no-heading.md: first line"),
            "empty.md": ("### Fixed\n\n\n", "empty.md: no bullet"),
            "blank.md": ("", "blank.md: first line"),
            "prose.md": ("### Fixed\n\nNot a bullet.\n", "prose.md: body must start"),
            "star.md": ("### Fixed\n\n* Star bullet.\n", "star.md: body must start"),
            "prose-after.md": (
                "### Fixed\n\n- Bullet.\nLoose line.\n",
                "prose-after.md:3: expected a `- ` bullet",
            ),
            "conflict.md": (
                "### Fixed\n\n<<<<<<< HEAD\n- Ours.\n=======\n- Theirs.\n>>>>>>> main\n",
                "conflict.md: unresolved merge-conflict marker",
            ),
            "stray.txt": ("### Fixed\n\n- Bullet.\n", "stray.txt: not a `.md` fragment"),
        }
        for name, (text, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, message):
                assemble.load_fragments(self.tree(**{name: text}))
        root = self.tree()
        (root / "changelog.d/dir.md").mkdir()
        with self.assertRaisesRegex(ValueError, "dir.md: not a `.md` fragment"):
            assemble.load_fragments(root)

    def test_duplicate_bullet_is_refused(self):
        root = self.tree(**{"added-dup.md": "### Added\n\n- Existing added   entry.\n"})
        with self.assertRaisesRegex(
            ValueError, r"added-dup.md: bullet already present in \[Unreleased\]"
        ):
            assemble.run(root, check=True)
        root = self.tree(
            **{
                "fixed-a.md": "### Fixed\n\n- Same text.\n",
                "fixed-b.md": "### Fixed\n\n- Same text.\n",
            }
        )
        with self.assertRaisesRegex(
            ValueError, "fixed-b.md: bullet already present in changelog.d/fixed-a.md"
        ):
            assemble.run(root, check=True)
        self.assertEqual((root / "CHANGELOG.md").read_text(encoding="utf-8"), CHANGELOG)

    def test_missing_unreleased_section_is_refused(self):
        root = self.tree("# Changelog\n\n## [1.0.0] — 2026-01-01\n\n- Old.\n")
        with self.assertRaisesRegex(ValueError, r"no `## \[Unreleased\]` section"):
            assemble.run(root, check=True)

    def test_missing_fragment_directory_means_no_fragments(self):
        root = self.tree()
        (root / "changelog.d/README.md").unlink()
        (root / "changelog.d").rmdir()
        self.assertEqual(assemble.load_fragments(root), [])

    def test_new_categories_follow_the_fixed_order(self):
        root = self.tree(
            "# Changelog\n\n## [Unreleased]\n\n## [1.0.0]\n\nOld.\n",
            **{
                f"{category.lower().split()[0]}-entry.md": f"### {category}\n\n- {category} entry.\n"
                for category in reversed(assemble.CATEGORIES)
            },
        )
        fragments = assemble.load_fragments(root)
        forward = assemble.assemble((root / "CHANGELOG.md").read_text(), fragments)
        backward = assemble.assemble((root / "CHANGELOG.md").read_text(), list(reversed(fragments)))
        self.assertEqual(forward, backward)
        self.assertEqual(
            [line[4:] for line in forward.splitlines() if line.startswith("### ")],
            list(assemble.CATEGORIES),
        )

    def test_history_and_existing_unreleased_text_are_not_reformatted(self):
        head = "# Changelog\r\n\r\nKeep this preamble.\r\n\r\n## [Unreleased]\r\n"
        body = "\r\n### Fixed\r\n\r\n- Existing.  \r\n\r\n  Wrapped continuation.\r\n"
        tail = "\r\n## [0.1.0] - old\r\n\r\n### Historical category\r\n\r\nLoose historical prose.  \r\n"
        root = self.tree(**{"fixed-new.md": "### Fixed\n\n- New entry.\n"})
        (root / "CHANGELOG.md").write_bytes((head + body + tail).encode())
        assemble.run(root, check=False)
        actual = (root / "CHANGELOG.md").read_bytes().decode()
        self.assertTrue(actual.startswith(head + body.rstrip("\r\n")))
        self.assertTrue(actual.endswith(tail))
        self.assertIn("- New entry.", actual)

    def test_legacy_unreleased_categories_are_retained(self):
        changelog = CHANGELOG.replace("### Fixed", "### Historical category", 1)
        root = self.tree(changelog, **{"fixed-new.md": "### Fixed\n\n- New entry.\n"})
        assemble.run(root, check=False)
        actual = (root / "CHANGELOG.md").read_text()
        self.assertIn("### Historical category\n\n- Existing fixed entry", actual)
        self.assertIn("### Fixed\n\n- New entry.", actual)

    def test_empty_existing_category_gets_a_valid_bullet(self):
        root = self.tree(
            "# Changelog\n\n## [Unreleased]\n\n### Fixed\n\n## [1.0.0]\n",
            **{"fixed-new.md": "### Fixed\n\n- New entry.\n"},
        )
        assemble.run(root, check=False)
        self.assertIn("### Fixed\n\n- New entry.\n\n## [1.0.0]", (root / "CHANGELOG.md").read_text())

    def test_bad_filenames_and_category_mismatches_are_refused(self):
        for name in ["fixed.md", "Fixed-entry.md", "fixed_bad.md", "fixed--entry.md", "added-entry.md"]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "<category>-<slug>"):
                assemble.load_fragments(self.tree(**{name: "### Fixed\n\n- Entry.\n"}))

    def test_empty_bullets_and_second_headings_are_refused(self):
        for body in ["- \n", "- First.\n-  \n", "- First.\n  ### Added\n"]:
            with self.subTest(body=body), self.assertRaises(ValueError):
                assemble.load_fragments(self.tree(**{"fixed-bad.md": f"### Fixed\n\n{body}"}))
        with self.assertRaisesRegex(ValueError, "merge-conflict"):
            assemble.load_fragments(self.tree(**{"fixed-bad.md": "### Fixed\n\n- First.\n  <<<<<<< HEAD\n"}))

    def test_unsupported_link_styles_are_refused_but_literal_examples_are_allowed(self):
        for body in ['- [Guide][guide].\n  [guide]: ../docs/x.md\n', '- <a href="../docs/x.md">Guide</a>.\n']:
            with self.subTest(body=body), self.assertRaisesRegex(ValueError, "inline Markdown"):
                assemble.load_fragments(self.tree(**{"fixed-links.md": f"### Fixed\n\n{body}"}))
        assemble.load_fragments(self.tree(**{
            "fixed-literal.md": '### Fixed\n\n- The literal `<a href="../missing.md">` stays unchanged.\n'
        }))

    def test_duplicate_bullets_in_one_fragment_are_refused(self):
        root = self.tree(**{"fixed-twice.md": "### Fixed\n\n- Same entry.\n- Same   entry.\n"})
        with self.assertRaisesRegex(ValueError, "already present"):
            assemble.run(root, check=True)

    def test_inline_links_rebase_titles_spaces_queries_and_readme(self):
        fragment = """### Fixed

- See [guide](../docs/x.md?view=full#missing-anchor "Title"),
  [spaces](<../docs/space name.md>), [encoded](../docs/space%20name.md),
  [readme](README.md), and [upstream](https://example.invalid/never-fetched).
"""
        root = self.tree(**{"fixed-links.md": fragment})
        assemble.run(root, check=False)
        actual = (root / "CHANGELOG.md").read_text()
        for expected in [
            '](docs/x.md?view=full#missing-anchor "Title")',
            "](<docs/space name.md>)", "](docs/space%20name.md)", "](changelog.d/README.md)",
        ]:
            self.assertIn(expected, actual)

    def test_missing_and_outside_local_links_fail_without_writes(self):
        for target, error in [
            ("../docs/missing.md", "does not exist"),
            ("../../outside.md", "escapes the repository"),
            ("../%2e%2e/outside.md", "escapes the repository"),
            ("/absolute.md", "must stay relative"),
            ("file:///absolute.md", "must stay relative"),
            ("fixed-links.md", "assembly consumes"),
        ]:
            root = self.tree(**{"fixed-links.md": f"### Fixed\n\n- See [guide]({target}).\n"})
            before = (root / "CHANGELOG.md").read_bytes()
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, error):
                assemble.run(root, check=False)
            self.assertEqual((root / "CHANGELOG.md").read_bytes(), before)
            self.assertTrue((root / "changelog.d/fixed-links.md").exists())

    def test_symlinks_and_stray_entries_are_refused(self):
        for name in ["fixed-link.md", "README.md"]:
            root = self.tree()
            path = root / "changelog.d" / name
            path.unlink(missing_ok=True)
            path.symlink_to(root / "docs/x.md")
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "symlinks"):
                assemble.run(root, check=True)
        root = self.tree()
        (root / "changelog.d/README.md").unlink()
        (root / "changelog.d").rmdir()
        (root / "changelog.d").symlink_to(root / "docs", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlinks"):
            assemble.run(root, check=True)
        root = self.tree()
        (root / "CHANGELOG.md").unlink()
        (root / "CHANGELOG.md").symlink_to(root / "docs/x.md")
        with self.assertRaisesRegex(ValueError, "symlinks"):
            assemble.run(root, check=True)
        root = self.tree(**{"fixed-link.md": "### Fixed\n\n- [Guide](../docs/outside.md).\n"})
        (root / "docs/outside.md").symlink_to(root.parent)
        with self.assertRaisesRegex(ValueError, "escapes the repository"):
            assemble.run(root, check=True)

    def test_check_mode_preserves_contents_modes_and_modification_times(self):
        root = self.tree(**{"fixed-entry.md": "### Fixed\n\n- Entry.\n"})
        def snapshot():
            return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mode, p.stat().st_mtime_ns)
                    for p in root.rglob("*") if p.is_file()}
        before = snapshot()
        assemble.run(root, check=True)
        self.assertEqual(snapshot(), before)

    def test_atomic_replace_keeps_mode_and_failed_replace_keeps_fragments(self):
        root = self.tree(**{"fixed-entry.md": "### Fixed\n\n- Entry.\n"})
        changelog = root / "CHANGELOG.md"
        changelog.chmod(0o640)
        with mock.patch.object(assemble.os, "replace", side_effect=OSError("replacement failed")):
            with self.assertRaisesRegex(OSError, "replacement failed"):
                assemble.run(root, check=False)
        self.assertEqual(changelog.read_text(), CHANGELOG)
        self.assertTrue((root / "changelog.d/fixed-entry.md").exists())
        self.assertEqual(list(root.glob(".CHANGELOG.md.*")), [])
        assemble.run(root, check=False)
        self.assertEqual(changelog.stat().st_mode & 0o777, 0o640)
        self.assertFalse((root / "changelog.d/fixed-entry.md").exists())

    def test_failed_flush_keeps_changelog_and_fragments(self):
        root = self.tree(**{"fixed-entry.md": "### Fixed\n\n- Entry.\n"})
        with mock.patch.object(assemble.os, "fsync", side_effect=OSError("disk write failed")):
            with self.assertRaisesRegex(OSError, "disk write failed"):
                assemble.run(root, check=False)
        self.assertEqual((root / "CHANGELOG.md").read_text(), CHANGELOG)
        self.assertTrue((root / "changelog.d/fixed-entry.md").exists())
        self.assertEqual(list(root.glob(".CHANGELOG.md.*")), [])

    def test_fragment_changed_during_output_is_not_consumed(self):
        root = self.tree(**{"fixed-entry.md": "### Fixed\n\n- Entry.\n"})
        replace = assemble.os.replace
        def edit_then_replace(source, destination):
            (root / "changelog.d/fixed-entry.md").write_text("### Fixed\n\n- Concurrent edit.\n")
            replace(source, destination)
        with mock.patch.object(assemble.os, "replace", side_effect=edit_then_replace):
            with self.assertRaisesRegex(ValueError, "changed since validation"):
                assemble.run(root, check=False)
        self.assertIn("Concurrent edit.", (root / "changelog.d/fixed-entry.md").read_text())


if __name__ == "__main__":
    unittest.main()
