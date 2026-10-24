#!/usr/bin/env python3
"""Allow the PR fast path only for explicit documentation paths."""

import argparse
import os
import subprocess
import tempfile
from pathlib import PurePosixPath

DOC_FILES = {
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "FEATURES.md",
    "README.md",
    "ROADMAP.md",
    "SECURITY.md",
    "lab/README.md",
    "frontend/tools/oxlint/anti-slop/UPSTREAM.md",
    "frontend/tools/oxlint/anti-slop/vendor/eslint-stylistic/UPSTREAM.md",
}
IMAGE_SUFFIXES = {".gif", ".jpeg", ".jpg", ".png", ".svg", ".webp"}


def docs_path(name):
    path = PurePosixPath(os.fsdecode(name))
    return path.as_posix() in DOC_FILES or (
        path.parts[0] == "docs"
        and (
            path.suffix == ".md"
            or (path.parts[:2] == ("docs", "images") and path.suffix in IMAGE_SUFFIXES)
        )
    )


def docs_only(base, head):
    # Disable rename detection so a source file moved into docs still counts.
    changed = subprocess.check_output(
        ["git", "diff", "--no-renames", "--name-only", "-z", f"{base}...{head}", "--"],
        stderr=subprocess.PIPE,
    ).split(b"\0")
    if changed[-1] != b"":
        raise ValueError("git diff did not terminate its path list")
    paths = changed[:-1]
    return bool(paths) and all(docs_path(path) for path in paths)


def self_test():
    from pathlib import Path

    for name, expected in [
        (b"README.md", True),
        (b"docs/adr/new.md", True),
        (b"docs/images/new.svg", True),
        (b"docs/new\nline.md", True),
        (b"lab/README.md", True),
        (b"frontend/tools/oxlint/anti-slop/UPSTREAM.md", True),
        (b"frontend/tools/oxlint/anti-slop/vendor/eslint-stylistic/UPSTREAM.md", True),
        (b"README.md\nsrc/main.rs", False),
        (b"src/main.rs", False),
        (b"docs/example.rs", False),
        (b"docs/images/script.py", False),
        (b"scripts/check.py", False),
        (b".github/workflows/ci.yml", False),
        (b"NEW.md", False),
    ]:
        assert docs_path(name) == expected, name

    with tempfile.TemporaryDirectory() as directory:

        def git(*args):
            return (
                subprocess.check_output(["git", "-C", directory, *args], stderr=subprocess.DEVNULL)
                .decode()
                .strip()
            )

        def commit():
            git("add", "-A")
            git(
                "-c",
                "user.name=Scope test",
                "-c",
                "user.email=scope@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            return git("rev-parse", "HEAD")

        git("init", "-q")
        root = Path(directory)
        (root / "README.md").write_text("base\n")
        (root / "main.rs").write_text("base\n")
        base = commit()
        (root / "README.md").write_text("docs\n")
        documentation = commit()
        git("checkout", "-qb", "diverged-base", base)
        (root / "main.rs").write_text("base-only code\n")
        newer_base = commit()
        git("checkout", "-q", documentation)
        previous = os.getcwd()
        try:
            os.chdir(directory)
            assert docs_only(newer_base, documentation), "base-only code is outside the PR diff"
            assert not docs_only(base, base), "an empty diff uses full CI"
            (root / "docs").mkdir()
            (root / "docs/new\nline.md").write_text("newline filename\n")
            assert docs_only(base, commit()), "NUL-delimited names preserve newline filenames"
            git("checkout", "-q", documentation)
            (root / "main.rs").write_text("changed\n")
            assert not docs_only(base, commit()), "mixed changes use full CI"
            git("checkout", "-q", documentation)
            (root / "docs").mkdir()
            git("mv", "main.rs", "docs/moved.md")
            assert not docs_only(base, commit()), "source-to-docs rename includes source deletion"
            git("checkout", "-q", documentation)
            git("rm", "README.md")
            assert docs_only(base, commit()), "documentation deletion stays documentation"
            try:
                docs_only("missing-ref", documentation)
            except subprocess.CalledProcessError:
                pass
            else:
                raise AssertionError("an unreadable diff must fail")
        finally:
            os.chdir(previous)
    print("Documentation scope self-test passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("base", nargs="?")
    parser.add_argument("head", nargs="?")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
    elif args.base and args.head:
        print(str(docs_only(args.base, args.head)).lower())
    else:
        parser.error("provide base and head commits, or --self-test")


if __name__ == "__main__":
    main()
