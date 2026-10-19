#!/usr/bin/env python3
"""Print one CHANGELOG.md release section as a GitHub release body.

Usage:
  scripts/release-notes.py X.Y.Z [CHANGELOG.md]
  scripts/release-notes.py --tag-info vX.Y.Z
  scripts/release-notes.py --selftest

Fails unless CHANGELOG.md has a dated, nonempty `## [X.Y.Z] - YYYY-MM-DD`
section. The heading line is dropped because the release page shows the
version; a summary paragraph before the first `###` group is kept.

--tag-info reads the local tag list and prints two GITHUB_OUTPUT lines:
`previous=` the newest final release tag older than vX.Y.Z (empty when there
is none), and `latest=true` when vX.Y.Z is a final release with no newer final
tag, so a backported patch never takes over releases/latest.

CHANGELOG.md is hard-wrapped, but GitHub renders every newline in a release
body as a line break. Each paragraph and list item is joined onto one line;
blank lines, headings, fenced code, tables, blockquotes and list-item
boundaries (including nesting) stay as they are.
"""

from __future__ import annotations

import re
import subprocess
import sys

HEADING = re.compile(r"^#{1,6}\s")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
VERBATIM = re.compile(r"^\s*[|>]")
TAG = re.compile(r"v(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?")


class NotesError(Exception):
    pass


def extract(changelog: str, version: str) -> str:
    lines = changelog.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.startswith(f"## [{version}]"):
            if not re.fullmatch(rf"## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}", line.rstrip()):
                raise NotesError(f"heading must read '## [{version}] - YYYY-MM-DD': {line!r}")
            start = i + 1
            break
    if start is None:
        raise NotesError(f"no '## [{version}]' section in CHANGELOG.md")
    body = []
    for line in lines[start:]:
        if line.startswith("## "):
            break
        body.append(line)
    text = "\n".join(body).strip("\n")
    if not text.strip():
        raise NotesError(f"'## [{version}]' section is empty")
    return text + "\n"


def reflow(text: str) -> str:
    out: list[str] = []
    buf: str | None = None
    fence = ""

    def flush() -> None:
        nonlocal buf
        if buf is not None:
            out.append(buf)
            buf = None

    for line in text.split("\n"):
        if fence:
            out.append(line)
            close = FENCE.match(line)
            if close and close.group(1)[0] == fence[0] and line.strip() == close.group(1):
                fence = ""
            continue
        opening = FENCE.match(line)
        if opening:
            flush()
            fence = opening.group(1)
            out.append(line)
        elif not line.strip() or HEADING.match(line) or VERBATIM.match(line):
            flush()
            out.append(line.rstrip())
        elif LIST_ITEM.match(line) or buf is None:
            flush()
            buf = line.rstrip()
        else:
            buf = f"{buf} {line.strip()}"
    flush()
    return "\n".join(out)


def notes(changelog: str, version: str) -> str:
    return reflow(extract(changelog, version))


def tag_info(tag: str, tags: list[str]) -> tuple[str, bool]:
    """Return (newest final tag older than tag, whether tag becomes latest)."""
    m = TAG.fullmatch(tag)
    if not m:
        raise NotesError(f"tag {tag!r} is not vX.Y.Z")
    base = tuple(int(n) for n in m.groups()[:3])
    finals = sorted(
        tuple(int(n) for n in f.groups()[:3])
        for f in map(TAG.fullmatch, tags)
        if f and f.group(4) is None
    )
    older = [f for f in finals if f < base]
    previous = "v%d.%d.%d" % older[-1] if older else ""
    latest = m.group(4) is None and all(f <= base for f in finals)
    return previous, latest


def selftest() -> None:
    changelog = """# Changelog

## [Unreleased]

### Added

- Not released yet.

## [1.2.0] - 2026-10-18

A short summary
before the groups.

### Security

- Reject a thing
  across two lines.
  - Nested item
    continues here.

A paragraph
wrapped twice.

```text
keep
  this
```

| a | b |
| - | - |

> quoted
> lines

## [1.1.0] - 2026-01-01

- Older entry.
"""
    want = """A short summary before the groups.

### Security

- Reject a thing across two lines.
  - Nested item continues here.

A paragraph wrapped twice.

```text
keep
  this
```

| a | b |
| - | - |

> quoted
> lines
"""
    got = notes(changelog, "1.2.0")
    assert got == want, f"reflow mismatch:\n{got}"
    assert notes(changelog, "1.1.0") == "- Older entry.\n"
    for bad, version in [
        (changelog, "9.9.9"),
        ("## [2.0.0]\n\n- x\n", "2.0.0"),
        ("## [2.0.0] - 2026-10-18\n\n## [1.0.0] - 2026-01-01\n", "2.0.0"),
        ("## [Unreleased]\n\n- x\n", "Unreleased"),
    ]:
        try:
            notes(bad, version)
        except NotesError:
            continue
        raise AssertionError(f"expected failure for {version!r}")
    # A version must not match by prefix: 1.2.0 must not select 1.2.0-rc.1.
    try:
        notes("## [1.2.0-rc.1] - 2026-10-01\n\n- rc\n", "1.2.0")
    except NotesError:
        pass
    else:
        raise AssertionError("prefix match selected a prerelease section")
    tags = ["v0.9.9", "v0.19.0", "v0.19.1", "v0.20.0-rc.1", "v0.20.0", "v0.21.0-rc.1", "x1"]
    assert tag_info("v0.20.0", tags) == ("v0.19.1", True)
    assert tag_info("v0.20.1", tags) == ("v0.20.0", True)
    assert tag_info("v0.21.0-rc.2", tags) == ("v0.20.0", False)
    assert tag_info("v0.21.0", tags) == ("v0.20.0", True)
    assert tag_info("v0.19.2", tags) == ("v0.19.1", False)  # backport
    assert tag_info("v0.10.0", tags) == ("v0.9.9", False)  # numeric, not lexical
    assert tag_info("v0.1.0", []) == ("", True)
    try:
        tag_info("0.20.0", tags)
    except NotesError:
        pass
    else:
        raise AssertionError("accepted a tag without the leading v")
    print("release-notes selftest: ok")


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        selftest()
        return 0
    if len(argv) == 2 and argv[0] == "--tag-info":
        tags = subprocess.run(["git", "tag", "--list", "v*"], check=True, capture_output=True, text=True)
        try:
            previous, latest = tag_info(argv[1], tags.stdout.split())
        except NotesError as e:
            print(f"::error::{e}", file=sys.stderr)
            return 1
        print(f"previous={previous}\nlatest={str(latest).lower()}")
        return 0
    if len(argv) not in (1, 2):
        print(__doc__, file=sys.stderr)
        return 2
    path = argv[1] if len(argv) == 2 else "CHANGELOG.md"
    with open(path, encoding="utf-8") as f:
        changelog = f.read()
    try:
        sys.stdout.write(notes(changelog, argv[0]))
    except NotesError as e:
        print(f"::error file={path}::{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
