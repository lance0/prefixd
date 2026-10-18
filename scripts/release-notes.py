#!/usr/bin/env python3
"""Print one CHANGELOG.md release section as a GitHub release body.

Usage:
  scripts/release-notes.py X.Y.Z [CHANGELOG.md]
  scripts/release-notes.py --selftest

Fails unless CHANGELOG.md has a dated, nonempty `## [X.Y.Z] - YYYY-MM-DD`
section. The heading line is dropped because the release page shows the
version.

CHANGELOG.md is hard-wrapped, but GitHub renders every newline in a release
body as a line break. Each paragraph and list item is joined onto one line;
blank lines, headings, fenced code, tables, blockquotes and list-item
boundaries (including nesting) stay as they are.
"""

from __future__ import annotations

import re
import sys

HEADING = re.compile(r"^#{1,6}\s")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+\S")
FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
VERBATIM = re.compile(r"^\s*[|>]")


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


def selftest() -> None:
    changelog = """# Changelog

## [Unreleased]

### Added

- Not released yet.

## [1.2.0] - 2026-10-18

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
    want = """### Security

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
    print("release-notes selftest: ok")


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        selftest()
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
