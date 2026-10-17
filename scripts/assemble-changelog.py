#!/usr/bin/env python3
"""Merge the per-change fragments under `changelog.d/` into `CHANGELOG.md`.

Every pull request that changes something user-visible adds one Markdown file
to `changelog.d/` instead of editing the `[Unreleased]` section, so concurrent
branches never conflict on the changelog. Release preparation runs this script
once: the fragments are grouped by category in the changelog's fixed category
order, sorted by file name inside a category, appended after the entries the
`[Unreleased]` section already holds, and deleted. The result is an ordinary
reviewed `[Unreleased]` section, which release preparation then rolls into a
versioned release section.

A fragment is `### <Category>` on its first line, then one or more `- ` bullets
in the changelog's hard-wrapped style; continuation lines are indented by two
spaces. Inline links are rebased from `changelog.d/` to the root `CHANGELOG.md`;
literal inline code is unchanged. Local targets must exist inside the
repository. `changelog.d/README.md` documents the format.

The script refuses, naming the file, a fragment whose first line is not a known
category, an empty fragment, a body line that is neither a bullet, a
continuation, nor blank, an unresolved merge-conflict marker, a stray file that
is not a `.md` fragment, and a bullet already present in `[Unreleased]` or in
another fragment. `--check` validates and assembles in memory without writing.
Assembly atomically replaces the changelog, preserves its mode, then removes
the validated fragments. With no fragments present the script changes nothing.

Usage:
  python3 scripts/assemble-changelog.py            # merge and delete fragments
  python3 scripts/assemble-changelog.py --check    # validate only
"""

from __future__ import annotations

import argparse
import os
import posixpath
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import NamedTuple
from urllib.parse import unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
FRAGMENT_DIR = "changelog.d"
README = "README.md"
CHANGELOG = "CHANGELOG.md"
UNRELEASED = "Unreleased"
# The subsection order of a release section in CHANGELOG.md.
CATEGORIES = (
    "Security",
    "Added",
    "Changed",
    "Removed",
    "Fixed",
    "Documentation",
    "Upgrade notes",
)
SECTION = re.compile(r"(?m)^## \[[^\]\n]+\][^\n]*$")
SUBSECTION = re.compile(r"(?m)^### [^\n]*$")
CONFLICT_MARKER = re.compile(r"(?m)^[ \t]*(?:<{7}|={7}|>{7}|\|{7})(?:\s|$)")
FILENAME = re.compile(
    r"(?P<category>security|added|changed|removed|fixed|documentation|upgrade)"
    r"-[a-z0-9]+(?:-[a-z0-9]+)*\.md\Z"
)
# An inline link or a code span (a backtick run closed by an equal run), whose literal
# text is kept. The opening run must not be backslash-escaped, so any even run
# of backslashes before it is consumed; inside a span a backslash is literal.
# This covers inline links in the fragment's restricted prose format.
FRAGMENT_LINK = re.compile(
    r"(?s)(?<!\\)(?:\\\\)*(?<!`)(?P<tick>`+)(?!`).*?(?<!`)(?P=tick)(?!`)"
    r"|\]\((?P<target><[^>\n]+>|[^\s()<>]+)"
    r"(?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'))?[ \t]*\)"
)


class Fragment(NamedTuple):
    name: str
    category: str
    body: str  # the bullets, without surrounding blank lines, newline-terminated
    source: str  # reject edits made after validation before consuming the file


def parse_fragment(name: str, text: str) -> Fragment:
    source = text
    text = text.replace("\r\n", "\n")
    if CONFLICT_MARKER.search(text):
        raise ValueError(f"{name}: unresolved merge-conflict marker")
    lines = text.split("\n")
    heading = lines[0].rstrip("\r")
    category = heading[4:] if heading.startswith("### ") else None
    if category not in CATEGORIES:
        raise ValueError(
            f"{name}: first line must be one of "
            + ", ".join(f"`### {c}`" for c in CATEGORIES)
            + f", got {heading!r}"
        )
    body = "\n".join(lines[1:]).strip("\n")
    if not body.strip():
        raise ValueError(f"{name}: no bullet under `{heading}`")
    if not body.startswith("- "):
        raise ValueError(f"{name}: body must start with a `- ` bullet")
    for number, line in enumerate(body.split("\n"), start=2):
        if line.startswith("- ") and not line[2:].strip():
            raise ValueError(f"{name}:{number}: empty bullet")
        if re.match(r"\s*#{1,6} ", line):
            raise ValueError(f"{name}:{number}: only one category heading is allowed")
        if line.strip() and not (line.startswith("- ") or line.startswith("  ")):
            raise ValueError(
                f"{name}:{number}: expected a `- ` bullet or an indented "
                f"continuation line, got {line!r}"
            )
    filename = FILENAME.fullmatch(Path(name).name)
    if filename is None or filename["category"] != category.lower().split()[0]:
        raise ValueError(f"{name}: expected lowercase <category>-<slug>.md matching the heading")
    if "](" in FRAGMENT_LINK.sub("", body):
        raise ValueError(
            f"{name}: unsupported inline link; put destinations containing spaces or "
            "parentheses in angle brackets, and literal examples in inline code"
        )
    prose = FRAGMENT_LINK.sub(lambda match: "" if match["tick"] else match.group(), body)
    if re.search(r"(?im)^ {0,3}\[[^\]\n]+\]:|<[^>\n]+\b(?:href|src)\s*=", prose):
        raise ValueError(f"{name}: use inline Markdown links, not reference definitions or HTML links")
    return Fragment(name, category, root_relative_links(body) + "\n", source)


def root_relative_links(body: str) -> str:
    """Rebase fragment-relative inline links without changing literal code spans."""
    def rewrite(match: re.Match[str]) -> str:
        if match["tick"]:
            return match.group()
        target = match["target"]
        url = urlsplit(target.strip("<>"))
        if url.scheme or url.netloc or not url.path or url.path.startswith("/"):
            return match.group()
        path = posixpath.normpath(f"{FRAGMENT_DIR}/{url.path}")
        rebased = urlunsplit(("", "", path, url.query, url.fragment))
        if target.startswith("<"):
            rebased = f"<{rebased}>"
        start, end = match.span("target")
        return (
            match.group()[: start - match.start()]
            + rebased
            + match.group()[end - match.start() :]
        )

    return FRAGMENT_LINK.sub(rewrite, body)


def validate_links(root: Path, fragment: Fragment) -> None:
    """Check local inline-link targets; URLs and heading anchors stay unchecked."""
    for match in FRAGMENT_LINK.finditer(fragment.body):
        if match["tick"]:
            continue
        target = match["target"].strip("<>")
        url = urlsplit(target)
        if url.scheme == "file" or (url.path.startswith("/") and not url.netloc):
            raise ValueError(f"{fragment.name}: link must stay relative to the repository: {target!r}")
        if url.scheme or url.netloc or not url.path:
            continue
        destination = (root / unquote(url.path)).resolve()
        if not destination.is_relative_to(root.resolve()):
            raise ValueError(f"{fragment.name}: link escapes the repository: {target!r}")
        if not destination.exists():
            raise ValueError(f"{fragment.name}: local link target does not exist: {target!r}")
        if destination.parent == (root / FRAGMENT_DIR).resolve() and destination.name != README:
            raise ValueError(f"{fragment.name}: link targets a fragment that assembly consumes: {target!r}")


def load_fragments(root: Path) -> list[Fragment]:
    """Return every fragment under `changelog.d/`, sorted by file name."""
    directory = root / FRAGMENT_DIR
    if directory.is_symlink():
        raise ValueError(f"{FRAGMENT_DIR}: symlinks are not allowed")
    if directory.exists() and not directory.is_dir():
        raise ValueError(f"{FRAGMENT_DIR}: not a directory")
    if not directory.is_dir():
        return []
    fragments = []
    for path in sorted(directory.iterdir()):
        if path.is_symlink():
            raise ValueError(f"{FRAGMENT_DIR}/{path.name}: symlinks are not allowed")
        if path.name == README:
            if not path.is_file():
                raise ValueError(f"{FRAGMENT_DIR}/{README}: not a regular file")
            continue
        if path.suffix != ".md" or not path.is_file():
            raise ValueError(f"{FRAGMENT_DIR}/{path.name}: not a `.md` fragment")
        fragment = parse_fragment(f"{FRAGMENT_DIR}/{path.name}", path.read_bytes().decode("utf-8"))
        validate_links(root, fragment)
        fragments.append(fragment)
    return fragments


def bullets(body: str) -> list[str]:
    """Split a subsection body into whitespace-normalized bullets."""
    found: list[list[str]] = []
    for line in body.split("\n"):
        if line.startswith("- "):
            found.append([line])
        elif found and line.strip():
            found[-1].append(line)
    return [" ".join(" ".join(item).split()) for item in found]


def split_unreleased(changelog: str) -> tuple[str, str, str]:
    """Return (text through the heading line, section body, rest of the file)."""
    heading = re.search(rf"(?m)^## \[{UNRELEASED}\][^\n]*\n", changelog)
    if heading is None:
        raise ValueError(f"{CHANGELOG}: no `## [{UNRELEASED}]` section")
    rest = changelog[heading.end() :]
    following = SECTION.search(rest)
    end = len(rest) if following is None else following.start()
    return changelog[: heading.end()], rest[:end], rest[end:]


def subsections(body: str) -> tuple[str, list[tuple[str, str]]]:
    """Split a section body into its preamble and `(category, bullets)` pairs."""
    matches = list(SUBSECTION.finditer(body))
    preamble = body[: matches[0].start()] if matches else body
    parts = []
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        parts.append((match.group()[4:].rstrip(), body[match.end() : end].strip("\n")))
    return preamble.strip("\n"), parts


def assemble(changelog: str, fragments: list[Fragment]) -> str:
    """Return the changelog with the fragments merged into `[Unreleased]`."""
    head, body, tail = split_unreleased(changelog)
    if not fragments:
        return changelog
    fragments = sorted(fragments, key=lambda fragment: fragment.name)
    _, parts = subsections(body)
    seen: dict[str, str] = {}
    for category, text in parts:
        for bullet in bullets(text):
            seen.setdefault(bullet, f"[{UNRELEASED}] `### {category}`")
    for fragment in fragments:
        for bullet in bullets(fragment.body):
            if bullet in seen:
                raise ValueError(
                    f"{fragment.name}: bullet already present in {seen[bullet]}: {bullet[:60]!r}"
                )
            seen[bullet] = fragment.name
    for category in CATEGORIES:
        addition = "".join(f.body for f in fragments if f.category == category)
        if not addition:
            continue
        matches = list(SUBSECTION.finditer(body))
        for index, match in enumerate(matches):
            if match.group()[4:].rstrip() == category:
                end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
                position = len(body[:end].rstrip("\r\n"))
                separator = "\n" if body[match.end() : end].strip() else "\n\n"
                body = body[:position] + separator + addition.rstrip("\n") + body[position:]
                break
        else:
            rank = CATEGORIES.index(category)
            position = next(
                (
                    match.start()
                    for match in matches
                    if (existing := match.group()[4:].rstrip()) in CATEGORIES
                    and CATEGORIES.index(existing) > rank
                ),
                len(body),
            )
            prefix = body[:position]
            separator = "" if prefix.endswith("\n") else "\n"
            if prefix.strip() and not prefix.endswith("\n\n"):
                separator += "\n"
            body = body[:position] + separator + f"### {category}\n\n{addition}\n" + body[position:]
    return head + body + tail


def unchanged_fragments(root: Path, fragments: list[Fragment]) -> None:
    for fragment in fragments:
        path = root / fragment.name
        if path.is_symlink() or path.read_bytes().decode("utf-8") != fragment.source:
            raise ValueError(f"{fragment.name}: changed since validation; fragment not consumed")


def atomic_write(path: Path, text: str) -> None:
    """Replace the changelog only after a complete, flushed temporary write."""
    mode = stat.S_IMODE(path.stat().st_mode)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", delete=False,
        ) as output:
            temporary = Path(output.name)
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run(root: Path, check: bool) -> str:
    fragments = load_fragments(root)
    changelog_path = root / CHANGELOG
    if changelog_path.is_symlink():
        raise ValueError(f"{CHANGELOG}: symlinks are not allowed")
    assembled = assemble(changelog_path.read_bytes().decode("utf-8"), fragments)
    if not fragments:
        return "no changelog fragments to assemble"
    counts = ", ".join(
        f"{c}: {n}" for c in CATEGORIES if (n := sum(f.category == c for f in fragments))
    )
    if check:
        return f"{len(fragments)} changelog fragments assemble cleanly ({counts})"
    unchanged_fragments(root, fragments)
    atomic_write(changelog_path, assembled)
    unchanged_fragments(root, fragments)
    for fragment in fragments:
        (root / fragment.name).unlink()
    return f"assembled {len(fragments)} changelog fragments into [{UNRELEASED}] ({counts})"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="validate without writing")
    parser.add_argument("--root", type=Path, default=ROOT, help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        print(f"changelog fragments: {run(args.root, args.check)}")
    except (OSError, ValueError) as error:
        print(f"changelog fragments: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
