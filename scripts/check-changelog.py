#!/usr/bin/env python3
"""Require release notes for changes that may affect operator interfaces.

Run assemble-changelog.py --check separately to validate fragment contents.
This check conservatively classifies paths; a documented internal/process-only
exception is a review decision, not automatic proof of compatibility.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SURFACE_DIRECTORIES = (
    "src/", "configs/", "migrations/", "proto/", "examples/", "docker/",
    "frontend/app/", "frontend/components/", "frontend/hooks/", "frontend/lib/",
)
SURFACE_FILES = {
    "Cargo.toml", "Cargo.lock", "build.rs", "Dockerfile", "docker-compose.yml",
    "frontend/package.json", "frontend/bun.lock", "frontend/Dockerfile",
}
EXCEPTION = re.compile(r"^Changelog:[ \t]*not needed:[ \t]*(\S[^\r\n]*)\r?$", re.I | re.M)


def no_change_reason(body: str) -> str:
    reasons = EXCEPTION.findall(body)
    if len(reasons) > 1:
        raise ValueError("provide only one Changelog: not needed reason")
    if not reasons:
        return ""
    reason = reasons[0].strip()
    if len(reason) < 15 or "<" in reason or reason.lower() in {"no visible changes", "internal refactor"}:
        raise ValueError("explain concretely why no operator interface or behavior changes")
    return reason


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=root, text=True, stderr=subprocess.PIPE)


def check(root: Path, base: str, head: str, reason: str = "") -> str:
    # Resolve separately so a supplied ref cannot become a git diff option.
    base_sha = git(root, "rev-parse", "--verify", "--end-of-options", f"{base}^{{commit}}").strip()
    head_sha = git(root, "rev-parse", "--verify", "--end-of-options", f"{head}^{{commit}}").strip()
    paths = git(root, "diff", "--no-renames", "--name-only", "-z", f"{base_sha}...{head_sha}", "--").split("\0")
    surfaces = [
        p for p in paths
        if p in SURFACE_FILES or p.startswith(SURFACE_DIRECTORIES)
        or re.fullmatch(r"(?:docker-)?compose(?:[.-].+)?\.ya?ml", p)
        or (p.startswith("scripts/") and not Path(p).name.startswith("test_"))
    ]
    if not surfaces:
        return "no interface candidate paths changed; no fragment required"
    notes = [
        p for p in paths
        if p.startswith("changelog.d/") and p.endswith(".md")
        and p != "changelog.d/README.md" and (root / p).is_file()
    ]
    if notes:
        return "release-note change: " + ", ".join(notes)
    if reason:
        return "no-change rationale requires review: " + reason
    raise ValueError(
        "add a changelog.d fragment for interface/behavior changes; otherwise explain "
        "`Changelog: not needed: <specific reason>` in the PR body. Candidate paths: "
        + ", ".join(surfaces[:5])
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="base commit or ref")
    parser.add_argument("--head", default="HEAD", help="head commit or ref")
    parser.add_argument("--event", type=Path, help="GitHub event JSON containing the PR body")
    args = parser.parse_args()
    try:
        body = ""
        if args.event:
            event = json.loads(args.event.read_text(encoding="utf-8"))
            body = (event.get("pull_request") or {}).get("body") or ""
        print(check(ROOT, args.base, args.head, no_change_reason(body)))
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"changelog contract: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
