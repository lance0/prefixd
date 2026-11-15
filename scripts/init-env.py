#!/usr/bin/env python3
"""Initialize the Compose bearer token without rotating an existing credential."""

import os
import re
import secrets
import sys
import tempfile
from pathlib import Path

ASSIGNMENT = re.compile(r"^\s*(?:export\s+)?PREFIXD_API_TOKEN\s*=\s*(.*)$")
EMPTY_OR_PLACEHOLDER = re.compile(
    r"^(?:|your-secret-token-here|\"\"|''|\"your-secret-token-here\"|'your-secret-token-here')"
    r"(?:\s+#.*|\s*)$"
)


def initialize(path: Path) -> bool:
    """Return whether a token was generated. Never print credential contents."""
    if path.is_symlink():
        raise ValueError("refusing a symlink; edit the intended .env file directly")
    try:
        original = path.read_bytes()
    except FileNotFoundError:
        original = b""
    lines = original.decode("utf-8").splitlines(keepends=True)
    assignments = [(i, ASSIGNMENT.fullmatch(line.rstrip("\r\n"))) for i, line in enumerate(lines)]
    assignments = [(i, match) for i, match in assignments if match]
    if len(assignments) > 1:
        raise ValueError(
            "duplicate PREFIXD_API_TOKEN assignments; keep one intended value and retry"
        )
    if assignments and not EMPTY_OR_PLACEHOLDER.fullmatch(assignments[0][1].group(1)):
        # Leave quoting, interpolation and comments for Compose to interpret.
        # Unknown syntax must never cause a credential to be silently rotated.
        path.chmod(0o600)
        return False

    # Generate before creating a file; entropy failures must leave the old file intact.
    token = secrets.token_hex(32)
    assignment = f"PREFIXD_API_TOKEN={token}\n"
    if assignments:
        lines[assignments[0][0]] = assignment
    else:
        if lines and not lines[-1].endswith("\n"):
            lines[-1] += "\n"
        lines.append(assignment)

    # NamedTemporaryFile creates mode 0600 before any secret is written, regardless
    # of umask. A same-directory replace commits only a completely written file.
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".env-", delete=False) as output:
            temporary = Path(output.name)
            output.write("".join(lines).encode("utf-8"))
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return True


def main() -> int:
    try:
        generated = initialize(Path(".env"))
    except (OSError, ValueError) as error:
        # Avoid exception values: filesystem/decoder messages may include secrets.
        if isinstance(error, ValueError) and not isinstance(error, UnicodeError):
            print(f"Cannot initialize .env: {error}", file=sys.stderr)
        else:
            print("Cannot initialize .env: check file access and UTF-8 encoding", file=sys.stderr)
        return 1
    print(
        "Generated a token in .env (0600)." if generated else "Kept existing token in .env (0600)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
