# Changelog fragments

Add a fragment for each change to an operator-visible
[compatibility surface](../docs/reference/stability.md), instead of editing
`[Unreleased]` in [CHANGELOG.md](../CHANGELOG.md). This lets concurrent pull
requests carry their own release notes. A process-only or internal change may
omit a fragment with an explicit reviewed explanation; do not add an empty note.

## Format

Name files `<category>-<descriptive-slug>.md` in lowercase, for example
`fixed-withdrawal-retry.md`. Use letters, numbers and single hyphens. The filename
prefix must match its heading:

| Prefix | Heading |
| --- | --- |
| `security` | `### Security` |
| `added` | `### Added` |
| `changed` | `### Changed` |
| `removed` | `### Removed` |
| `fixed` | `### Fixed` |
| `documentation` | `### Documentation` |
| `upgrade` | `### Upgrade notes` |

Each file has exactly one category heading and one or more `- ` bullets. Indent
continuation lines by two spaces; blank lines may separate paragraphs. Write
UTF-8 Markdown, preferably with LF line endings.

```markdown
### Fixed

- Keep failed withdrawals retryable and explain their pending state in the
  [operator guide](../docs/reference/speaker-backends.md).
  **Operator-visible:** a failed request no longer reports successful removal.
```

Explain the resulting behavior and any upgrade action. Use descriptive names
and public issue or pull-request references; keep private tracker identifiers,
machine names and user paths out of public notes. Only fragments and this README
belong in this directory. Symlinks and subdirectories are rejected.

## Check a pull request

Run from the repository root:

```sh
python3 scripts/assemble-changelog.py --check
python3 scripts/test_assemble_changelog.py
```

`--check` validates every fragment present, including untracked files, and
assembles the result in memory. It writes nothing and consumes nothing. It
rejects invalid filenames or headings, empty bullets, malformed body lines,
merge conflicts and duplicate bullets within a fragment, across fragments or
against existing `[Unreleased]` entries. Whitespace differences do not hide a
duplicate. Existing changelog entries and historical formatting are retained;
the stricter fragment format is not applied retroactively.

Use inline Markdown links, with an optional quoted title. Destinations containing
spaces or parentheses require angle brackets, for example
`[guide](<../docs/guide(v1).md>)`; escaped parentheses are unsupported. Put literal
link examples in inline code. Unrecognized `](` syntax, reference definitions
and HTML links are rejected. Relative targets resolve from this directory:
write `../docs/...`, not `docs/...`. The assembler rebases them for the root
changelog, leaving literal inline code unchanged. It checks that local targets
exist inside the repository and rejects links to fragments that assembly will
remove. External URLs and heading anchors are not checked; no network is used.

## Prepare a release

On the release branch, assemble the reviewed notes:

```sh
python3 scripts/assemble-changelog.py
python3 scripts/assemble-changelog.py --check
git diff -- CHANGELOG.md changelog.d/
```

The assembler appends notes after existing entries, in the category order above
and filename order within each category. It preserves existing section names,
entries and released history. It writes a complete temporary changelog, flushes
it and atomically replaces `CHANGELOG.md` while preserving its permissions.
Only then does it remove the validated fragments. A failed output write leaves
the original changelog and fragments intact. With no fragments, rerunning it
changes nothing.

Review and commit the assembled changelog and fragment deletions before turning
`[Unreleased]` into the release section. If interrupted between replacement and
fragment removal, inspect the output before removing already-assembled notes;
duplicate detection prevents silently appending them twice.
