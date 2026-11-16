#!/usr/bin/env python3
"""Offline regressions for safe Compose token initialization."""

import importlib.util
import os
import re
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("init_env", Path(__file__).with_name("init-env.py"))
INIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INIT)


class InitializeEnv(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / ".env"

    def test_fresh_token_and_idempotence(self):
        self.assertTrue(INIT.initialize(self.path))
        first = self.path.read_bytes()
        self.assertRegex(first.decode(), r"^PREFIXD_API_TOKEN=[0-9a-f]{64}\n$")
        self.assertFalse(INIT.initialize(self.path))
        self.assertEqual(self.path.read_bytes(), first)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_existing_tokens_preserved_verbatim(self):
        for value in (
            "secret",
            '"secret" # comment',
            "'secret'",
            "${EXTERNAL_TOKEN}",
            "your-secret-token-here#suffix",
            '"',
        ):
            with self.subTest(value=value):
                original = f"POSTGRES_PASSWORD=other\n export PREFIXD_API_TOKEN = {value}\n"
                self.path.write_text(original)
                with patch.object(INIT.secrets, "token_hex", side_effect=AssertionError("rotated")):
                    self.assertFalse(INIT.initialize(self.path))
                self.assertEqual(self.path.read_text(), original)

    def test_empty_and_placeholder_values(self):
        for value in (
            "",
            '""',
            "'' # comment",
            "your-secret-token-here",
            '"your-secret-token-here"',
        ):
            with self.subTest(value=value):
                self.path.write_text(f"# Keep this\nPREFIXD_API_TOKEN={value}\nOTHER=keep\n")
                self.assertTrue(INIT.initialize(self.path))
                self.assertRegex(
                    self.path.read_text(),
                    r"^# Keep this\nPREFIXD_API_TOKEN=[0-9a-f]{64}\nOTHER=keep\n$",
                )

    def test_commented_empty_values_are_initialized(self):
        for value in (" # generate a token", "\t# generate a token", "   ", '  "" # empty'):
            with self.subTest(value=value):
                self.path.write_text(f"PREFIXD_API_TOKEN={value}\nOTHER=keep\n")
                self.assertTrue(INIT.initialize(self.path))
                self.assertRegex(
                    self.path.read_text(), r"^PREFIXD_API_TOKEN=[0-9a-f]{64}\nOTHER=keep\n$"
                )

    def test_literal_hash_tokens_are_not_rotated(self):
        for value in ("#literal", "#literal # comment", "'#literal'", ' "#literal" # comment'):
            with self.subTest(value=value):
                original = f"PREFIXD_API_TOKEN={value}\n"
                self.path.write_text(original)
                with patch.object(INIT.secrets, "token_hex", side_effect=AssertionError("rotated")):
                    self.assertFalse(INIT.initialize(self.path))
                self.assertEqual(self.path.read_text(), original)

    def test_append_preserves_variables_without_final_newline(self):
        self.path.write_bytes(b"OTHER=keep")
        INIT.initialize(self.path)
        self.assertTrue(self.path.read_bytes().startswith(b"OTHER=keep\nPREFIXD_API_TOKEN="))

    def test_duplicates_are_rejected_without_changes(self):
        original = b"PREFIXD_API_TOKEN=first\nexport PREFIXD_API_TOKEN='second'\n"
        self.path.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            INIT.initialize(self.path)
        self.assertEqual(self.path.read_bytes(), original)

    def test_generation_and_replace_failures_preserve_file(self):
        original = b"OTHER=keep\nPREFIXD_API_TOKEN=\n"
        for target, method in (
            (INIT.secrets, "token_hex"),
            (INIT.os, "fsync"),
            (INIT.os, "replace"),
        ):
            self.path.write_bytes(original)
            with (
                patch.object(target, method, side_effect=OSError("failure")),
                self.assertRaises(OSError),
            ):
                INIT.initialize(self.path)
            self.assertEqual(self.path.read_bytes(), original)
            self.assertEqual(list(self.path.parent.iterdir()), [self.path])

    def test_read_failure_does_not_initialize(self):
        with (
            patch.object(Path, "read_bytes", side_effect=PermissionError("denied")),
            self.assertRaises(PermissionError),
        ):
            INIT.initialize(self.path)
        self.assertFalse(self.path.exists())

    def test_generation_failure_does_not_create_file(self):
        with (
            patch.object(INIT.secrets, "token_hex", side_effect=OSError("entropy unavailable")),
            self.assertRaises(OSError),
        ):
            INIT.initialize(self.path)
        self.assertEqual(list(self.path.parent.iterdir()), [])

    def test_private_before_replace_even_with_permissive_umask(self):
        replace = os.replace

        def check_private(source, destination):
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o600)
            self.assertTrue(re.fullmatch(rb"PREFIXD_API_TOKEN=[0-9a-f]{64}\n", source.read_bytes()))
            replace(source, destination)

        previous = os.umask(0)
        try:
            with patch.object(INIT.os, "replace", side_effect=check_private):
                INIT.initialize(self.path)
        finally:
            os.umask(previous)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_symlink_and_invalid_encoding_are_not_overwritten(self):
        target = self.path.with_name("target")
        target.write_bytes(b"PREFIXD_API_TOKEN=keep\n")
        self.path.symlink_to(target)
        with self.assertRaisesRegex(ValueError, "symlink"):
            INIT.initialize(self.path)
        self.assertEqual(target.read_bytes(), b"PREFIXD_API_TOKEN=keep\n")
        self.path.unlink()
        self.path.write_bytes(b"\xff")
        with self.assertRaises(UnicodeError):
            INIT.initialize(self.path)
        self.assertEqual(self.path.read_bytes(), b"\xff")


if __name__ == "__main__":
    unittest.main()
