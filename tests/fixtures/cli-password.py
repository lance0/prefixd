"""Exercise the real operator CLI through a controlling terminal on Linux."""

import errno
import os
import pty
import select
import signal
import subprocess
import sys
import termios
import time


def interactive(username, steps, expected):
    pid, terminal = pty.fork()
    if pid == 0:
        settings = termios.tcgetattr(0)
        settings[3] |= termios.ECHO | termios.ICANON | termios.ISIG
        termios.tcsetattr(0, termios.TCSANOW, settings)
        os.execv(sys.argv[1], [sys.argv[1], "operators", "create", "--username", username])

    output = bytearray()
    finished = 0
    eof = False
    sent = 0
    consumed = 0
    deadline = time.monotonic() + 15
    try:
        while time.monotonic() < deadline:
            if select.select([terminal], [], [], 0.05)[0]:
                try:
                    chunk = os.read(terminal, 4096)
                    output.extend(chunk)
                    eof = not chunk
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    eof = True
            if sent < len(steps) and steps[sent][0] in output[consumed:]:
                # The prompt can precede the terminal-mode change by a few instructions.
                echo_deadline = time.monotonic() + 2
                while termios.tcgetattr(terminal)[3] & termios.ECHO:
                    assert time.monotonic() < echo_deadline, (
                        "password input leaves terminal echo enabled"
                    )
                    time.sleep(0.01)
                os.write(terminal, steps[sent][1])
                consumed = len(output)
                sent += 1
                if sent == len(steps):
                    # Exercise child exit before its final PTY output is consumed.
                    while not os.waitid(os.P_PID, pid, os.WEXITED | os.WNOWAIT | os.WNOHANG):
                        assert time.monotonic() < deadline, (
                            "child did not exit before the capture deadline"
                        )
                        time.sleep(0.001)
            if not finished:
                finished, status = os.waitpid(pid, os.WNOHANG)
            if finished and eof:
                break
        else:
            raise AssertionError("password command timed out")

        assert sent == len(steps), f"{username}: password flow ended before all prompts"
        exit_code = os.waitstatus_to_exitcode(status)
        assert exit_code == expected, "unexpected command exit status"
        terminal_flags = termios.ECHO | termios.ICANON | termios.ISIG
        assert termios.tcgetattr(terminal)[3] & terminal_flags == terminal_flags, (
            "terminal mode was not restored"
        )
        for _, answer in steps:
            secret = answer.strip()
            if secret and secret not in (b"\x03", b"\x04"):
                assert secret not in output, "password appeared in terminal output"
        if username == "pty-empty":
            assert b"password cannot be empty" in output, "blank password was not rejected"
    finally:
        if not finished:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        os.close(terminal)


interactive(
    "pty-admin",
    [(b"Password:", b"  pty-test-password  \n"), (b"Confirmation:", b"  pty-test-password  \n")],
    0,
)
interactive(
    "pty-corrected",
    [
        (b"Password:", b"mistyped-first-secret\n"),
        (b"Confirmation:", b"different-confirmation-secret\n"),
        (b"The answers don't match.", b"pty-test-password\n"),
        (b"Confirmation:", b"pty-test-password\n"),
    ],
    0,
)
interactive("pty-empty", [(b"Password:", b"\n"), (b"Confirmation:", b"\n")], 1)
interactive("pty-interrupt", [(b"Password:", b"\x03")], 1)
interactive("pty-eof", [(b"Password:", b"\x04")], 1)
interactive(
    "pty-confirm-interrupt",
    [(b"Password:", b"cancelled-password\n"), (b"Confirmation:", b"\x03")],
    1,
)
interactive(
    "pty-confirm-eof",
    [
        (b"Password:", b"eof-password\n"),
        (b"Confirmation:", b"\x04"),
        # Ctrl-D clears the confirmation line; the first prompt stays rendered.
        (b"\x1b[2K", b"\x03"),
    ],
    1,
)
interactive(
    "pty-mismatch-cancel",
    [
        (b"Password:", b"unconfirmed-first-secret\n"),
        (b"Confirmation:", b"unconfirmed-other-secret\n"),
        (b"The answers don't match.", b"\x03"),
    ],
    1,
)
result = subprocess.run(
    [sys.argv[1], "operators", "create", "--username", "pty-no-terminal"],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    start_new_session=True,
    timeout=15,
)
assert result.returncode != 0, "password prompt succeeded without a terminal"
assert b"failed to read password" in result.stderr, "missing terminal did not fail explicitly"
result = subprocess.run(
    [
        sys.argv[1],
        "operators",
        "create",
        "--username",
        "pty-explicit",
        "--password",
        "pty-test-password",
    ],
    stdin=subprocess.DEVNULL,
    capture_output=True,
    start_new_session=True,
    timeout=15,
)
assert result.returncode == 0, "explicit password failed without a terminal"

assert b"pty-test-password" not in result.stdout + result.stderr, "explicit password leaked"
