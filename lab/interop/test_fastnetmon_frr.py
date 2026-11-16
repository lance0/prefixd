#!/usr/bin/env python3
"""Negative controls for the FastNetMon lane's script-log and NetFlow helpers.

Runs without a lab: python3 -m unittest discover -s lab/interop -p 'test_*.py'
The log lines are prefixd-fastnetmon.sh output from a 2026-11-16 lane run.
"""

import io
import json
import os
import socket
import subprocess
import tempfile
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from fastnetmon_frr import (
    CONF,
    FastNetMonLab,
    ban_outcome,
    ban_time,
    check_udp_flood_coverage,
    messages,
    police,
    unban_outcome,
)
from netflow_v5 import HEADER, RECORD, RECORDS, datagram

MID = "a55fc086-8db5-495a-8021-2867853142ca"
SENT = (
    "Sending ban for 203.0.113.10 (unknown, 0 pps, event_id=ee1081e6-7b80-4b05-8cda-b78d7a1e195c)"
)
ACCEPTED = f'SUCCESS (202, status=accepted): {{"status":"accepted","mitigation_id":"{MID}"}}'
RETRY = "Ban for 203.0.113.10 not accepted (curl=7, http=000), attempt 1/3; retrying in 1s"
UNBAN = (
    "Sending unban for 203.0.113.10 (unknown, 0 pps, event_id=7d0c2c11-3a0e-4f7e-9f61-0a7a3f0c1d22)"
)
WITHDREW = (
    f'SUCCESS (202, status=withdrawn): {{"status":"withdrawn","mitigation_id":"{MID}",'
    f'"mitigation_ids":["{MID}"]}}'
)


class ApiClientTests(unittest.TestCase):
    def test_stderr_refusal_with_success_exit_is_not_a_successful_ban(self):
        lab = FastNetMonLab.__new__(FastNetMonLab)
        lab.args = SimpleNamespace(fastnetmon="fixture")
        lab.log = lambda _: None
        execute = subprocess.run

        def fake_docker(command, **kwargs):
            self.assertEqual(command[:4], ["docker", "exec", "-i", "fixture"])
            return execute(["bash", "-c", "echo 'Query failed' >&2; exit 0"], **kwargs)

        with (
            patch("fastnetmon_frr.subprocess.run", side_effect=fake_docker),
            self.assertRaisesRegex(AssertionError, "Query failed"),
        ):
            lab.api_client("ban", "203.0.113.10")

    def probe_readiness(self, succeeds):
        # Run the script's readiness block with a fake API and controlled time.
        script = Path(__file__).with_name("fastnetmon-probe.sh").read_text()
        block = script[script.index("deadline=$((SECONDS + 30))") :]
        block = block[: block.index("\nin_probe 'flock --version'")]
        with tempfile.TemporaryDirectory() as directory:
            count = Path(directory) / "count"
            count.write_text("0")
            shell = (
                r"""
set -euo pipefail
name=fixture
client=fixture
timeout() { [ "$1" = 5 ]; shift; "$@"; }
docker() {
    local count
    count=$(cat "$TEST_COUNT")
    echo $((count + 1)) > "$TEST_COUNT"
    if [ "$TEST_SUCCEEDS" = 1 ] && [ "$count" -gt 0 ]; then return 0; fi
    echo 'Query failed: fixture API unavailable' >&2
}
sleep() { SECONDS=$deadline; }
"""
                + block
                + "\necho READY\n"
            )
            result = subprocess.run(
                ["bash", "-c", shell],
                text=True,
                capture_output=True,
                check=False,
                timeout=5,
                env={**os.environ, "TEST_COUNT": str(count), "TEST_SUCCEEDS": str(int(succeeds))},
            )
            return result, int(count.read_text())

    def test_probe_retries_exit_zero_query_failure_before_ready(self):
        result, calls = self.probe_readiness(succeeds=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, 2)
        self.assertIn("READY", result.stdout)

    def test_probe_query_failure_expires_with_diagnostics(self):
        result, calls = self.probe_readiness(succeeds=False)
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertEqual(calls, 2)
        self.assertNotIn("READY", result.stdout)
        self.assertIn("Query failed: fixture API unavailable", result.stderr)


class TokenControlTests(unittest.TestCase):
    def run_controls(self, *, legacy_status=401, events=(), mitigations=()):
        requests, logs = [], []
        tokens = {
            "fixture-wrong-source": 403,
            "fixture-operator": 403,
            "fixture-legacy-shared-bearer": legacy_status,
        }

        def urlopen(request, **_):
            requests.append(request)
            if request.get_method() == "POST":
                token = request.get_header("Authorization").removeprefix("Bearer ")
                status = tokens[token]
                body = io.BytesIO(b'{"error":"fixture refusal"}')
                if status >= 400:
                    raise urllib.error.HTTPError(request.full_url, status, "refused", None, body)
                body.status = status
                return body
            body = (
                {"events": list(events)}
                if "/events?" in request.full_url
                else {"mitigations": list(mitigations)}
            )
            response = io.BytesIO(json.dumps(body).encode())
            response.status = 200
            return response

        with tempfile.TemporaryDirectory() as directory:
            wrong = Path(directory) / "wrong.token"
            wrong.write_text("fixture-wrong-source\n")
            lab = FastNetMonLab.__new__(FastNetMonLab)
            lab.args = SimpleNamespace(api="http://fixture", wrong_token_file=wrong)
            lab.token = "fixture-operator"
            lab.use_session = False
            lab.opener = SimpleNamespace(open=urlopen)
            lab.log = logs.append
            with patch("fastnetmon_frr.urllib.request.urlopen", side_effect=urlopen):
                lab.token_controls("203.0.113.10")
        return requests, logs

    def test_all_three_credentials_are_refused_without_writes(self):
        requests, logs = self.run_controls()
        posts = [r for r in requests if r.get_method() == "POST"]
        self.assertEqual(
            [r.get_header("Authorization") for r in posts],
            [
                "Bearer fixture-wrong-source",
                "Bearer fixture-operator",
                "Bearer fixture-legacy-shared-bearer",
            ],
        )
        for request in posts:
            self.assertEqual(request.full_url, "http://fixture/v1/events")
            self.assertEqual(request.get_header("Content-type"), "application/json")
            event = json.loads(request.data)
            self.assertEqual(
                (event["event_id"], event["source"], event["victim_ip"]),
                ("lane-token-control", "fastnetmon", "203.0.113.10"),
            )
        self.assertEqual(
            [r.full_url for r in requests if r.get_method() == "GET"],
            [
                "http://fixture/v1/events?source=fastnetmon&limit=100",
                "http://fixture/v1/mitigations?victim_ip=203.0.113.10",
            ],
        )
        self.assertIn("POST /v1/events as legacy shared bearer -> 401", logs)
        for token in ("fixture-wrong-source", "fixture-operator", "fixture-legacy-shared-bearer"):
            self.assertNotIn(token, "\n".join(logs))

    def test_accepted_legacy_credential_fails_the_lane(self):
        with self.assertRaisesRegex(AssertionError, "legacy shared bearer"):
            self.run_controls(legacy_status=202)

    def test_event_stored_after_refusal_fails_the_lane(self):
        with self.assertRaisesRegex(AssertionError, "external_event_id"):
            self.run_controls(events=[{"external_event_id": "lane-token-control"}])

    def test_mitigation_stored_after_refusal_fails_the_lane(self):
        with self.assertRaisesRegex(AssertionError, "mitigation_id"):
            self.run_controls(mitigations=[{"mitigation_id": MID}])


class PackageReceiptTests(unittest.TestCase):
    def test_records_every_required_fastnetmon_package(self):
        lab = FastNetMonLab.__new__(FastNetMonLab)
        lab.args = SimpleNamespace(fastnetmon="fixture")
        packages = "fastnetmon\t1.2.9\ncurl\tfixture\njq\tfixture\n"
        calls = []

        def execute(command, **kwargs):
            calls.append(command)
            if "dpkg-query" in command:
                self.assertTrue(kwargs.get("check"))
                return subprocess.CompletedProcess(command, 0, stdout=packages)
            return subprocess.CompletedProcess(command, 0, stdout="sha256:fixture\n")

        with (
            patch("flowspec_frr.Lab.versions", return_value={}),
            patch("fastnetmon_frr.subprocess.run", side_effect=execute),
        ):
            receipt = lab.versions()
        self.assertEqual(
            calls[0],
            ["docker", "exec", "fixture", "dpkg-query", "-W", "fastnetmon", "curl", "jq"],
        )
        self.assertEqual(receipt["fastnetmon_packages"], packages.splitlines())


class ScriptLogTests(unittest.TestCase):
    def outcome(self, parse, lines, victim):
        """A parsed outcome that must exist."""
        found = parse(lines, victim)
        if found is None:
            self.fail(f"{parse.__name__} found no outcome for {victim} in {lines}")
        return found

    def test_messages_drop_the_timestamp(self):
        self.assertEqual(messages(f"2026-11-16T03:37:22+0000 {SENT}\n"), [SENT])

    def test_ban_accepted(self):
        got = self.outcome(ban_outcome, [SENT, ACCEPTED], "203.0.113.10")
        self.assertEqual((got["result"], got["http"], got["status"]), ("SUCCESS", 202, "accepted"))
        self.assertEqual(got["body"]["mitigation_id"], MID)

    def test_ban_still_running_has_no_outcome(self):
        self.assertIsNone(ban_outcome([SENT, RETRY], "203.0.113.10"))
        self.assertIsNone(ban_outcome([], "203.0.113.10"))

    def test_ban_failures(self):
        for line in (
            "ERROR (000, curl=7): ",
            'NO_MITIGATION (202, status=accepted_no_playbook): {"status":"x"}',
        ):
            with self.subTest(line=line):
                self.assertNotEqual(
                    self.outcome(ban_outcome, [SENT, RETRY, line], "203.0.113.10")["result"],
                    "SUCCESS",
                )
        # Checks that fail before the script sends end the call at once.
        for line in ("ERROR: curl is required", "ERROR: the token is malformed"):
            with self.subTest(line=line):
                self.assertEqual(
                    self.outcome(ban_outcome, [line], "203.0.113.10")["result"], "ERROR"
                )
                self.assertEqual(
                    self.outcome(unban_outcome, [line], "203.0.113.10")["result"], "ERROR"
                )

    def test_another_victims_ban_is_not_this_outcome(self):
        other = SENT.replace("203.0.113.10", "203.0.113.1")
        self.assertIsNone(ban_outcome([other, ACCEPTED], "203.0.113.10"))
        self.assertIsNone(ban_outcome([SENT, ACCEPTED], "203.0.113.1"))

    def test_unban(self):
        got = self.outcome(unban_outcome, [UNBAN, WITHDREW], "203.0.113.10")
        self.assertEqual((got["result"], got["mitigation_ids"]), ("WITHDRAWN", [MID]))
        self.assertIsNone(unban_outcome([UNBAN], "203.0.113.10"))
        nothing = (
            'NO_MITIGATION (202, status=no_active_mitigation): {"status":"no_active_mitigation",'
            '"mitigation_id":null,"mitigation_ids":[]}'
        )
        self.assertEqual(
            self.outcome(unban_outcome, [UNBAN, nothing], "203.0.113.10")["result"], "NOTHING_FOUND"
        )
        failed = 'ERROR (403, curl=0): {"error":"forbidden"}'
        self.assertEqual(
            self.outcome(unban_outcome, [UNBAN, failed], "203.0.113.10")["result"], "ERROR"
        )
        # A ban's log lines are not this unban's outcome.
        self.assertIsNone(unban_outcome([SENT, ACCEPTED], "203.0.113.10"))
        self.assertIsNone(unban_outcome([WITHDREW], "203.0.113.10"), "no send, no outcome")


class BanTimeTests(unittest.TestCase):
    def test_reads_the_lane_setting(self):
        self.assertEqual(ban_time("ban_time = 1900\nban_time_x = 3\n"), 1900)
        self.assertGreater(ban_time(CONF.read_text()), 0)
        with self.assertRaises(AssertionError):
            ban_time("# ban_time = 20\n")


class RuleTests(unittest.TestCase):
    def test_detected_rule_covers_the_flood(self):
        for ports in ([], [80], [53, 80]):
            check_udp_flood_coverage({"protocol": 17, "dst_ports": ports}, 80)
        for rule in (
            {"protocol": 17, "dst_ports": [53, 123]},
            {"protocol": 6, "dst_ports": []},
        ):
            with self.subTest(rule=rule), self.assertRaisesRegex(AssertionError, "misses"):
                check_udp_flood_coverage(rule, 80)

    def test_police_spelling(self):
        self.assertEqual(
            police("203.0.113.30", 5_000_000, proto=17, dst_ports=(53, 123)),
            {
                "family": "ipv4",
                "to": "203.0.113.30/32",
                "proto": "=17",
                "dstp": "=53,=123",
                "action": "FS:rate 625000.000000",
            },
        )
        self.assertEqual(police("2001:db8:113::10", 1_000_000)["to"], "2001:db8:113::10/128/off 0")


class NetflowTests(unittest.TestCase):
    def test_datagram_layout(self):
        packet = datagram("203.0.113.30", 40, 1000, 5000)
        self.assertEqual(len(packet), HEADER.size + RECORDS * RECORD.size)
        self.assertEqual(RECORD.size, 48)  # Cisco's NetFlow v5 flow record
        version, count, uptime, *_ = HEADER.unpack_from(packet)
        self.assertEqual((version, count, uptime), (5, RECORDS, 5000))
        record = RECORD.unpack_from(packet, HEADER.size)
        self.assertEqual(socket.inet_ntoa(record[1]), "203.0.113.30")
        self.assertEqual((record[5], record[6], record[10], record[13]), (1000, 512_000, 80, 17))


if __name__ == "__main__":
    unittest.main()
