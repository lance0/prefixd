#!/usr/bin/env python3
"""Negative controls for the FastNetMon lane's script-log and NetFlow helpers.

Runs without a lab: python3 -m unittest discover -s lab/interop -p 'test_*.py'
The log lines are prefixd-fastnetmon.sh output from a 2026-11-16 lane run.
"""

import socket
import unittest

from fastnetmon_frr import ban_outcome, messages, police, unban_outcome
from netflow_v5 import HEADER, RECORD, RECORDS, datagram

MID = "a55fc086-8db5-495a-8021-2867853142ca"
SENT = (
    "Sending ban for 203.0.113.10 (unknown, 0 pps, event_id=ee1081e6-7b80-4b05-8cda-b78d7a1e195c)"
)
ACCEPTED = f'SUCCESS (202, status=accepted): {{"status":"accepted","mitigation_id":"{MID}"}}'
RETRY = "Ban for 203.0.113.10 not accepted (curl=7, http=000), attempt 1/3; retrying in 1s"
QUERY = "Querying active mitigations for 203.0.113.10 to withdraw"
WITHDREW = f"SUCCESS: Withdrew mitigation {MID} for 203.0.113.10 (200)"


class ScriptLogTests(unittest.TestCase):
    def test_messages_drop_the_timestamp(self):
        self.assertEqual(messages(f"2026-11-16T03:37:22+0000 {SENT}\n"), [SENT])

    def test_ban_accepted(self):
        got = ban_outcome([SENT, ACCEPTED], "203.0.113.10")
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
                    ban_outcome([SENT, RETRY, line], "203.0.113.10")["result"], "SUCCESS"
                )
        # A script that cannot run curl fails before it logs the send.
        self.assertEqual(
            ban_outcome(["ERROR: curl is required"], "203.0.113.10")["result"], "ERROR"
        )

    def test_another_victims_ban_is_not_this_outcome(self):
        other = SENT.replace("203.0.113.10", "203.0.113.1")
        self.assertIsNone(ban_outcome([other, ACCEPTED], "203.0.113.10"))
        self.assertIsNone(ban_outcome([SENT, ACCEPTED], "203.0.113.1"))

    def test_unban(self):
        self.assertEqual(unban_outcome([QUERY, WITHDREW], "203.0.113.10")["mitigation_ids"], [MID])
        self.assertIsNone(unban_outcome([QUERY], "203.0.113.10"))
        nothing = (
            "No active mitigations found for 203.0.113.10 after 5 attempts, nothing to withdraw"
        )
        self.assertEqual(unban_outcome([QUERY, nothing], "203.0.113.10")["result"], "NOTHING_FOUND")
        failed = f"ERROR withdrawing {MID} (500): boom"
        self.assertEqual(unban_outcome([QUERY, failed], "203.0.113.10")["result"], "ERROR")
        self.assertIsNone(unban_outcome([WITHDREW], "203.0.113.10"), "no query, no outcome")


class RuleTests(unittest.TestCase):
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
