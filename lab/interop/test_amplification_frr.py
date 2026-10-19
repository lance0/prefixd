#!/usr/bin/env python3
"""Negative controls for the FRR amplification oracle, on captured FRR 10.7.1 output.

The fixtures under fixtures/amplification/ are raw `show bgp <family> flowspec
[detail] json` output from the rustbgpd amplification run.

Runs without a lab: python3 -m unittest discover -s lab/interop -p 'test_*.py'
"""

import json
import unittest
from pathlib import Path

from amplification_frr import LENGTH, LIBRARY, over_limit, response, source_rule
from flowspec_frr import ordered, parse_frr

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "amplification"


def fixture(name):
    return (FIXTURES / f"{name}.json").read_text(), (FIXTURES / f"{name}-detail.json").read_text()


def observed(name, family, table=None, detail=None):
    captured_table, captured_detail = fixture(name)
    return parse_frr(family, table or captured_table, detail or captured_detail)


def edit_detail(name, change):
    """Apply change to each rule's components in the captured detail view."""
    text, decoder, rules = fixture(name)[1], json.JSONDecoder(), []
    while text.strip():
        parts, end = decoder.raw_decode(text.lstrip())
        text = text.lstrip()[end:]
        change(parts[0])
        rules.append(json.dumps(parts))
    return "\n".join(rules)


def rejected(name, family, expected, detail):
    """The oracle accepts the captured view but rejects the edited one.

    Rejection means the views disagree or the rules differ from expected.
    """
    if observed(name, family) != ordered(expected):
        return False
    try:
        return observed(name, family, detail=detail) != ordered(expected)
    except AssertionError:
        return True


NTP_MEMCACHED = response("203.0.113.60", [11211, 123], 8)
CHUNKED = response("2001:db8:113::62", LIBRARY, 5)
LENGTHS = response("2001:db8:113::63", [11211], 5, LENGTH)


class OracleTests(unittest.TestCase):
    def test_captured_rules_match(self):
        self.assertEqual(observed("ntp-memcached-ipv4", "ipv4"), ordered(NTP_MEMCACHED))
        self.assertEqual(observed("chunked-ipv6", "ipv6"), ordered(CHUNKED))
        self.assertEqual(observed("length-ipv6", "ipv6"), ordered(LENGTHS))

    def test_chunks_respect_frr_value_limit(self):
        self.assertEqual(len(CHUNKED), 5)
        self.assertEqual(over_limit(CHUNKED), [])
        # The lab configuration's max_ports 8 produces rules FRR 10.7.1 refuses.
        self.assertEqual(len(over_limit(response("203.0.113.61", LIBRARY, 8))), 2)

    def test_different_source_port_set_is_a_diff(self):
        for ports in ([123], [123, 11211, 53], [124, 11211]):
            wanted = [source_rule("203.0.113.60", ports), *NTP_MEMCACHED[1:]]
            with self.subTest(ports=ports):
                self.assertNotEqual(ordered(wanted), observed("ntp-memcached-ipv4", "ipv4"))

    def test_never_announced_rule_is_absent(self):
        wanted = [*NTP_MEMCACHED, source_rule("203.0.113.99", [123])]
        self.assertNotEqual(ordered(wanted), observed("ntp-memcached-ipv4", "ipv4"))

    def test_widened_rule_is_rejected(self):
        # A rule missing a component is broader than intended: the oracle must not accept it.
        for component in ("srcp", "pktlen", "pktfrag"):
            detail = edit_detail("length-ipv6", lambda c, k=component: c.pop(k, None))
            with self.subTest(component=component):
                self.assertTrue(rejected("length-ipv6", "ipv6", LENGTHS, detail))

    def test_extra_or_changed_component_is_a_diff(self):
        for change in (
            lambda c: c.update(dstp="= 53 "),
            lambda c: c.update(proto="= 6 "),
            lambda c: c.get("pktfrag") and c.update(pktfrag="= 4"),
            lambda c: c.get("pktlen") and c.update(pktlen=">= 468 , <= 65535 "),
        ):
            with self.subTest(change=change):
                detail = edit_detail("length-ipv6", change)
                self.assertTrue(rejected("length-ipv6", "ipv6", LENGTHS, detail))

    def test_swapped_actions_are_a_diff(self):
        detail = fixture("ntp-memcached-ipv4")[1]
        swapped = detail.replace("FS:rate 0.000000", "X").replace(
            "FS:rate 2500000.000000", "FS:rate 0.000000"
        )
        swapped = swapped.replace("X", "FS:rate 2500000.000000")
        self.assertTrue(rejected("ntp-memcached-ipv4", "ipv4", NTP_MEMCACHED, swapped))


if __name__ == "__main__":
    unittest.main()
