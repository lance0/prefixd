#!/usr/bin/env python3
"""Negative controls for the FRR FlowSpec oracle, on FRR 10.7.1 output.

Runs without a lab: python3 -m unittest discover -s lab/interop -p 'test_*.py'
"""

import json
import unittest

from flowspec_frr import diff, ordered, parse_frr, rule

PATH = (
    '{"valid":true,"bestpath":true,"selectionReason":"First path received","pathFrom":"external",'
    '"to":"%s","proto":"= %d ","dstp":"= %d ","weight":0,"peerId":"10.0.0.1","path":"65010","origin":"IGP"}'
)


def table(*routes, total=None):
    body = ",".join(
        f'"to {to} proto = {proto}  dstp = {port} /12": [{PATH % (to, proto, port)}]'
        for to, proto, port in routes
    )
    count = len(routes) if total is None else total
    return f'{{"routes": {{ {body} }}, "totalRoutes": {count}, "totalPaths": {count}}}'


def detail(*routes):
    return "\n".join(
        json.dumps(
            [
                {"to": to, "proto": f"= {proto} ", "dstp": f"= {port} "},
                {"ecomlist": action},
                {"time": "00:00:01"},
            ],
            indent=2,
        )
        for to, proto, port, action in routes
    )


POLICE = ("203.0.113.20/32", 6, 80)
DISCARD = ("203.0.113.10/32", 17, 53)
EXPECTED = [
    rule("ipv4", "203.0.113.20/32", 6, 80, 1_000_000),
    rule("ipv4", "203.0.113.10/32", 17, 53, 0),
]


def observed(police_action="FS:rate 1000000.000000", **table_args):
    return parse_frr(
        "ipv4",
        table(POLICE, DISCARD, **table_args),
        detail((*POLICE, police_action), (*DISCARD, "FS:rate 0.000000")),
    )


class OracleTests(unittest.TestCase):
    def test_exact_rules_match(self):
        self.assertEqual(observed(), ordered(EXPECTED))
        self.assertEqual(diff(EXPECTED, observed()), "")

    def test_empty_table(self):
        self.assertEqual(parse_frr("ipv6", table(), ""), [])

    def test_ipv6_destination_keeps_offset_spelling(self):
        to = "2001:db8:113::10/128/off 0"
        got = parse_frr("ipv6", table((to, 17, 53)), detail((to, 17, 53, "FS:rate 0.000000")))
        self.assertEqual(got, [rule("ipv6", to, 17, 53, 0)])

    def test_wrong_action_or_match_is_a_diff(self):
        for mutate in (
            lambda r: r.update(action="FS:rate 0.000000"),
            lambda r: r.update(proto="=17"),
            lambda r: r.update(dstp="=443"),
            lambda r: r.update(to="203.0.113.21/32"),
            lambda r: r.update(family="ipv6"),
        ):
            wanted = [dict(r) for r in EXPECTED]
            mutate(wanted[0])
            with self.subTest(wanted=wanted[0]):
                self.assertNotEqual(ordered(wanted), observed())
                self.assertIn("-", diff(wanted, observed()))

    def test_missing_or_extra_rule_is_a_diff(self):
        self.assertNotEqual(ordered(EXPECTED[:1]), observed())
        self.assertNotEqual(
            ordered(EXPECTED + [rule("ipv4", "203.0.113.30/32", 17, 123, 625_000)]), observed()
        )

    def test_inconsistent_frr_views_are_rejected(self):
        with self.assertRaises(AssertionError):
            observed(total=3)
        with self.assertRaises(AssertionError):
            parse_frr("ipv4", table(POLICE), detail((*DISCARD, "FS:rate 0.000000")))
        not_best = table(POLICE).replace('"bestpath":true', '"bestpath":false')
        with self.assertRaises(AssertionError):
            parse_frr("ipv4", not_best, detail((*POLICE, "FS:rate 1000000.000000")))
        other_peer = table(POLICE).replace('"peerId":"10.0.0.1"', '"peerId":"10.0.0.9"')
        with self.assertRaises(AssertionError):
            parse_frr("ipv4", other_peer, detail((*POLICE, "FS:rate 1000000.000000")))


if __name__ == "__main__":
    unittest.main()
