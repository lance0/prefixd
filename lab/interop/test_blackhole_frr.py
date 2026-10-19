#!/usr/bin/env python3
"""Negative controls for the FRR blackhole oracle, on FRR 10.7.1 output shapes.

Runs without a lab: python3 -m unittest discover -s lab/interop -p 'test_*.py'
"""

import copy
import unittest

from blackhole_frr import classify

PREFIX = "203.0.113.50/32"


def bgp(communities=("65010:666", "blackhole", "noExport"), peer="10.0.0.1", valid=True, paths=1):
    path = {
        "valid": valid,
        "bestpath": {"overall": valid},
        "peer": {"peerId": peer},
        "community": {"string": " ".join(communities), "list": list(communities)},
        "nexthops": [{"ip": "192.0.2.1", "afi": "ipv4", "accessible": True, "used": True}],
    }
    return {"prefix": PREFIX, "paths": [copy.deepcopy(path) for _ in range(paths)]}


def rib(blackhole=True):
    hops = [{"ip": "192.0.2.1", "afi": "ipv4", "active": True, "recursive": True, "weight": 1}]
    if blackhole:
        hops.append(
            {
                "flags": 3,
                "fib": True,
                "unreachable": True,
                "blackhole": True,
                "active": True,
                "resolver": True,
                "weight": 1,
            }
        )
    else:
        hops = [
            {
                "fib": True,
                "ip": "10.0.0.1",
                "afi": "ipv4",
                "interfaceName": "eth1",
                "active": True,
                "weight": 1,
            }
        ]
    return {
        PREFIX: [
            {
                "prefix": PREFIX,
                "protocol": "bgp",
                "selected": True,
                "installed": True,
                "nexthops": hops,
            }
        ]
    }


KERNEL_DISCARD = [{"type": "blackhole", "dst": "203.0.113.50", "protocol": "bgp", "metric": 20}]
KERNEL_VIA_LINK = [{"dst": "203.0.113.50", "gateway": "10.0.0.1", "dev": "eth1", "protocol": "bgp"}]


class OracleTests(unittest.TestCase):
    def test_discard(self):
        self.assertEqual(classify(PREFIX, bgp(), rib(), KERNEL_DISCARD), ("discard", []))

    def test_graceful_restart_stale_path(self):
        path = bgp()
        path["paths"][0]["stale"] = True
        self.assertEqual(classify(PREFIX, path, rib(), KERNEL_DISCARD), ("stale", []))

    def test_absent(self):
        self.assertEqual(classify(PREFIX, {}, {}, []), ("absent", []))

    def test_route_map_removed_is_not_discard(self):
        # Received over the link next hop, installed as an ordinary route.
        state, problems = classify(PREFIX, bgp(), rib(blackhole=False), KERNEL_VIA_LINK)
        self.assertEqual(state, "other")
        self.assertTrue(any("FIB next hops" in p for p in problems), problems)
        self.assertTrue(any("kernel routes" in p for p in problems), problems)
        # Received with an unresolvable next hop: in BGP, but nowhere in zebra or the kernel.
        self.assertEqual(classify(PREFIX, bgp(valid=False), {}, [])[0], "other")

    def test_each_view_is_required(self):
        for views in ((bgp(), rib(), []), (bgp(), {}, KERNEL_DISCARD), ({}, rib(), KERNEL_DISCARD)):
            with self.subTest(views=views):
                self.assertEqual(classify(PREFIX, *views)[0], "other")

    def test_communities_must_match_exactly(self):
        for communities in (
            ("65010:666", "blackhole"),
            ("blackhole", "noExport"),
            ("65010:666", "blackhole", "noExport", "noAdvertise"),
        ):
            with self.subTest(communities=communities):
                self.assertEqual(
                    classify(PREFIX, bgp(communities), rib(), KERNEL_DISCARD)[0], "other"
                )

    def test_path_must_be_one_valid_best_from_the_speaker(self):
        for path in (bgp(peer="10.0.0.9"), bgp(valid=False), bgp(paths=2)):
            with self.subTest(path=path):
                self.assertEqual(classify(PREFIX, path, rib(), KERNEL_DISCARD)[0], "other")

    def test_uninstalled_zebra_route_is_not_discard(self):
        table = rib()
        table[PREFIX][0]["installed"] = False
        self.assertEqual(classify(PREFIX, bgp(), table, KERNEL_DISCARD)[0], "other")


if __name__ == "__main__":
    unittest.main()
