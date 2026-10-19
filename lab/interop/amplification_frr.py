#!/usr/bin/env python3
"""Drive udp_amplification events and assert FRR's FlowSpec tables (ADR 028).

Invoked by `run-frr.sh <speaker> amplification` against a deployed
frr-<speaker>.clab.yml lab (ADR 028, slice 7). FastNetMon-shaped events go
through `POST /v1/events`; the lab playbooks answer each with discard rules
for the reflector source ports and a policed non-first-fragment rule. Each step
waits until FRR's IPv4 and IPv6 FlowSpec tables hold exactly the expected rules:
destination, protocol, source ports, packet length, fragment and traffic-rate
action, with no other component. The oracle is flowspec_frr.parse_frr.

FRR 10.7.1 refuses a numeric component with more than five values and resets
the session. One step records that at the lab configuration's max_ports of 8,
deliberately above prefixd's default of 5; the rest of the scenario runs
prefixd with max_ports 5.

The receipt directory gets receipt.json, summary.md, commands.log and the raw
FRR output of every step. This is control-plane evidence at FRR only: FRR
installs no filter here, no packets are forwarded and no vendor forwarding is
claimed.
"""

import argparse
import contextlib
import datetime
import json
import subprocess
import sys
import time
from pathlib import Path

# run-frr.sh uses python3 -I, which leaves the script directory off sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flowspec_frr import FAMILIES, SPEAKER_ADDRESS, Lab, ordered

# prefixd's built-in reflector-port library (ADR 028), all twenty ports.
# fmt: off
LIBRARY = [17, 19, 53, 111, 123, 137, 161, 389, 427, 520,
           1434, 1900, 3283, 3702, 5353, 5683, 10001, 11211, 33848, 37810]
# fmt: on
FRR_MAX_VALUES = 5  # BGP_PBR_MATCH_VAL_MAX in FRR 10.7.1's bgpd/bgp_pbr.h
FRAGMENT_POLICE_BYTES = 2_500_000  # the lab playbooks police fragments at 20 Mbit/s
# The length variant's packet_length { min: 1000, max: 65535 }. FRR prints each
# value's operator but not the AND bit, so AND and OR render alike.
LENGTH = ">=1000,<=65535"
FRAGMENT_OFF = "fragment needs guardrails.allow_fragment_match: true"
CONTROLLER_START = "echo $$ >/tmp/prefixd.pid; exec prefixd --config {} >>/tmp/prefixd.log 2>&1"


def destination(victim):
    """FRR's spelling: IPv6 destinations carry an offset."""
    return f"{victim}/128/off 0" if ":" in victim else f"{victim}/32"


def family(victim):
    return "ipv6" if ":" in victim else "ipv4"


def source_rule(victim, ports, length=None):
    """A source-port rule as FRR 10.7.1 renders it, after whitespace compaction."""
    found = {
        "family": family(victim),
        "to": destination(victim),
        "proto": "=17",
        "srcp": ",".join(f"={port}" for port in ports),
        "action": "FS:rate 0.000000",
    }
    if length:
        found["pktlen"] = length
    return found


def fragment_rule(victim):
    """FRR prints the fragment bitmask as a number: = 2 is IsF with the match bit."""
    return {
        "family": family(victim),
        "to": destination(victim),
        "proto": "=17",
        "pktfrag": "=2",
        "action": f"FS:rate {FRAGMENT_POLICE_BYTES:.6f}",
    }


def response(victim, ports, chunk, length=None):
    """The rules one event produces: one per chunk of sorted ports, then the fragment rule."""
    ports = sorted(ports)
    sources = [
        source_rule(victim, ports[i : i + chunk], length) for i in range(0, len(ports), chunk)
    ]
    return [*sources, fragment_rule(victim)]


def over_limit(rules):
    """Rules whose source-port component has more values than FRR accepts."""
    return [r for r in rules if r.get("srcp", "").count(",") >= FRR_MAX_VALUES]


class AmplificationLab(Lab):
    TITLE = "Amplification interop"
    SCOPE = (
        "control-plane receipt of prefixd udp_amplification rules (source port, packet length, "
        "non-first fragment) in FRR's BGP FlowSpec table; FRR installs no filter here, "
        "no dataplane or forwarding claim"
    )

    def ban(self, victim, ports, ids, dst_ports=None):
        """One FastNetMon-shaped ban; returns the event's mitigation IDs."""
        body = {
            "event_id": ids,
            "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
            "source": "fastnetmon",
            "victim_ip": victim,
            "vector": "udp_amplification",
            "bps": 2_000_000_000,
            "pps": 400_000,
            "confidence": 0.9,
            "top_src_ports": ports,
            "action": "ban",
        }
        if dst_ports:
            body["top_dst_ports"] = dst_ports
        event = self.api("POST", "/v1/events", body, expect=(202,))
        assert event["status"] == "accepted", event
        return event["mitigation_ids"]

    def unban(self, victim, ids):
        event = self.api(
            "POST",
            "/v1/events",
            {
                "event_id": ids,
                "timestamp": datetime.datetime.now(datetime.UTC).isoformat(),
                "source": "fastnetmon",
                "victim_ip": victim,
                "vector": "udp_amplification",
                "action": "unban",
            },
            expect=(202,),
        )
        assert event["status"] == "withdrawn", event
        return event

    def withdraw(self, victims, prefix):
        return lambda: [self.unban(victim, f"{prefix}-{victim}") for victim in victims]

    def check_rules(self, mitigation_ids, expected):
        """prefixd's view: one mitigation per expected rule, in playbook order, with its action."""
        assert len(mitigation_ids) == len(expected), (mitigation_ids, expected)
        for mitigation_id, rule in zip(mitigation_ids, expected, strict=True):
            detail = self.api("GET", f"/v1/mitigations/{mitigation_id}")
            assert detail["action_type"] == ("discard" if "srcp" in rule else "police"), detail

    def controls(self, label, expected):
        """Live negative controls: near-miss expectations must not match what FRR holds."""
        observed = ordered(self.frr_rules(label))
        assert observed == ordered(expected), label
        first = dict(expected[0])
        first["srcp"] = first["srcp"].rsplit(",", 1)[0]
        near_misses = {
            "different source-port set": [first, *expected[1:]],
            "never-announced rule added": [*expected, source_rule("203.0.113.99", [123])],
            "fragment rule missing": [r for r in expected if "pktfrag" not in r],
        }
        for name, wrong in near_misses.items():
            assert ordered(wrong) != observed, f"{label}: oracle accepted {name}"
        return sorted(near_misses)

    def frr(self, label, name, *command):
        """Run a command in the FRR container and save its output under label."""
        text = self.run("docker", "exec", self.args.frr, *command, check=False)
        (self.receipt / "frr" / f"{label}-{name}").write_text(text)
        return text

    def install_state(self, label):
        """What FRR and its kernel show for filter installation, saved under label."""
        found = {
            f: self.frr(label, f"{f}-detail.txt", "vtysh", "-c", f"show bgp {f} flowspec detail")
            for f in FAMILIES
        }
        for name, command in {
            "pbr-ipset.txt": ("vtysh", "-c", "show pbr ipset"),
            "pbr-iptable.txt": ("vtysh", "-c", "show pbr iptable"),
            "pbr-rule.txt": ("vtysh", "-c", "show pbr rule"),
            "ip-rule.txt": ("ip", "rule"),
            "ip6-rule.txt": ("ip", "-6", "rule"),
            "filter-tools.txt": (
                "sh",
                "-c",
                "command -v iptables ip6tables ipset nft || echo none",
            ),
        }.items():
            self.frr(label, name, *command)
        details = "".join(found.values())
        return {
            "installed_in_pbr": details.count("\tinstalled in PBR"),
            "not_installed_in_pbr": details.count("not installed in PBR"),
        }

    def session(self):
        return json.loads(self.vtysh(f"show bgp neighbors {SPEAKER_ADDRESS} json"))[SPEAKER_ADDRESS]

    def controller(self, *command):
        return self.run("docker", "exec", self.args.controller, *command)

    def config_copy(self, name, sed):
        """Copy the running configuration to /tmp/<name> with one sed edit, checked."""
        path = f"/tmp/{name}"
        old, new = sed
        self.controller(
            "sh",
            "-c",
            f"rm -rf {path} && mkdir {path} && cp /etc/prefixd/*.yaml {path}/"
            f" && sed -i 's/{old}/{new}/' {path}/prefixd.yaml && grep -q '{new}' {path}/prefixd.yaml",
        )
        return path

    def restart_controller(self, config):
        self.controller("sh", "-c", 'kill -TERM "$(cat /tmp/prefixd.pid)"')
        deadline = time.monotonic() + 30
        while (
            subprocess.run(
                [
                    "docker",
                    "exec",
                    self.args.controller,
                    "sh",
                    "-c",
                    'kill -0 "$(cat /tmp/prefixd.pid)"',
                ],
                capture_output=True,
                timeout=30,
                check=False,
            ).returncode
            == 0
        ):
            assert time.monotonic() < deadline, "prefixd did not stop within 30s"
            time.sleep(1)
        self.run(
            "docker",
            "exec",
            "-d",
            self.args.controller,
            "sh",
            "-c",
            CONTROLLER_START.format(config),
        )
        self.wait_ready()

    def local_install(self):
        """Ask FRR to install FlowSpec filters on eth1 (runtime only; frr.conf is shared)."""
        for afi in FAMILIES:
            self.run(
                "docker", "exec", self.args.frr, "vtysh", "-c", "configure terminal", "-c", "router bgp 65002",
                "-c", f"address-family {afi} flowspec", "-c", "local-install eth1",
            )  # fmt: skip

    def session_reset(self, victims, ports):
        """At max_ports 8, the 8-value rules make FRR reset the session; record it, then withdraw."""
        before = self.session()
        for victim in victims:
            self.ban(victim, ports, f"over-{victim}")
        deadline = time.monotonic() + 60
        seen_over_limit = []
        while True:
            with contextlib.suppress(AssertionError, ValueError, subprocess.SubprocessError):
                seen_over_limit += over_limit(
                    self.frr_rules(f"{self.step_no:02d}-session-reset-poll")
                )
            after = self.session()
            if after.get("connectionsDropped", 0) > before.get("connectionsDropped", 0):
                break
            assert time.monotonic() < deadline, "FRR did not reset the session within 60s"
            time.sleep(1)
        assert not seen_over_limit, (
            "FRR held a rule with more than five source ports",
            seen_over_limit,
        )
        (self.receipt / "frr" / f"{self.step_no:02d}-session-reset-neighbor.json").write_text(
            json.dumps(after, indent=2) + "\n"
        )
        record = {
            k: after.get(k)
            for k in (
                "connectionsDropped",
                "lastResetDueTo",
                "lastErrorCodeSubcode",
                "lastNotificationReason",
            )
        }
        record["connectionsDroppedBefore"] = before.get("connectionsDropped")
        # FRR sends UPDATE Message Error / Optional Attribute Error for the refused NLRI.
        assert record["lastErrorCodeSubcode"] == "0309", record
        self.steps[-1]["session_reset"] = record
        self.withdraw(victims, "over")()
        self.wait_ready()

    def scenario(self):
        v4, v6 = "203.0.113.60", "2001:db8:113::60"
        o4, o6 = "203.0.113.61", "2001:db8:113::61"
        c4, c6 = "203.0.113.62", "2001:db8:113::62"
        l4, l6 = "203.0.113.63", "2001:db8:113::63"
        ntp_memcached = [11211, 123]
        for afi in FAMILIES:
            self.log(
                f"polled: docker exec {self.args.frr} vtysh -c 'show bgp {afi} flowspec [detail] json'"
            )
        self.local_install()
        self.wait_frr("00-baseline", [])

        pair = response(v4, ntp_memcached, 8) + response(v6, ntp_memcached, 8)

        def announce():
            ids = {victim: self.ban(victim, ntp_memcached, f"amp-{victim}") for victim in (v4, v6)}
            for victim, mitigation_ids in ids.items():
                self.check_rules(mitigation_ids, response(victim, ntp_memcached, 8))
            return ids

        self.step("ntp-memcached", announce, pair)
        label = f"{self.step_no:02d}-ntp-memcached"
        self.steps[-1]["negative_controls"] = self.controls(f"{label}-controls", pair)
        self.steps[-1]["install_state"] = self.install_state(f"{label}-install")

        self.step("unban", self.withdraw((v4, v6), "amp"), [])

        # The lab configuration's max_ports 8 chunks 20 ports as 8 + 8 + 4.
        self.step(
            "max-ports-8-session-reset",
            lambda: self.session_reset((o4, o6), LIBRARY),
            [],
            seconds=90,
        )

        self.step(
            "max-ports-5",
            lambda: self.restart_controller(
                self.config_copy("max-ports-5", ("max_ports: 8", "max_ports: 5"))
            ),
            [],
        )

        chunked = response(c4, LIBRARY, FRR_MAX_VALUES) + response(c6, LIBRARY, FRR_MAX_VALUES)
        assert len(chunked) == 10, (
            chunked
        )  # 5 + 5 + 5 + 5 source ports, plus the fragment rule, per family

        def chunk():
            ids = {
                victim: self.ban(victim, list(reversed(LIBRARY)), f"chunk-{victim}")
                for victim in (c4, c6)
            }
            for victim, mitigation_ids in ids.items():
                self.check_rules(mitigation_ids, response(victim, LIBRARY, FRR_MAX_VALUES))

        self.step("twenty-ports-chunked", chunk, chunked)

        repairs = 'prefixd_reconciliation_repairs_total{status="success"}'
        speaker = self.args.speaker_container

        def restart():
            before = self.metric(repairs)
            self.run("docker", "stop", speaker)
            self.wait_frr(f"{self.step_no:02d}-speaker-restart-stopped", [])
            self.run("docker", "start", speaker)
            return before

        before = self.step("speaker-restart", restart, chunked, seconds=120)
        repaired = self.metric(repairs) - before
        assert repaired >= len(chunked), (
            f"expected prefixd to repair {len(chunked)} rules, metric moved {repaired}"
        )
        self.steps[-1]["reconciliation_repairs"] = repaired

        self.step("unban-chunked", self.withdraw((c4, c6), "chunk"), [])

        lengths = response(l4, [11211], 5, LENGTH) + response(l6, [11211], 5, LENGTH)

        def expire():
            # top_dst_ports selects the 30 s packet-length playbook.
            created = [
                m
                for victim in (l4, l6)
                for m in self.ban(victim, [11211], f"len-{victim}", dst_ports=[11211])
            ]
            label = f"{self.step_no:02d}-length-ttl-announced"
            self.wait_frr(label, lengths, seconds=20)  # inside the 30 s TTL
            self.steps[-1]["install_state"] = self.install_state(f"{label}-install")
            return created

        created = self.step("packet-length-ttl-expiry", expire, [], seconds=90)
        assert [self.status(m) for m in created] == ["expired"] * len(lengths), created

        self.step("fragment-opt-in-refused", self.refuse_fragments, [])

    def refuse_fragments(self):
        """Negative control: the lab playbooks fail startup without allow_fragment_match.

        A second prefixd reads a copy of the running configuration with only that
        flag cleared. It must exit with the refusal before serving or announcing;
        the running controller, with the flag set, is the accepting control.
        """
        path = self.config_copy(
            "fragment-off",
            ("allow_fragment_match: true", "allow_fragment_match: false"),
        )
        command = ["docker", "exec", self.args.controller, "timeout", "60", "prefixd", "--config", path,
                   "--listen", "127.0.0.1:18080"]  # fmt: skip
        self.log("$ " + " ".join(command))
        result = subprocess.run(command, text=True, capture_output=True, timeout=90, check=False)
        output = result.stdout + result.stderr
        refusal = next((line for line in output.splitlines() if FRAGMENT_OFF in line), None)
        self.log(f"exit {result.returncode}: {refusal}")
        assert result.returncode not in (0, 124) and refusal, (
            result.returncode,
            output[-2000:],
        )
        self.steps[-1].update(exit_code=result.returncode, refusal=refusal.strip())


def main():
    if __doc__ is None:  # stripped by python -OO
        raise SystemExit("amplification_frr.py needs its docstring; do not run it with -OO")
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in (
        "speaker",
        "api",
        "token-file",
        "frr",
        "speaker-container",
        "topology",
        "receipt",
        "controller",
    ):
        parser.add_argument(f"--{name}", required=True)
    raise SystemExit(0 if AmplificationLab(parser.parse_args()).main() else 1)


if __name__ == "__main__":
    main()
