#!/usr/bin/env python3
"""Drive prefixd manual blackholes and assert FRR's unicast RIB and FIB.

Invoked by `run-frr.sh rustbgpd blackhole` against a deployed
frr-rustbgpd.clab.yml lab (ADR 027, slice 7). An Admin session creates each
blackhole through `POST /v1/mitigations`. Each step then waits until every
watched host route is in an exact state at FRR:

- discard: one valid best path from the speaker with exactly the expected
  communities, a selected and installed zebra route whose FIB next hops are all
  blackhole, and a kernel route of type blackhole.
- absent: no BGP path, no BGP route in zebra and no kernel route.

Anything else is "other". The RPKI steps add the rtr node's ROAs for the lab
customer (203.0.113.0/24 and 2001:db8:113::/48, maxLength 24 and 48, AS 65010),
so every blackhole host route is RPKI-Invalid for that origin. They check a ban
under a speaker export chain that drops Invalid, under an FRR import policy that
exempts BLACKHOLE from its Invalid filter, and under one that drops Invalid
first. The receipt directory gets receipt.json, summary.md,
commands.log and the raw FRR and kernel JSON of every step. Secrets are never
written to it. This is control-plane evidence at FRR only: no packets are
forwarded and no vendor forwarding is claimed.
"""

import argparse
import datetime
import json
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

# run-frr.sh uses python3 -I, which leaves the script directory off sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flowspec_frr import SPEAKER_ADDRESS, Lab

# prefixd's frozen route: BLACKHOLE plus the lab's configured community.
COMMUNITIES = ["65010:666", "65535:666"]
# What FRR 10.7.1 holds: it adds NO_EXPORT on receipt of BLACKHOLE (RFC 7999 3.2).
FRR_COMMUNITIES = [*COMMUNITIES, "noExport"]
NEXT_HOPS = {"ipv4": "192.0.2.66", "ipv6": "2001:db8:ffff::66"}
ROUTE_MAPS = {"ipv4": "RTBH-IN-V4", "ipv6": "RTBH-IN-V6"}
CONTROLLER_START = (
    "echo $$ >/tmp/prefixd.pid; exec prefixd --config /etc/prefixd >>/tmp/prefixd.log 2>&1"
)
ADMIN = "interop-admin"
# rbgp in the speaker container, over the lab's loopback gRPC listener. The
# token stays in its file; only the path appears in the command log.
RBGP = ("rbgp", "-s", "http://127.0.0.1:50051", "--token-file", "/run/lab/rustbgpd.token", "-j")
RTR = "rpki cache tcp 10.0.0.1 8282 preference 1"
SPEAKER_ASN = 65010


def family(prefix):
    return "ipv6" if ":" in prefix else "ipv4"


def host(victim):
    return f"{victim}/{128 if ':' in victim else 32}"


def _community(value):
    """FRR names RFC 7999 BLACKHOLE "blackhole"; compare numerically."""
    return "65535:666" if value == "blackhole" else value


def find(value, key):
    """Every value of key anywhere in a JSON document, depth first."""
    if isinstance(value, dict):
        for name, item in value.items():
            if name == key:
                yield item
            yield from find(item, key)
    elif isinstance(value, list):
        for item in value:
            yield from find(item, key)


def frr_rpki_states(bgp):
    """FRR's per-path RPKI state, from `show bgp <afi> unicast <prefix> json`."""
    return [path.get("rpkiValidationState") for path in bgp.get("paths") or []]


def classify(prefix, bgp, rib, fib, communities=FRR_COMMUNITIES):
    """Reduce one prefix's FRR views to discard, stale, absent or other, with reasons.

    stale is discard held by FRR's Graceful Restart helper after the session dropped.

    bgp is `show bgp <afi> unicast <prefix> json`, rib is
    `show ip[v6] route <prefix> json` and fib is `ip -j route show exact <prefix>`.
    """
    paths = bgp.get("paths") or []
    zebra = [route for route in rib.get(prefix, []) if route.get("protocol") == "bgp"]
    if not paths and not zebra and not fib:
        return "absent", []
    problems = []
    if len(paths) != 1:
        problems.append(f"{len(paths)} BGP paths")
    for path in paths:
        if (path.get("peer") or {}).get("peerId") != SPEAKER_ADDRESS:
            problems.append(f"path from {(path.get('peer') or {}).get('peerId')}")
        if not path.get("valid") or not (path.get("bestpath") or {}).get("overall"):
            problems.append("path not valid best")
        seen = sorted(_community(c) for c in (path.get("community") or {}).get("list", []))
        if seen != sorted(communities):
            problems.append(f"communities {seen}")
    if len(zebra) != 1:
        problems.append(f"{len(zebra)} zebra BGP routes")
    for route in zebra:
        if not (route.get("selected") and route.get("installed")):
            problems.append("zebra route not selected and installed")
        installed = [hop for hop in route.get("nexthops", []) if hop.get("fib")]
        if not installed or not all(hop.get("blackhole") for hop in installed):
            problems.append(f"FIB next hops {installed}")
    if [route.get("type") for route in fib] != ["blackhole"]:
        problems.append(f"kernel routes {fib}")
    if problems:
        return "other", problems
    return ("stale", []) if any(path.get("stale") for path in paths) else ("discard", [])


class BlackholeLab(Lab):
    TITLE = "Blackhole interop"
    SCOPE = (
        "control-plane receipt of prefixd blackhole host routes in FRR's unicast BGP table, "
        "zebra RIB and container kernel FIB; no packet forwarding or vendor claim"
    )

    def quiet(self, *command, check=True):
        # Polled every second, so not logged per call; scenario() logs them once.
        return subprocess.run(command, check=check, text=True, capture_output=True, timeout=60)

    def observe(self, label, prefixes):
        """Read and save every view of each prefix; return {prefix: (state, problems)}."""
        states = {}
        for prefix in prefixes:
            afi = family(prefix)
            bgp = json.loads(self.vtysh(f"show bgp {afi} unicast {prefix} json") or "{}")
            rib = json.loads(
                self.vtysh(f"show {'ipv6' if afi == 'ipv6' else 'ip'} route {prefix} json") or "{}"
            )
            fib = json.loads(
                self.quiet(
                    "docker",
                    "exec",
                    self.args.frr,
                    "ip",
                    "-j",
                    "-6" if afi == "ipv6" else "-4",
                    "route",
                    "show",
                    "exact",
                    prefix,
                ).stdout
                or "[]"
            )
            name = prefix.replace("/", "_").replace(":", "-")
            (self.receipt / "frr" / f"{label}-{name}.json").write_text(
                json.dumps({"bgp": bgp, "rib": rib, "kernel": fib}, indent=2) + "\n"
            )
            states[prefix] = classify(prefix, bgp, rib, fib)
        return states

    def wait_states(self, label, want, seconds=60):
        """Poll until every prefix is in its wanted state; the last poll is kept."""
        deadline = time.monotonic() + seconds
        while True:
            try:
                states = self.observe(label, want)
                if all(states[prefix][0] == wanted for prefix, wanted in want.items()):
                    return states
                problem = {prefix: states[prefix] for prefix in want}
            except (ValueError, subprocess.SubprocessError) as error:
                problem = repr(error)
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"{label}: FRR did not reach {want} within {seconds}s: {problem}"
                )
            time.sleep(1)

    def bstep(self, name, action, want, seconds=60):
        self.step_no += 1
        label = f"{self.step_no:02d}-{name}"
        print(f"[{label}] start", flush=True)
        self.observe(f"{label}-before", want)
        started = time.monotonic()
        record = {"step": label, "expected": want}
        self.steps.append(record)
        result = action()
        states = self.wait_states(f"{label}-after", want, seconds)
        record.update(
            result="pass",
            seconds=round(time.monotonic() - started, 1),
            observed={prefix: state for prefix, (state, _) in states.items()},
        )
        print(f"[{label}] PASS in {record['seconds']}s", flush=True)
        return result

    def login(self):
        self.run(
            "docker",
            "exec",
            self.args.controller,
            "sh",
            "-c",
            f"prefixdctl operators create --username {ADMIN} --role admin "
            '--password "$PREFIXD_LAB_ADMIN_PASSWORD"',
        )
        password = Path(self.args.admin_password_file).read_text().strip()
        request = urllib.request.Request(
            self.args.api + "/v1/auth/login",
            method="POST",
            data=json.dumps({"username": ADMIN, "password": password}).encode(),
            headers={"Content-Type": "application/json"},
        )
        with self.opener.open(request, timeout=30) as response:
            role = json.loads(response.read().decode())["role"]
        self.log(
            f"POST /v1/auth/login {ADMIN} (password withheld) -> {response.status}, role {role}"
        )
        assert role == "admin", role

    def blackhole(self, victim, ttl):
        mitigation = self.api(
            "POST",
            "/v1/mitigations",
            {
                "action": "blackhole",
                "victim_ip": victim,
                "confirm_victim_ip": victim,
                "reason": "interop blackhole",
                "ttl_seconds": ttl,
            },
            expect=(201,),
        )
        frozen = mitigation["blackhole"]
        assert (mitigation["action_type"], mitigation["dst_prefix"]) == (
            "blackhole",
            host(victim),
        ), mitigation
        assert frozen["next_hop"] == NEXT_HOPS[family(victim)], frozen
        assert sorted(frozen["communities"]) == COMMUNITIES, frozen
        return mitigation["mitigation_id"]

    def route_maps(self, bound):
        for afi, name in ROUTE_MAPS.items():
            prefix = "" if bound else "no "
            self.run(
                "docker",
                "exec",
                self.args.frr,
                "vtysh",
                "-c",
                "configure terminal",
                "-c",
                "router bgp 65002",
                "-c",
                f"address-family {afi} unicast",
                "-c",
                f"{prefix}neighbor {SPEAKER_ADDRESS} route-map {name} in",
            )
            self.run(
                "docker",
                "exec",
                self.args.frr,
                "vtysh",
                "-c",
                f"clear bgp {afi} unicast {SPEAKER_ADDRESS} soft in",
            )

    def stop_controller(self):
        self.run(
            "docker",
            "exec",
            self.args.controller,
            "sh",
            "-c",
            'kill -TERM "$(cat /tmp/prefixd.pid)"',
        )
        deadline = time.monotonic() + 30
        while (
            self.quiet(
                "docker",
                "exec",
                self.args.controller,
                "sh",
                "-c",
                'kill -0 "$(cat /tmp/prefixd.pid)"',
                check=False,
            ).returncode
            == 0
        ):
            assert time.monotonic() < deadline, "prefixd did not stop within 30s"
            time.sleep(1)

    def rbgp(self, *args):
        """rbgp's JSON output; a failure reports rbgp's own error."""
        command = ("docker", "exec", self.args.speaker_container, *RBGP, *args)
        self.log("$ " + " ".join(command))
        result = subprocess.run(command, text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, f"{' '.join(args)}: {result.stderr.strip()}"
        return json.loads(result.stdout or "null")

    def frr_configure(self, *lines):
        command = ["docker", "exec", self.args.frr, "vtysh", "-c", "configure terminal"]
        for line in lines:
            command += ["-c", line]
        self.run(*command)

    def soft_in(self):
        for afi in ROUTE_MAPS:
            self.run(
                "docker",
                "exec",
                self.args.frr,
                "vtysh",
                "-c",
                f"clear bgp {afi} unicast {SPEAKER_ADDRESS} soft in",
            )

    def rpki_filter(self, seq, present):
        """Add or remove `deny <seq> match rpki invalid` in both import route-maps."""
        for name in ROUTE_MAPS.values():
            if present:
                self.frr_configure(f"route-map {name} deny {seq}", "match rpki invalid", "exit")
            else:
                self.frr_configure(f"no route-map {name} deny {seq}")
        self.soft_in()

    def frr_rpki(self, prefixes):
        """{prefix: FRR RPKI states of its paths}."""
        return {
            prefix: frr_rpki_states(
                json.loads(self.vtysh(f"show bgp {family(prefix)} unicast {prefix} json") or "{}")
            )
            for prefix in prefixes
        }

    def announce_outcomes(self, ids):
        """{mitigation_id: [audited speaker add outcomes, oldest first]}."""
        entries = self.api("GET", "/v1/audit?limit=1000")["entries"]
        return {
            m: [
                e["details"]["outcome"]
                for e in reversed(entries)
                if e["action"] == "announce" and e["target_id"] == m
            ]
            for m in ids
        }

    def start_controller(self):
        self.run("docker", "exec", "-d", self.args.controller, "sh", "-c", CONTROLLER_START)
        self.wait_ready()

    def scenario(self):
        v4, v6 = "203.0.113.50", "2001:db8:113::50"
        main = {host(v4): "discard", host(v6): "discard"}
        gone = {prefix: "absent" for prefix in main}
        never = {host("203.0.113.99"): "absent", host("2001:db8:113::99"): "absent"}

        for afi in ("ipv4", "ipv6"):
            self.log(
                f"polled: docker exec {self.args.frr} vtysh -c 'show bgp {afi} unicast <prefix> json', "
                f"'show ip[v6] route <prefix> json'; ip -j route show exact <prefix>"
            )
        self.login()
        # Negative control: a route that was never announced is reported absent.
        self.wait_states("00-baseline", {**gone, **never})

        ids = self.bstep(
            "announce", lambda: [self.blackhole(v, 600) for v in (v4, v6)], {**main, **never}
        )

        # Negative control: without the import route-map, the discard check fails.
        def unbind():
            self.route_maps(bound=False)

        self.bstep("route-map-removed", unbind, {prefix: "other" for prefix in main})
        self.steps[-1]["problems"] = {
            prefix: problems
            for prefix, (_, problems) in self.observe(
                f"{self.step_no:02d}-route-map-removed-detail", main
            ).items()
        }
        self.bstep("route-map-restored", lambda: self.route_maps(bound=True), main)

        repairs = 'prefixd_reconciliation_repairs_total{status="success"}'
        speaker = self.args.speaker_container

        def restart():
            # FRR is a Graceful Restart helper: it keeps the routes, marked stale,
            # while the speaker is down (ADR 027 failure modes: measure this).
            before = self.metric(repairs)
            self.run("docker", "stop", speaker)
            self.wait_states(
                f"{self.step_no:02d}-speaker-stopped", {prefix: "stale" for prefix in main}
            )
            started = time.monotonic()
            self.run("docker", "start", speaker)
            timeline, last = [], None
            while time.monotonic() - started < 120:
                states = {
                    prefix: state
                    for prefix, (state, _) in self.observe(
                        f"{self.step_no:02d}-speaker-restarting", main
                    ).items()
                }
                if states != last:
                    timeline.append(
                        {"seconds_after_start": round(time.monotonic() - started, 1), **states}
                    )
                    last = states
                if states == main:
                    break
                time.sleep(0.5)
            return before, timeline

        before, timeline = self.bstep("speaker-restart", restart, main, seconds=120)
        repaired = self.metric(repairs) - before
        assert repaired >= 2, (
            f"expected prefixd to repair 2 blackholes, repairs metric moved {repaired}"
        )
        # The restart lost the routes, so each repair is a new local route again.
        outcomes = self.announce_outcomes(ids)
        assert all(o[0] == "created" and o[-1] == "created" for o in outcomes.values()), outcomes
        self.steps[-1].update(
            reconciliation_repairs=repaired,
            timeline_after_start=timeline,
            audited_add_outcomes=outcomes,
        )

        self.bstep(
            "withdraw",
            lambda: [
                self.api("POST", f"/v1/mitigations/{m}/withdraw", {"reason": "interop withdrawal"})
                for m in ids
            ],
            gone,
        )
        assert [self.status(m) for m in ids] == ["withdrawn", "withdrawn"]

        expiring = {host("203.0.113.51"): "discard", host("2001:db8:113::51"): "discard"}

        def expire():
            created = [self.blackhole(v, 15) for v in ("203.0.113.51", "2001:db8:113::51")]
            self.wait_states(f"{self.step_no:02d}-ttl-expiry-announced", expiring)
            return created

        created = self.bstep(
            "ttl-expiry", expire, {prefix: "absent" for prefix in expiring}, seconds=90
        )
        assert [self.status(m) for m in created] == ["expired", "expired"]

        # Negative case (ADR 027 failure modes): a manual blackhole is unleased, so
        # with prefixd stopped and the speaker up it outlives its TTL at FRR.
        stranded = {host("203.0.113.52"): "discard", host("2001:db8:113::52"): "discard"}

        def stop():
            created = [self.blackhole(v, 20) for v in ("203.0.113.52", "2001:db8:113::52")]
            expires = max(
                datetime.datetime.fromisoformat(
                    self.api("GET", f"/v1/mitigations/{m}")["expires_at"]
                )
                for m in created
            )
            self.wait_states(f"{self.step_no:02d}-controller-stop-announced", stranded)
            self.stop_controller()
            self.wait_states(f"{self.step_no:02d}-controller-stopped", stranded)
            # Hold until 30 s past the TTL; the step then requires discard still.
            now = datetime.datetime.now(datetime.UTC)
            time.sleep(max(0.0, (expires - now).total_seconds()) + 30)
            return created, expires

        created, expires = self.bstep("controller-stopped-route-persists", stop, stranded)
        past = datetime.datetime.now(datetime.UTC) - expires
        self.steps[-1].update(
            expires_at=expires.isoformat(),
            checked_seconds_after_expiry=round(past.total_seconds()),
            note="known unleased gap: nothing expires a manual blackhole while prefixd is stopped",
        )

        self.bstep(
            "controller-restart-expires",
            self.start_controller,
            {prefix: "absent" for prefix in stranded},
            seconds=90,
        )
        assert [self.status(m) for m in created] == ["expired", "expired"]

        self.rpki_steps()
        self.wait_states(f"{self.step_no:02d}-end", {**gone, **never})

    def rpki_steps(self):
        victims = ("203.0.113.53", "2001:db8:113::53")
        held = {host(v): "discard" for v in victims}
        dropped = {prefix: "absent" for prefix in held}
        caches = self.rbgp("rpki", "caches")
        (self.receipt / "rpki-speaker-caches.json").write_text(json.dumps(caches, indent=2) + "\n")

        # The speaker's export chain drops RPKI-Invalid routes for the whole run
        # (configs/rustbgpd.toml). Control: the same host route injected with an
        # AS_PATH has an origin to validate, so the speaker withholds it.
        control = host("203.0.113.54")

        def speaker_drops_invalid():
            self.rbgp(
                "rib",
                "add",
                control,
                "--next-hop",
                NEXT_HOPS["ipv4"],
                "--as-path",
                str(SPEAKER_ASN),
                "--communities",
                "65010:666,BLACKHOLE",
            )
            return [self.blackhole(v, 600) for v in victims]

        ids = self.bstep(
            "rpki-speaker-drops-invalid", speaker_drops_invalid, {**held, control: "absent"}
        )
        # Give the control route time to be exported, if the filter let it through.
        time.sleep(3)
        self.wait_states(f"{self.step_no:02d}-rpki-control-withheld", {control: "absent"}, 1)
        speaker = {}
        for prefix in [*held, control]:
            afi = f"{family(prefix)}_unicast"
            speaker[prefix] = {
                # The speaker's own VRP table for this prefix with the lab origin.
                "validate_origin_65010": self.rbgp("rpki", "validate", prefix, str(SPEAKER_ASN)),
                # The state it stores for the local route.
                "local_validation_state": list(
                    find(
                        self.rbgp("rib", "received", "0.0.0.0", "-a", afi, "-p", prefix),
                        "validation_state",
                    )
                ),
            }
        for prefix in held:
            assert speaker[prefix]["local_validation_state"] == ["not_found"], speaker
        assert speaker[control]["local_validation_state"] == ["invalid"], speaker
        self.steps[-1].update(
            speaker_export_chain=self.rbgp("policy", "chain", "show"),
            speaker_rpki=speaker,
            audited_add_outcomes=self.announce_outcomes(ids),
        )
        self.rbgp("rib", "delete", control, "--allow-missing")

        # FRR validates with the speaker as origin. Its Invalid filter sits behind
        # the BLACKHOLE permit (seq 10), so blackholes are exempt from it.
        def router_exempts_blackhole():
            self.frr_configure("rpki", RTR, "exit")
            self.rpki_filter(15, present=True)
            deadline = time.monotonic() + 60
            while True:
                states = self.frr_rpki(held)
                if all(s == ["invalid"] for s in states.values()):
                    # Re-run the import route-maps now that the paths are Invalid.
                    self.soft_in()
                    return states
                assert time.monotonic() < deadline, f"FRR RPKI states {states}"
                time.sleep(1)

        states = self.bstep("rpki-router-exempts-blackhole", router_exempts_blackhole, held)
        self.steps[-1]["frr_rpki_states"] = states

        # Negative control: an Invalid filter ahead of the exemption drops every ban.
        self.bstep("rpki-router-drops-invalid", lambda: self.rpki_filter(5, present=True), dropped)
        self.bstep("rpki-router-filter-removed", lambda: self.rpki_filter(5, present=False), held)
        self.bstep(
            "rpki-withdraw",
            lambda: [
                self.api("POST", f"/v1/mitigations/{m}/withdraw", {"reason": "interop withdrawal"})
                for m in ids
            ],
            dropped,
        )
        assert [self.status(m) for m in ids] == ["withdrawn", "withdrawn"]


def main():
    if __doc__ is None:  # stripped by python -OO
        raise SystemExit("blackhole_frr.py needs its docstring; do not run it with -OO")
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
        "admin-password-file",
    ):
        parser.add_argument(f"--{name}", required=True)
    raise SystemExit(0 if BlackholeLab(parser.parse_args()).main() else 1)


if __name__ == "__main__":
    main()
