#!/usr/bin/env python3
"""Drive FastNetMon Community bans through prefixd to FRR's FlowSpec tables.

Invoked by run-fastnetmon.sh against a deployed fastnetmon-rustbgpd.clab.yml
lab. FastNetMon Community 1.2.9 runs the bundled scripts/prefixd-fastnetmon.sh
as its notify script. Each ban or unban comes from FastNetMon itself
(`fastnetmon_api_client`, detection of a NetFlow v5 flood, or its ban timer)
except the extending re-ban, which runs the script directly with two bans and
an unban.

Every trigger waits for the script's own outcome line in its log before the
next one: FastNetMon starts ban and unban scripts independently, so an unban
sent before its ban finished could overtake it. The step then checks prefixd's
mitigation and waits until FRR's IPv4 and IPv6 FlowSpec tables hold exactly the
expected rules (flowspec_frr.parse_frr).

The receipt directory gets receipt.json, summary.md, commands.log, raw FRR
JSON, prefixd's events and the script's outcome lines. This is control-plane
evidence at FRR only: no packets are forwarded and no router enforcement is
claimed.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

# run-fastnetmon.sh uses python3 -I, which leaves the script directory off sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from flowspec_frr import Lab

API_CLIENT = "/opt/fastnetmon-community/app/bin/fastnetmon_api_client"
SCRIPT = "/usr/local/bin/prefixd-fastnetmon.sh"
SCRIPT_LOG = "/var/log/prefixd-fastnetmon.log"
NETFLOW = Path(__file__).resolve().parent / "netflow_v5.py"
OUTCOME_SECONDS = 60
DETECT_SECONDS = 90
CONF = Path(__file__).resolve().parent / "configs" / "fastnetmon.conf"


def ban_time(conf_text):
    """FastNetMon's ban_time from the lane configuration."""
    match = re.search(r"^ban_time = (\d+)$", conf_text, re.M)
    if match is None:
        raise AssertionError(f"{CONF.name} sets no ban_time")
    return int(match.group(1))


# The cleanup thread wakes every ban_time / 2 s and unbans only once the
# attack has finished, so allow two wakeups past ban_time plus a margin.
UNBAN_SECONDS = 2 * ban_time(CONF.read_text()) + 60

# Terminal lines of prefixd-fastnetmon.sh, after its timestamp.
BAN_OUTCOME = re.compile(
    r"^(SUCCESS|NO_MITIGATION) \((\d{3}), status=([^)]*)\): (.*)$|^(ERROR)\b(.*)$"
)
UNBAN_OUTCOME = re.compile(
    r"^SUCCESS: Withdrew mitigation (\S+) for (\S+)"
    r"|^(No active mitigations found for \S+ after \d+ attempts)"
    r"|^(ERROR)\b(.*)$"
)


def messages(log_text):
    """The script log's messages, without the leading timestamp."""
    return [line.split(" ", 1)[1] if " " in line else line for line in log_text.splitlines()]


def ban_outcome(lines, victim):
    """The outcome of the first ban for victim in lines, or None while it is running.

    Returns {"result", "http", "status", "body"}; result is SUCCESS,
    NO_MITIGATION or ERROR. A ban for another address is not this ban's outcome.
    """
    started = False
    for line in lines:
        if line.startswith(f"Sending ban for {victim} "):
            started = True
            continue
        # "ERROR: ..." lines come before the script sends anything (no curl,
        # no victim, an empty PREFIXD_OPERATOR), so the call is already over.
        if line.startswith("ERROR: "):
            return {"result": "ERROR", "http": None, "status": None, "body": line}
        if not started:
            continue
        match = BAN_OUTCOME.match(line)
        if match and match.group(1):
            body = match.group(4)
            return {
                "result": match.group(1),
                "http": int(match.group(2)),
                "status": match.group(3),
                "body": json.loads(body) if body.startswith("{") else body,
            }
        if match:
            return {"result": "ERROR", "http": None, "status": None, "body": line}
    return None


def unban_outcome(lines, victim):
    """The outcome of the first unban for victim: withdrawn IDs, nothing found, or ERROR."""
    started = False
    withdrawn = []
    for line in lines:
        if line.startswith("ERROR: "):
            return {"result": "ERROR", "mitigation_ids": [], "body": line}
        if line.startswith(f"Querying active mitigations for {victim} "):
            started = True
            continue
        if not started:
            continue
        match = UNBAN_OUTCOME.match(line)
        if not match:
            continue
        if match.group(1):
            withdrawn.append(match.group(1))
            # One withdrawal per live mitigation; the lane keeps one per victim.
            return {"result": "WITHDRAWN", "mitigation_ids": withdrawn, "body": line}
        if match.group(3):
            return {"result": "NOTHING_FOUND", "mitigation_ids": [], "body": line}
        return {"result": "ERROR", "mitigation_ids": [], "body": line}
    return None


def police(victim, rate_bps, proto=None, dst_ports=()):
    """A police rule as FRR 10.7.1 renders it; FRR shows the rate in bytes."""
    found = {
        "family": "ipv6" if ":" in victim else "ipv4",
        "to": f"{victim}/128/off 0" if ":" in victim else f"{victim}/32",
        "action": f"FS:rate {rate_bps / 8:.6f}",
    }
    if proto is not None:
        found["proto"] = f"={proto}"
    if dst_ports:
        found["dstp"] = ",".join(f"={port}" for port in dst_ports)
    return found


class FastNetMonLab(Lab):
    TITLE = "FastNetMon Community interop"
    SCOPE = (
        "FastNetMon Community notify path to prefixd and control-plane receipt of the "
        "resulting rules in FRR's BGP FlowSpec table; no dataplane or forwarding claim"
    )

    def __init__(self, args):
        super().__init__(args)
        (self.receipt / "script").mkdir(parents=True, exist_ok=True)
        self.collector = f"{urlparse(args.api).hostname}:2055"

    def fnm(self, *command, stdin=None):
        self.log(f"$ docker exec {self.args.fastnetmon} " + " ".join(command))
        return subprocess.run(
            ["docker", "exec", "-i", self.args.fastnetmon, *command],
            input=stdin,
            check=True,
            text=True,
            capture_output=True,
            timeout=60,
        ).stdout

    def script_log(self):
        # Polled; not logged per call.
        result = subprocess.run(
            ["docker", "exec", self.args.fastnetmon, "cat", SCRIPT_LOG],
            text=True,
            capture_output=True,
            timeout=30,
        )
        return messages(result.stdout) if result.returncode == 0 else []

    def api_client(self, action, victim):
        """fastnetmon_api_client exits 0 even when FastNetMon refuses; read its output."""
        output = self.fnm(API_CLIENT, action, victim)
        assert "Query failed" not in output, f"fastnetmon_api_client {action} {victim}: {output}"

    def wait_outcome(self, parse, victim, before, label, seconds=OUTCOME_SECONDS):
        """Wait for the script's outcome line for victim after the first `before` log lines."""
        deadline = time.monotonic() + seconds
        while True:
            lines = self.script_log()[before:]
            outcome = parse(lines, victim)
            if outcome is not None:
                (self.receipt / "script" / f"{label}.log").write_text("\n".join(lines) + "\n")
                self.log(f"script outcome for {victim}: {outcome['body']}")
                return outcome
            if time.monotonic() >= deadline:
                tail = subprocess.run(
                    [
                        "docker",
                        "exec",
                        self.args.fastnetmon,
                        "tail",
                        "-n",
                        "20",
                        "/var/log/fastnetmon.log",
                    ],
                    text=True,
                    capture_output=True,
                    timeout=30,
                ).stdout
                raise AssertionError(
                    f"{label}: no script outcome for {victim} within {seconds}s\n"
                    f"script log since trigger: {lines}\nFastNetMon log tail:\n{tail}"
                )
            time.sleep(1)

    def banned(self, trigger, victim, label, status="accepted"):
        """Run a ban trigger, wait for its outcome and return the live mitigation."""
        before = len(self.script_log())
        trigger()
        outcome = self.wait_outcome(ban_outcome, victim, before, label)
        assert (outcome["result"], outcome["status"]) == ("SUCCESS", status), (
            f"{label}: the script reported {outcome['result']} ({outcome['http']}, "
            f"status={outcome['status']}), expected SUCCESS with status={status}: {outcome['body']}"
        )
        mitigation = self.api("GET", f"/v1/mitigations/{outcome['body']['mitigation_id']}")
        assert mitigation["status"] == "active", (label, mitigation)
        return mitigation

    def unbanned(self, trigger, victim, mitigation_id, label, before=None, seconds=OUTCOME_SECONDS):
        if before is None:
            before = len(self.script_log())
        trigger()
        outcome = self.wait_outcome(unban_outcome, victim, before, label, seconds)
        assert outcome == {
            "result": "WITHDRAWN",
            "mitigation_ids": [mitigation_id],
            "body": outcome["body"],
        }, f"{label}: expected the script to withdraw {mitigation_id}, got {outcome}"
        status = self.status(mitigation_id)
        assert status == "withdrawn", (label, mitigation_id, status)

    def check(self, mitigation, vector, action, rate_bps):
        got = (mitigation["vector"], mitigation["action_type"], mitigation["rate_bps"])
        assert got == (vector, action, rate_bps), (mitigation["mitigation_id"], got)

    def scenario(self):
        manual = "203.0.113.10"
        rebanned = "203.0.113.20"
        detected = "203.0.113.30"
        direct = "203.0.113.40"
        ipv6 = "2001:db8:113::10"
        manual_rule = police(manual, 1_000_000)
        state = {}

        self.wait_frr("00-baseline", [])

        # A manual ban: FastNetMon runs the script with "<ip> other 0 ban" and
        # all-zero counters, so the script sends vector unknown.
        def api_ban():
            m = self.banned(lambda: self.api_client("ban", manual), manual, "01-api-ban")
            self.check(m, "unknown", "police", 1_000_000)
            state["manual"] = m

        self.step("api-ban", api_ban, [manual_rule])
        self.step(
            "api-unban",
            lambda: self.unbanned(
                lambda: self.api_client("unban", manual),
                manual,
                state["manual"]["mitigation_id"],
                "02-api-unban",
            ),
            [],
        )

        # fastnetmon_api_client ban on an address it already holds runs the
        # notify script again; prefixd extends the same mitigation.
        rebanned_rule = police(rebanned, 1_000_000)

        def api_reban():
            first = self.banned(
                lambda: self.api_client("ban", rebanned), rebanned, "03-api-ban-first"
            )
            second = self.banned(
                lambda: self.api_client("ban", rebanned),
                rebanned,
                "03-api-ban-again",
                status="extended",
            )
            assert second["mitigation_id"] == first["mitigation_id"], (first, second)
            assert second["expires_at"] > first["expires_at"], (first, second)
            state["rebanned"] = second

        self.step("api-reban-extends", api_reban, [rebanned_rule])
        self.step(
            "api-reban-unban",
            lambda: self.unbanned(
                lambda: self.api_client("unban", rebanned),
                rebanned,
                state["rebanned"]["mitigation_id"],
                "04-api-reban-unban",
            ),
            [],
        )

        # The extending re-ban the script owns (ADR 034 section 16): run it
        # directly with two bans, then an unban.
        details = (
            Path(__file__).resolve().parent / "fixtures" / "fastnetmon" / "udp-flood.txt"
        ).read_text()
        # A portless UDP flood takes the service's allowed UDP ports (inventory.yaml).
        direct_rule = police(direct, 5_000_000, proto=17, dst_ports=(53, 123))

        def run_script(action):
            return lambda: self.fnm(
                SCRIPT, direct, "incoming", "3625", action, stdin=details if action == "ban" else ""
            )

        def script_reban():
            first = self.banned(run_script("ban"), direct, "05-script-ban-first")
            self.check(first, "udp_flood", "police", 5_000_000)
            second = self.banned(
                run_script("ban"), direct, "05-script-ban-again", status="extended"
            )
            assert second["mitigation_id"] == first["mitigation_id"], (first, second)
            assert second["expires_at"] > first["expires_at"], (first, second)
            state["direct"] = second

        self.step("script-reban-extends", script_reban, [direct_rule])
        self.step(
            "script-unban",
            lambda: self.unbanned(
                run_script("unban"), direct, state["direct"]["mitigation_id"], "06-script-unban"
            ),
            [],
        )

        # FastNetMon hands IPv6 victims to the script with zero-padded groups
        # ("2001:0db8:0113::0010"). prefixd canonicalizes the rule's
        # destination but stores victim_ip as sent; the step records that
        # spelling rather than pinning it.
        ipv6_arg = "2001:0db8:0113::0010"
        ipv6_rule = police(ipv6, 1_000_000)

        def ipv6_ban():
            m = self.banned(lambda: self.api_client("ban", ipv6), ipv6_arg, "07-ipv6-api-ban")
            assert m["dst_prefix"] == f"{ipv6}/128", m
            self.steps[-1]["victim_ip_stored"] = m["victim_ip"]
            state["ipv6"] = m

        self.step("ipv6-api-ban", ipv6_ban, [ipv6_rule])
        self.step(
            "ipv6-api-unban",
            lambda: self.unbanned(
                lambda: self.api_client("unban", ipv6),
                ipv6_arg,
                state["ipv6"]["mitigation_id"],
                "08-ipv6-api-unban",
            ),
            [],
        )

        # Detection: a NetFlow v5 UDP flood above threshold_pps. FastNetMon
        # collects ban_details_records_count flows, then runs the script with
        # its real attack details on stdin.
        detected_rule = police(detected, 5_000_000, proto=17, dst_ports=(53, 123))

        def detect():
            sender = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    str(NETFLOW),
                    self.collector,
                    detected,
                    "--seconds",
                    str(DETECT_SECONDS),
                ]
            )
            self.log(
                f"$ {sys.executable} -I {NETFLOW.name} {self.collector} {detected} --seconds {DETECT_SECONDS}"
            )
            try:
                m = self.banned(lambda: None, detected, "09-detected-ban")
            finally:
                sender.terminate()
                sender.wait(timeout=10)
            self.check(m, "udp_flood", "police", 5_000_000)
            event = self.event(m["triggering_event_id"])
            raw = event["raw_details"]
            assert raw["direction"] == "incoming" and "Attack protocol: udp" in raw["raw"], raw
            assert event["pps"] > 1000, event
            state["detected"] = m
            # FastNetMon's timer cannot unban before ban_time, so nothing
            # after this point in the log belongs to the ban.
            state["detected_log"] = len(self.script_log())

        self.step("netflow-detected-ban", detect, [detected_rule], seconds=DETECT_SECONDS)

        # FastNetMon's own unban: once ban_time has passed and the flood has
        # stopped, its cleanup thread runs the script with the ban's direction
        # and pps. The script puts the direction in the withdrawal reason.
        def timer_unban():
            mitigation_id = state["detected"]["mitigation_id"]
            self.unbanned(
                lambda: None,
                detected,
                mitigation_id,
                "10-detected-timer-unban",
                before=state["detected_log"],
                seconds=UNBAN_SECONDS,
            )
            audit = self.api("GET", f"/v1/audit?target_type=mitigation&target_id={mitigation_id}")[
                "entries"
            ]
            # prefixd prefixes the reason with the actor ("anonymous: " in none mode).
            reasons = [e["details"].get("reason", "") for e in audit if e["action"] == "withdraw"]
            wanted = f"FastNetMon unban for {detected} (direction=incoming)"
            assert len(reasons) == 1 and reasons[0].endswith(wanted), audit
            self.steps[-1]["withdraw_reason"] = reasons[0]
            bans = [
                line
                for line in self.script_log()
                if line.startswith(f"Sending ban for {detected} ")
            ]
            assert len(bans) == 1, f"FastNetMon banned {detected} again: {bans}"

        self.step("detected-timer-unban", timer_unban, [])

    def event(self, event_id):
        events = self.api("GET", "/v1/events?source=fastnetmon&limit=100")["events"]
        found = [e for e in events if e["event_id"] == event_id]
        assert found, f"event {event_id} not in prefixd's event list"
        return found[0]

    def versions(self):
        found = super().versions()
        found["fastnetmon_packages"] = subprocess.run(
            ["docker", "exec", self.args.fastnetmon, "dpkg-query", "-W", "fastnetmon", "curl"],
            text=True,
            capture_output=True,
            timeout=30,
        ).stdout.splitlines()
        dockerfile = Path(__file__).resolve().parent / "fastnetmon.Dockerfile"
        base = re.search(r"^FROM (\S+)", dockerfile.read_text(), re.M)
        if base is None:
            raise AssertionError(f"{dockerfile.name} has no FROM line")
        found["fastnetmon_base"] = base.group(1)
        found["fastnetmon_image_id"] = subprocess.run(
            ["docker", "image", "inspect", "-f", "{{.Id}}", "prefixd-fastnetmon:interop"],
            text=True,
            capture_output=True,
            timeout=30,
        ).stdout.strip()
        return found

    def main(self):
        try:
            return super().main()
        finally:
            try:
                events = self.api("GET", "/v1/events?source=fastnetmon&limit=100")
                (self.receipt / "events.json").write_text(json.dumps(events, indent=2) + "\n")
            except (AssertionError, OSError, ValueError) as error:
                print(f"could not save prefixd events: {error}", flush=True)


def main():
    # python3 -OO strips docstrings.
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    for name in (
        "speaker",
        "api",
        "token-file",
        "frr",
        "speaker-container",
        "fastnetmon",
        "topology",
        "receipt",
    ):
        parser.add_argument(f"--{name}", required=True)
    raise SystemExit(0 if FastNetMonLab(parser.parse_args()).main() else 1)


if __name__ == "__main__":
    main()
