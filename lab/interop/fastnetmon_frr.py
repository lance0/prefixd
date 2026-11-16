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
import urllib.error
import urllib.request
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


def check_udp_flood_coverage(mitigation, port):
    """A detected rule must include the synthetic flood's destination port."""
    assert mitigation["protocol"] == 17 and (
        not mitigation["dst_ports"] or port in mitigation["dst_ports"]
    ), (f"rule misses the NetFlow flood's UDP destination port {port}", mitigation)


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


def messages(log_text):
    """The script log's messages, without the leading timestamp."""
    return [line.split(" ", 1)[1] if " " in line else line for line in log_text.splitlines()]


def ban_outcome(lines, victim, action="ban"):
    """The outcome of the first ban (or unban) for victim in lines, or None while it runs.

    Returns {"result", "http", "status", "body"}; result is SUCCESS,
    NO_MITIGATION or ERROR. A call for another address is not this outcome.
    """
    started = False
    for line in lines:
        if line.startswith(f"Sending {action} for {victim} "):
            started = True
            continue
        # "ERROR: ..." lines come before the script sends anything (no curl,
        # no victim, an unreadable or malformed token), so the call is over.
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
    """The outcome of the first unban for victim: withdrawn IDs, nothing to withdraw, or ERROR.

    The script posts an unban event; prefixd answers `withdrawn` with the IDs
    it withdrew, or the definitive `no_active_mitigation`.
    """
    outcome = ban_outcome(lines, victim, action="unban")
    if outcome is None:
        return None
    body = outcome["body"]
    if outcome["result"] == "SUCCESS" and outcome["status"] == "withdrawn":
        return {"result": "WITHDRAWN", "mitigation_ids": body["mitigation_ids"], "body": body}
    if outcome["result"] == "NO_MITIGATION" and outcome["status"] == "no_active_mitigation":
        return {"result": "NOTHING_FOUND", "mitigation_ids": [], "body": body}
    return {"result": "ERROR", "mitigation_ids": [], "body": body}


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
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
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
        # ADR 034 section 16: wrong-source, operator and legacy shared
        # credentials cannot ingest as fastnetmon.
        self.step("token-negative-controls", lambda: self.token_controls(manual), [])

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
        # A portless UDP flood must cover ports outside the service inventory.
        direct_rule = police(direct, 5_000_000, proto=17)

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
        # ("2001:0db8:0113::0010"); prefixd stores the canonical victim.
        ipv6_arg = "2001:0db8:0113::0010"
        ipv6_rule = police(ipv6, 1_000_000)

        def ipv6_ban():
            m = self.banned(lambda: self.api_client("ban", ipv6), ipv6_arg, "07-ipv6-api-ban")
            assert m["dst_prefix"] == f"{ipv6}/128", m
            assert m["victim_ip"] == ipv6, m
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
        detected_rule = police(detected, 5_000_000, proto=17)

        def detect():
            senders = []

            # The trigger, so banned() reads the script-log cursor before any
            # flow is sent and cannot skip a ban logged in the meantime.
            def flood():
                command = [sys.executable, "-I", str(NETFLOW), self.collector, detected]
                command += ["--seconds", str(DETECT_SECONDS)]
                self.log("$ " + " ".join(command))
                senders.append(subprocess.Popen(command))

            try:
                m = self.banned(flood, detected, "09-detected-ban")
            finally:
                for sender in senders:
                    sender.terminate()
                    sender.wait(timeout=10)
            self.check(m, "udp_flood", "police", 5_000_000)
            check_udp_flood_coverage(m, 80)
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
            # The detector unban withdraws as the script's ingest token.
            withdrawals = [e for e in audit if e["action"] == "withdraw"]
            assert len(withdrawals) == 1, audit
            withdrawal = withdrawals[0]
            assert (withdrawal["actor_type"], withdrawal["actor_id"]) == (
                "detector",
                "token:fnm-script",
            ), withdrawal
            assert withdrawal["details"]["reason"].endswith("Detector unban: fastnetmon"), (
                withdrawal
            )
            self.steps[-1]["withdraw_actor"] = withdrawal["actor_id"]
            # FastNetMon's timer passes the ban's direction; the unban event keeps it.
            unbans = [
                e
                for e in self.api("GET", "/v1/events?source=fastnetmon&limit=100")["events"]
                if e["action"] == "unban" and e["victim_ip"] == detected
            ]
            assert [e["raw_details"]["direction"] for e in unbans] == ["incoming"], unbans
            bans = [
                line
                for line in self.script_log()
                if line.startswith(f"Sending ban for {detected} ")
            ]
            assert len(bans) == 1, f"FastNetMon banned {detected} again: {bans}"

        self.step("detected-timer-unban", timer_unban, [])

    def token_controls(self, victim):
        """Wrong-source/operator tokens get 403 and a legacy bearer gets 401;
        none may store an event or mitigation."""
        wrong = Path(self.args.wrong_token_file).read_text().strip()
        event = {
            "event_id": "lane-token-control",
            "timestamp": "2026-11-16T00:00:00Z",
            "source": "fastnetmon",
            "victim_ip": victim,
            "vector": "udp_flood",
            "confidence": 0.9,
        }
        for label, token, expected in (
            ("wrong-source ingest token", wrong, 403),
            ("operator token", self.token, 403),
            ("legacy shared bearer", "fixture-legacy-shared-bearer", 401),
        ):
            request = urllib.request.Request(
                self.args.api + "/v1/events", data=json.dumps(event).encode(), method="POST"
            )
            request.add_header("Authorization", f"Bearer {token}")
            request.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    status, text = response.status, response.read().decode()
            except urllib.error.HTTPError as error:
                status, text = error.code, error.read().decode()
            self.log(f"POST /v1/events as {label} -> {status}")
            assert status == expected, (label, status, text)
        events = self.api("GET", "/v1/events?source=fastnetmon&limit=100")["events"]
        assert not [e for e in events if e["external_event_id"] == "lane-token-control"], events
        mitigations = self.api("GET", f"/v1/mitigations?victim_ip={victim}")["mitigations"]
        assert not mitigations, mitigations

    def event(self, event_id):
        events = self.api("GET", "/v1/events?source=fastnetmon&limit=100")["events"]
        found = [e for e in events if e["event_id"] == event_id]
        assert found, f"event {event_id} not in prefixd's event list"
        return found[0]

    def versions(self):
        found = super().versions()
        found["fastnetmon_packages"] = subprocess.run(
            [
                "docker",
                "exec",
                self.args.fastnetmon,
                "dpkg-query",
                "-W",
                "fastnetmon",
                "curl",
                "jq",
            ],
            check=True,
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
        "wrong-token-file",
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
