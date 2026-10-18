#!/usr/bin/env python3
"""Drive prefixd's HTTP API and assert FRR's received FlowSpec tables.

Invoked by run-frr.sh against a deployed frr-<speaker>.clab.yml lab. Each step
changes prefixd intent, then waits until FRR's IPv4 and IPv6 FlowSpec tables
equal the exact expected rule set: destination, protocol, destination port and
traffic-rate action. Exact-content comparison follows rustbgpd's M22
controller oracle (tests/interop/scripts/m22_flowspec_controller.py).

The receipt directory gets receipt.json, summary.md, commands.log and raw FRR
JSON before and after every step. Secrets are never written to it.
"""

import argparse
import datetime
import difflib
import json
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path

FAMILIES = ("ipv4", "ipv6")
SPEAKER_ADDRESS = "10.0.0.1"
MATCH_FIELDS = ("to", "proto", "dstp")
CONVERGE_SECONDS = 60


def rule(family, to, proto, dstp, rate_bytes):
    """One rule as FRR 10.7 renders it; discard is a zero traffic rate."""
    return {"family": family, "to": to, "proto": f"={proto}", "dstp": f"={dstp}",
            "action": f"FS:rate {rate_bytes:.6f}"}


def _compact(key, value):
    """FRR pads operators ("= 17 "); the destination keeps its own spelling."""
    return value if key == "to" or not isinstance(value, str) else re.sub(r"\s+", "", value)


def key(row):
    return json.dumps(row, sort_keys=True)


def ordered(rules):
    return sorted(rules, key=key)


def parse_frr(family, table_text, detail_text):
    """Normalize `show bgp <family> flowspec [detail] json` into sorted rules.

    Every route must have exactly one valid best path from the speaker, and the
    table and detail views must describe the same rules. Unexpected match
    components are kept so they appear in the diff rather than being dropped.
    """
    table = json.loads(table_text)
    routes = table.get("routes") or {}
    assert table.get("totalRoutes", 0) == len(routes), ("route count mismatch", table)
    table_rules = []
    for nlri, paths in routes.items():
        assert len(paths) == 1, ("expected one path", nlri, paths)
        path = paths[0]
        assert path.get("valid") and path.get("bestpath"), ("path not valid best", nlri, path)
        assert path.get("peerId") == SPEAKER_ADDRESS, ("unexpected peer", nlri, path)
        table_rules.append({k: _compact(k, path[k]) for k in MATCH_FIELDS if k in path})

    decoder = json.JSONDecoder()
    detail_rules = []
    text = detail_text
    while text.strip():
        text = text.lstrip()
        parts, end = decoder.raw_decode(text)
        text = text[end:]
        components = {k: _compact(k, v) for k, v in parts[0].items()}
        action = next((p["ecomlist"] for p in parts[1:] if "ecomlist" in p), None)
        detail_rules.append(dict(components, family=family, action=action))

    stripped = [{k: v for k, v in r.items() if k in MATCH_FIELDS} for r in detail_rules]
    assert sorted(map(key, stripped)) == sorted(map(key, table_rules)), (
        "table and detail views disagree", table_rules, detail_rules)
    return ordered(detail_rules)


def diff(expected, observed):
    want = json.dumps(ordered(expected), indent=2, sort_keys=True).splitlines()
    got = json.dumps(ordered(observed), indent=2, sort_keys=True).splitlines()
    return "\n".join(difflib.unified_diff(want, got, "expected", "frr", lineterm=""))


class Lab:
    def __init__(self, args):
        self.args = args
        self.receipt = Path(args.receipt)
        (self.receipt / "frr").mkdir(parents=True, exist_ok=True)
        self.token = Path(args.token_file).read_text().strip()
        self.commands = (self.receipt / "commands.log").open("a")
        self.steps = []
        self.step_no = 0

    def log(self, line):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")
        self.commands.write(f"{stamp} {line}\n")
        self.commands.flush()

    def run(self, *command, check=True):
        self.log("$ " + " ".join(command))
        return subprocess.run(command, check=check, text=True, capture_output=True, timeout=60).stdout

    def api(self, method, path, body=None, expect=(200, 201, 202)):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(self.args.api + path, data=data, method=method)
        request.add_header("Authorization", f"Bearer {self.token}")
        request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                status, text = response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            status, text = error.code, error.read().decode()
        self.log(f"{method} {path} {json.dumps(body) if body is not None else ''} -> {status}")
        assert status in expect, (method, path, status, text)
        return json.loads(text) if text else None

    def metric(self, name):
        with urllib.request.urlopen(self.args.api.rstrip("/") + "/metrics", timeout=10) as response:
            text = response.read().decode()
        match = re.search(rf"^{re.escape(name)} (\S+)$", text, re.M)
        return float(match.group(1)) if match else 0.0

    def vtysh(self, command):
        # Polled every second, so not logged per call; scenario() logs them once.
        return subprocess.run(["docker", "exec", self.args.frr, "vtysh", "-c", command],
                              check=True, text=True, capture_output=True, timeout=60).stdout

    def frr_rules(self, label):
        """Read both families once, save the raw JSON under label, return rules."""
        observed = []
        for family in FAMILIES:
            table = self.vtysh(f"show bgp {family} flowspec json")
            detail = self.vtysh(f"show bgp {family} flowspec detail json")
            path = self.receipt / "frr" / f"{label}-{family}.json"
            path.write_text(table.rstrip() + "\n")
            path.with_name(f"{label}-{family}-detail.json").write_text(detail)
            observed += parse_frr(family, table, detail)
        return observed

    def wait_frr(self, label, expected, seconds=CONVERGE_SECONDS):
        """Poll until FRR holds exactly the expected rules; the last poll is kept."""
        deadline = time.monotonic() + seconds
        want = ordered(expected)
        while True:
            try:
                observed = ordered(self.frr_rules(label))
                if observed == want:
                    return observed
                problem = diff(want, observed)
            except (AssertionError, ValueError, subprocess.SubprocessError) as error:
                problem = repr(error)
            if time.monotonic() >= deadline:
                raise AssertionError(f"{label}: FRR did not converge within {seconds}s\n{problem}")
            time.sleep(1)

    def step(self, name, action, expected, seconds=CONVERGE_SECONDS):
        self.step_no += 1
        label = f"{self.step_no:02d}-{name}"
        print(f"[{label}] start", flush=True)
        self.frr_rules(f"{label}-before")
        started = time.monotonic()
        record = {"step": label, "expected": expected}
        self.steps.append(record)
        result = action()
        self.wait_frr(f"{label}-after", expected, seconds)
        record.update(result="pass", seconds=round(time.monotonic() - started, 1))
        print(f"[{label}] PASS in {record['seconds']}s", flush=True)
        return result

    def mitigate(self, body):
        return self.api("POST", "/v1/mitigations", body, expect=(201,))["mitigation_id"]

    def status(self, mitigation_id):
        return self.api("GET", f"/v1/mitigations/{mitigation_id}")["status"]

    def wait_ready(self):
        deadline = time.monotonic() + 90
        while True:
            try:
                state = json.loads(self.vtysh(f"show bgp neighbors {SPEAKER_ADDRESS} json"))
                if (state[SPEAKER_ADDRESS]["bgpState"] == "Established"
                        and self.api("GET", "/v1/health")["status"] == "ok"):
                    return
            except (AssertionError, KeyError, ValueError, OSError, subprocess.SubprocessError):
                pass
            assert time.monotonic() < deadline, "speaker session or prefixd API not ready within 90s"
            time.sleep(2)

    def versions(self):
        def out(*command):
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            return (result.stdout.strip() or result.stderr.strip()).splitlines()[0]
        speaker = (["rustbgpd", "--version"] if self.args.speaker == "rustbgpd"
                   else ["/usr/local/bin/gobgpd", "--version"])
        images = re.findall(r"^\s+image:\s*(\S+)", Path(self.args.topology).read_text(), re.M)
        return {
            "prefixd": self.api("GET", "/v1/health")["version"],
            "prefixd_commit": out("git", "rev-parse", "HEAD"),
            "prefixd_image_id": out("docker", "image", "inspect", "-f", "{{.Id}}", "prefixd:interop"),
            "speaker": out("docker", "exec", self.args.speaker_container, *speaker),
            "frr": out("docker", "exec", self.args.frr, "vtysh", "-c", "show version"),
            "containerlab": out("containerlab", "version", "--short"),
            "kernel": out("uname", "-sr"),
            "topology": self.args.topology,
            "images": images,
        }

    def scenario(self):
        speaker = self.args.speaker_container
        police = rule("ipv4", "203.0.113.20/32", 6, 80, 1_000_000)
        detector = rule("ipv4", "203.0.113.30/32", 17, 123, 625_000)
        discard = rule("ipv4", "203.0.113.10/32", 17, 53, 0)
        expiring = rule("ipv4", "203.0.113.40/32", 17, 53, 0)
        ipv6 = rule("ipv6", "2001:db8:113::10/128/off 0", 17, 53, 0)

        for family in FAMILIES:
            self.log(f"polled: docker exec {self.args.frr} vtysh -c 'show bgp {family} flowspec [detail] json'")
        self.wait_frr("00-baseline", [])

        m_discard = self.step("manual-discard", lambda: self.mitigate({
            "reason": "interop manual discard", "victim_ip": "203.0.113.10", "protocol": "udp",
            "dst_ports": [53], "action": "discard", "ttl_seconds": 1800}), [discard])
        m_police = self.step("manual-police", lambda: self.mitigate({
            "reason": "interop manual police", "victim_ip": "203.0.113.20", "protocol": "tcp",
            "dst_ports": [80], "action": "police", "rate_bps": 8_000_000, "ttl_seconds": 1800}),
            [discard, police])

        def detect():
            event = self.api("POST", "/v1/events", {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "source": "fastnetmon", "victim_ip": "203.0.113.30", "vector": "udp_flood",
                "bps": 900_000_000, "pps": 500_000, "confidence": 0.9,
                "top_dst_ports": [123], "action": "ban"}, expect=(202,))
            assert event["status"] == "accepted" and event.get("mitigation_id"), event
            detail = self.api("GET", f"/v1/mitigations/{event['mitigation_id']}")
            assert (detail["action_type"], detail["rate_bps"]) == ("police", 5_000_000), detail
            return event["mitigation_id"]
        m_detector = self.step("detector-event", detect, [discard, police, detector])

        self.step("operator-withdrawal", lambda: self.api(
            "POST", f"/v1/mitigations/{m_discard}/withdraw", {"reason": "interop withdrawal"}),
            [police, detector])
        assert self.status(m_discard) == "withdrawn"

        def expire():
            mitigation = self.mitigate({
                "reason": "interop ttl expiry", "victim_ip": "203.0.113.40", "protocol": "udp",
                "dst_ports": [53], "action": "discard", "ttl_seconds": 15})
            self.wait_frr(f"{self.step_no:02d}-ttl-expiry-announced", [police, detector, expiring])
            return mitigation
        m_expiring = self.step("ttl-expiry", expire, [police, detector], seconds=90)
        assert self.status(m_expiring) == "expired"

        repairs = 'prefixd_reconciliation_repairs_total{status="success"}'
        def restart():
            before = self.metric(repairs)
            self.run("docker", "stop", speaker)
            self.wait_frr(f"{self.step_no:02d}-speaker-restart-stopped", [])
            self.run("docker", "start", speaker)
            return before
        before = self.step("speaker-restart", restart, [police, detector], seconds=120)
        repaired = self.metric(repairs) - before
        assert repaired >= 2, f"expected prefixd re-injection of 2 rules, repairs metric moved {repaired}"
        self.steps[-1]["reconciliation_repairs"] = repaired

        m_ipv6 = self.step("ipv6-discard", lambda: self.mitigate({
            "reason": "interop ipv6 discard", "victim_ip": "2001:db8:113::10", "protocol": "udp",
            "dst_ports": [53], "action": "discard", "ttl_seconds": 1800}), [police, detector, ipv6])

        def withdraw_all():
            for mitigation in (m_police, m_detector, m_ipv6):
                self.api("POST", f"/v1/mitigations/{mitigation}/withdraw", {"reason": "interop cleanup"})
        self.step("withdraw-all", withdraw_all, [])

    def main(self):
        receipt = {"date_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
                   "speaker": self.args.speaker, "result": "fail",
                   "scope": "control-plane receipt of prefixd intent in FRR's BGP FlowSpec table; "
                            "no dataplane or forwarding claim"}
        try:
            self.wait_ready()
            receipt["versions"] = self.versions()
            self.scenario()
            receipt["result"] = "pass"
        except Exception as error:  # record every failure in the receipt, then fail
            receipt["failure"] = str(error)
            if self.steps and "result" not in self.steps[-1]:
                self.steps[-1]["result"] = "fail"
            print(f"FAIL: {error}", flush=True)
        finally:
            receipt["steps"] = self.steps
            (self.receipt / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
            self.summary(receipt)
        return receipt["result"] == "pass"

    def summary(self, receipt):
        versions = receipt.get("versions", {})
        lines = [f"### FlowSpec interop: prefixd -> {receipt['speaker']} -> FRR ({receipt['result']})", "",
                 f"{receipt['date_utc']}; prefixd {versions.get('prefixd', '?')} "
                 f"({versions.get('prefixd_commit', '?')[:12]}); speaker {versions.get('speaker', '?')}; "
                 f"{versions.get('frr', '?')}", "", "| step | result | seconds |", "|---|---|---|"]
        lines += [f"| {s['step']} | {s.get('result', 'not reached')} | {s.get('seconds', '')} |"
                  for s in receipt["steps"]]
        if "failure" in receipt:
            lines += ["", "```diff", receipt["failure"], "```"]
        (self.receipt / "summary.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    for name in ("speaker", "api", "token-file", "frr", "speaker-container", "topology", "receipt"):
        parser.add_argument(f"--{name}", required=True)
    raise SystemExit(0 if Lab(parser.parse_args()).main() else 1)


if __name__ == "__main__":
    main()
