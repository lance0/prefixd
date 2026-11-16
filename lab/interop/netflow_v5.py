#!/usr/bin/env python3
"""Send a synthetic UDP flood toward one victim as NetFlow v5 records.

    python3 -I lab/interop/netflow_v5.py COLLECTOR:PORT VICTIM [--packets N] [--seconds N]

Each one-second export carries one datagram of 20 flow records, each claiming
PACKETS packets of 512 bytes from a different documentation-range source on
UDP port 40000 + i to the victim's port 80: PACKETS * 20 UDP packets per
export. NetFlow v5 is fixed-format (Cisco's
published layout), so the generator needs nothing beyond the standard library.
It stops after --seconds; the lane terminates it once the ban lands.
"""

import argparse
import socket
import struct
import time

HEADER = struct.Struct("!HHIIIIBBH")
RECORD = struct.Struct("!4s4s4sHHIIIIHHBBBBHHBBH")
RECORDS = 20


def datagram(victim, sequence, packets, uptime_ms):
    now = time.time()
    header = HEADER.pack(5, RECORDS, uptime_ms, int(now), int(now % 1 * 1e9), sequence, 0, 0, 0)
    records = b"".join(
        RECORD.pack(
            socket.inet_aton(f"198.51.100.{i + 1}"),
            socket.inet_aton(victim),
            socket.inet_aton("0.0.0.0"),
            1,  # input ifIndex
            2,  # output ifIndex
            packets,
            packets * 512,
            max(uptime_ms - 1000, 0),  # first
            uptime_ms,  # last: a one-second flow
            40000 + i,
            80,
            0,  # pad
            0,  # TCP flags
            17,  # UDP
            0,  # ToS
            64496,
            64500,
            24,
            32,
            0,
        )
        for i in range(RECORDS)
    )
    return header + records


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("collector", help="host:port")
    parser.add_argument("victim")
    parser.add_argument("--packets", type=int, default=1000, help="packets per record per second")
    parser.add_argument("--seconds", type=int, default=60)
    args = parser.parse_args()
    host, port = args.collector.rsplit(":", 1)
    started = time.monotonic()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for sequence in range(args.seconds):
            uptime = int((time.monotonic() - started) * 1000) + 1000
            sock.sendto(
                datagram(args.victim, sequence * RECORDS, args.packets, uptime), (host, int(port))
            )
            time.sleep(1)


if __name__ == "__main__":
    main()
