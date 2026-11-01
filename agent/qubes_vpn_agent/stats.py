"""Traffic counters: the tunnel interface and every downstream qube's vif.

The kernel's counters (``/sys/class/net/<if>/statistics``) are read as they
are; the manager computes speeds from the difference between two calls.

A downstream qube is behind ``vif<domid>.0``, with a host route to its address
on that interface. Seen from here, ``rx`` on a vif is what that qube sent
(its upload) and ``tx`` what it received.
"""

from __future__ import annotations

import os
import re
import socket
import struct

COUNTERS = ("rx_bytes", "tx_bytes", "rx_packets", "tx_packets")
MAX_VIFS = 256
_PING_TIME = re.compile(r"time[=<]([0-9.]+) ?ms")


def read_counters(sys_net: str, interface: str) -> dict[str, int] | None:
    """The interface's counters, or None when it does not exist."""
    directory = os.path.join(sys_net, interface, "statistics")
    if not os.path.isdir(directory):
        return None
    counters = {}
    for name in COUNTERS:
        try:
            with open(os.path.join(directory, name), encoding="ascii") as handle:
                counters[name] = int(handle.read().strip())
        except (OSError, ValueError):
            continue
    return counters


def vif_addresses(route_text: str) -> dict[str, str]:
    """``{interface: IPv4}`` from the host routes in ``/proc/net/route``."""
    found = {}
    for line in route_text.splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or not fields[0].startswith("vif"):
            continue
        if fields[7] != "FFFFFFFF":
            continue
        try:
            address = socket.inet_ntoa(struct.pack("<I", int(fields[1], 16)))
        except (ValueError, struct.error):
            continue
        found.setdefault(fields[0], address)
    return found


def vif_counters(sys_net: str, route_text: str) -> list[tuple[str, int, int]]:
    """``(address, rx_bytes, tx_bytes)`` per downstream qube, by address."""
    rows = []
    for interface, address in vif_addresses(route_text).items():
        counters = read_counters(sys_net, interface)
        if counters and "rx_bytes" in counters and "tx_bytes" in counters:
            rows.append((address, counters["rx_bytes"], counters["tx_bytes"]))
    rows.sort(key=lambda row: socket.inet_aton(row[0]))
    return rows[:MAX_VIFS]


def parse_ping(text: str) -> float | None:
    """The round-trip time in ``ping`` output, in ms."""
    match = _PING_TIME.search(text)
    return float(match.group(1)) if match else None
