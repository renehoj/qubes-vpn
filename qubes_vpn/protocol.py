"""Reading what a VPN qube says: the agent's ``key=value`` output, distrusted.

A VPN qube talks to the internet, so whatever it answers may come from an
attacker who owns it. Nothing it sends is shown or used as it came:

* the whole answer is refused if it is longer than :data:`MAX_OUTPUT` bytes,
  has more than :data:`MAX_LINES` lines, or is not ASCII;
* a line longer than :data:`MAX_LINE`, or without ``=``, is dropped;
* only the keys of the service's schema are read; the rest are dropped;
* every value is checked against its key's type: numbers must be plain
  decimal numbers in range, states and protocols one of the known words,
  addresses must parse as addresses, names must match the profile pattern.
  A value that does not is dropped, never "cleaned up" into something else.

What comes out is plain Python values the window can show as they are. Error
codes are only ever shown through :data:`ERROR_TEXT`, or as "error" when the
code is unknown.
"""

from __future__ import annotations

import dataclasses
import ipaddress
import re
from typing import Callable

MAX_OUTPUT = 16 * 1024
MAX_LINES = 400
MAX_LINE = 256
MAX_VIFS = 256
MAX_PROFILES = 200
MAX_INT = 2 ** 64 - 1

PROTOCOLS = ("wireguard", "openvpn")
PROTOCOL_TEXT = {"wireguard": "WireGuard", "openvpn": "OpenVPN"}

DISCONNECTED = "disconnected"
CONNECTING = "connecting"
CONNECTED = "connected"
STALE = "stale"
DISCONNECTING = "disconnecting"
ERROR = "error"
STATES = (DISCONNECTED, CONNECTING, CONNECTED, STALE, DISCONNECTING, ERROR)

#: What the agent's error codes mean. Unknown codes are shown as "error".
ERROR_TEXT = {
    "bad-argument": "the profile name is not valid",
    "unknown-profile": "no such profile in the VPN qube",
    "ambiguous-profile": "a WireGuard and an OpenVPN profile have this name",
    "start-failed": "the tunnel did not start",
    "tunnel-failed": "the tunnel stopped with an error",
    "killswitch-failed": "the kill switch could not be set up, so the tunnel was not started",
    "interface-missing": "the tunnel interface is gone",
    "no-peer": "the WireGuard profile has no peer",
    "stopped": "the tunnel was stopped outside the VPN manager",
    "busy": "the VPN qube is busy with another connect or disconnect",
    "no-credentials": "the OpenVPN profile needs a username and password: run "
                      "vpn-agent credentials in the VPN qube",
    "bad-credentials": "the OpenVPN credentials file needs the username on line 1 "
                       "and the password on line 2",
    "not-root": "the agent does not run as root (policy needs user=root)",
    "internal": "the agent failed; see the VPN qube's journal",
}

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
QUBE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,30}$")
_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_INT_RE = re.compile(r"^[0-9]{1,20}$")
_DECIMAL_RE = re.compile(r"^[0-9]{1,6}(\.[0-9]{1,3})?$")
_CODE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,62})(\.[A-Za-z0-9-]{1,63})*$")
_INTERFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")


class ProtocolError(Exception):
    """The answer as a whole was refused."""


def valid_profile_name(name: str) -> bool:
    return bool(NAME_RE.match(name)) and not name.endswith(".")


def valid_qube_name(name: str) -> bool:
    return bool(QUBE_RE.match(name))


# -- value types ---------------------------------------------------------------
def _int(text: str) -> int | None:
    if not _INT_RE.match(text):
        return None
    value = int(text)
    return value if value <= MAX_INT else None


def _decimal(text: str) -> float | None:
    return float(text) if _DECIMAL_RE.match(text) else None


def _one_of(words: tuple[str, ...]) -> Callable[[str], str | None]:
    return lambda text: text if text in words else None


def _ip(text: str) -> str | None:
    try:
        return str(ipaddress.ip_address(text))
    except ValueError:
        return None


def _ipv4(text: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def _endpoint(text: str) -> str | None:
    """``host:port``, ``[v6]:port`` or a bare host."""
    host, port = text, None
    if text.startswith("["):
        host, sep, rest = text[1:].partition("]")
        if not sep or (rest and not rest.startswith(":")):
            return None
        port = rest[1:] or None
        if _ip(host) is None:
            return None
    elif text.count(":") == 1:
        host, port = text.split(":")
    elif text.count(":") > 1:
        return _ip(text)
    if port is not None and (not port.isdigit() or not 0 < int(port) < 65536):
        return None
    if _ip(host) is None and not _HOST_RE.match(host):
        return None
    return text


def _name(text: str) -> str | None:
    return text if valid_profile_name(text) else None


def _code(text: str) -> str | None:
    return text if _CODE_RE.match(text) else None


def _interface(text: str) -> str | None:
    return text if _INTERFACE_RE.match(text) else None


@dataclasses.dataclass(frozen=True)
class Vif:
    """A downstream qube's counters, seen from the VPN qube."""

    address: str
    rx_bytes: int
    tx_bytes: int


def _vif(text: str) -> Vif | None:
    parts = text.split(":")
    if len(parts) != 3:
        return None
    address, rx, tx = _ipv4(parts[0]), _int(parts[1]), _int(parts[2])
    if address is None or rx is None or tx is None:
        return None
    return Vif(address, rx, tx)


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    protocol: str


def _profile(text: str) -> Profile | None:
    name, sep, protocol = text.rpartition(":")
    if not sep or not valid_profile_name(name) or protocol not in PROTOCOLS:
        return None
    return Profile(name, protocol)


# -- schemas -------------------------------------------------------------------
_COMMON = {
    "result": _one_of(("ok", "error")),
    "error": _code,
    "protocol": _one_of(PROTOCOLS),
    "state": _one_of(STATES),
}

STATUS_SCHEMA = {
    **_COMMON,
    "profile": _name,
    "interface": _interface,
    "endpoint": _endpoint,
    "tunnel_ip": _ip,
    "since": _int,
    "dns": _ip,
    "handshake_age": _int,
    "killswitch": _one_of(("on", "off")),
}

STATS_SCHEMA = {
    **_COMMON,
    "rx_bytes": _int,
    "tx_bytes": _int,
    "rx_packets": _int,
    "tx_packets": _int,
    "link_rx_bytes": _int,
    "link_tx_bytes": _int,
    "handshake_age": _int,
    "uptime": _int,
    "latency_ms": _decimal,
}

PROFILES_SCHEMA = {
    "result": _COMMON["result"],
    "error": _code,
    "active": _name,
}

#: dom0's ``vpn.SetNetvm`` (the optional service).
SETNETVM_SCHEMA = {
    "result": _COMMON["result"],
    "error": _code,
}

#: Keys that may repeat, with their type and limit.
_REPEATED = {
    "vif": (_vif, MAX_VIFS),
    "profile": (_profile, MAX_PROFILES),
}


@dataclasses.dataclass
class Answer:
    """One service's answer, validated."""

    values: dict[str, object]
    vifs: list[Vif] = dataclasses.field(default_factory=list)
    profiles: list[Profile] = dataclasses.field(default_factory=list)
    #: Lines that were dropped (unknown key, bad value, too long).
    dropped: int = 0

    def get(self, key: str, default=None):
        return self.values.get(key, default)

    @property
    def error(self) -> str | None:
        return self.values.get("error")  # type: ignore[return-value]


def parse(data: bytes, schema: dict[str, Callable], repeated: tuple[str, ...] = ()) -> Answer:
    """Validate ``data`` against ``schema``; ``repeated`` names keys that repeat.

    A single key that comes twice keeps its first value.
    """
    if len(data) > MAX_OUTPUT:
        raise ProtocolError("the answer is too long")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        raise ProtocolError("the answer is not plain ASCII") from None
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    if len(lines) > MAX_LINES:
        raise ProtocolError("the answer has too many lines")
    answer = Answer({})
    for line in lines:
        key, sep, raw = line.rstrip("\r").partition("=")
        if not sep or len(line) > MAX_LINE or not _KEY_RE.match(key):
            answer.dropped += 1
            continue
        if key in repeated:
            check, limit = _REPEATED[key]
            target = answer.vifs if key == "vif" else answer.profiles
            value = check(raw)
            if value is None or len(target) >= limit:
                answer.dropped += 1
            else:
                target.append(value)
            continue
        check = schema.get(key)
        value = check(raw) if check is not None else None
        if value is None or key in answer.values:
            answer.dropped += 1
            continue
        answer.values[key] = value
    return answer


def parse_status(data: bytes) -> Answer:
    return parse(data, STATUS_SCHEMA)


def parse_stats(data: bytes) -> Answer:
    return parse(data, STATS_SCHEMA, repeated=("vif",))


def parse_profiles(data: bytes) -> Answer:
    return parse(data, PROFILES_SCHEMA, repeated=("profile",))


def parse_setnetvm(data: bytes) -> Answer:
    return parse(data, SETNETVM_SCHEMA)


def error_text(code: str | None) -> str:
    """What to show for an agent's error code; never the code's own text
    unless it is one this module knows."""
    if code is None:
        return ""
    return ERROR_TEXT.get(code, "the VPN qube reported an error")
