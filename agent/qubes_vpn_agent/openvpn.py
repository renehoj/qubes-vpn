"""OpenVPN: systemd, read back over the management interface.

``qubes-vpn-openvpn.service`` runs ``openvpn --config <profile>`` with the
options that make it the agent's tunnel, after the profile's own, so they win:
interface ``vpn-tun``, ``--management /run/openvpn/mgmt.sock unix``, and the
agent as ``--up``/``--down`` script (``openvpn-event``), which picks the DNS
servers out of what the server pushed. Pushed IPv6 is filtered out, as for
WireGuard.

The management interface answers ``state`` (where the connection is) and
``status`` (byte counts). ``bytecount`` is not used: it only turns on
real-time ``>BYTECOUNT`` notices, and waiting for one would hold up every
``vpn.Stats`` call.

Credentials: providers such as ProtonVPN ship ``.ovpn`` files with a bare
``auth-user-pass``, which makes OpenVPN ask on a terminal it does not have.
The username and password go in a file beside the profiles instead, in
OpenVPN's own format (username on the first line, password on the second):
``openvpn/<profile>.auth`` for one profile, else ``openvpn/default.auth`` for
all of them. The agent hands that file to OpenVPN with ``--auth-user-pass``,
which overrides the profile's own line. ``vpn-agent credentials [<profile>]``
writes it.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time

PROTOCOL = "openvpn"
INTERFACE = "vpn-tun"
UNIT = "qubes-vpn-openvpn.service"
MAX_REPLY = 64 * 1024
DEFAULT_CREDENTIALS = "default"
CREDENTIALS_EXT = ".auth"

#: OpenVPN's states (management ``state``), as the agent reports them.
STATES = {
    "CONNECTED": "connected",
    "EXITING": "disconnecting",
}
CONNECTING = "connecting"


def credentials_path(directory: str, name: str = DEFAULT_CREDENTIALS) -> str:
    return os.path.join(directory, name + CREDENTIALS_EXT)


def find_credentials(directory: str, profile: str) -> str | None:
    """The credentials file for ``profile``: its own, else the default one."""
    for name in (profile, DEFAULT_CREDENTIALS):
        path = credentials_path(directory, name)
        if os.path.isfile(path) and not os.path.islink(path):
            return path
    return None


def asks_for_credentials(profile_text: str) -> bool:
    """Whether the profile has a bare ``auth-user-pass`` (OpenVPN would prompt)."""
    for line in profile_text.splitlines():
        words = line.split("#", 1)[0].split(";", 1)[0].split()
        if words == ["auth-user-pass"]:
            return True
    return False


def valid_credentials(text: str) -> bool:
    """A username and a password, each on its own line, neither empty."""
    lines = text.splitlines()
    return len(lines) >= 2 and all(lines[:2]) and "\0" not in text


def format_credentials(username: str, password: str) -> str:
    if not username or not password or any(c in username + password for c in "\r\n\0"):
        raise ValueError("username and password must be one non-empty line each")
    return f"{username}\n{password}\n"


class ManagementError(Exception):
    pass


class Management:
    """One command at a time over the management socket."""

    def __init__(self, path: str, timeout: float = 2.0):
        self.path = path
        self.timeout = timeout

    def command(self, command: str) -> list[str]:
        """The reply lines up to ``END`` (or the one SUCCESS/ERROR line).

        Real-time notices (lines starting ``>``) are skipped wherever they come.
        """
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                sock.connect(self.path)
                sock.sendall(command.encode("ascii") + b"\n")
                return self._read_reply(sock)
        except OSError as exc:
            raise ManagementError(str(exc)) from exc

    def _read_reply(self, sock: socket.socket) -> list[str]:
        buffer = b""
        lines: list[str] = []
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > MAX_REPLY:
                raise ManagementError("reply too long")
            *complete, buffer = buffer.split(b"\n")
            for raw in complete:
                line = raw.decode("utf-8", "replace").rstrip("\r")
                if line.startswith(">"):
                    continue
                if line == "END":
                    return lines
                if line.startswith(("SUCCESS:", "ERROR:")) and not lines:
                    return [line]
                lines.append(line)
        raise ManagementError("no complete reply")

    def state(self) -> dict[str, str]:
        return parse_state(self.command("state"))

    def status(self) -> dict[str, int]:
        return parse_status(self.command("status"))


def parse_state(lines: list[str]) -> dict[str, str]:
    """The latest ``state`` line: ``time,STATE,detail,local_ip,remote_ip,remote_port,...``."""
    for line in reversed(lines):
        fields = line.split(",")
        if len(fields) >= 2 and fields[0].isdigit():
            info = {"name": fields[1]}
            if len(fields) > 3 and fields[3]:
                info["local_ip"] = fields[3]
            if len(fields) > 5 and fields[4]:
                info["remote_ip"] = fields[4]
                info["remote_port"] = fields[5]
            return info
    return {}


def parse_status(lines: list[str]) -> dict[str, int]:
    """The ``key,number`` lines of ``status`` (client mode, format 1)."""
    counts = {}
    for line in lines:
        key, sep, value = line.partition(",")
        if sep and value.isdigit():
            counts[key] = int(value)
    return counts


def probe(mgmt: Management) -> dict[str, object]:
    """State, endpoint, tunnel address and link byte counts; {} without a socket."""
    try:
        state = mgmt.state()
        counts = mgmt.status()
    except ManagementError:
        return {}
    name = state.get("name", "")
    info: dict[str, object] = {"state": STATES.get(name, CONNECTING)}
    if state.get("local_ip"):
        info["tunnel_ip"] = state["local_ip"]
    if state.get("remote_ip"):
        info["endpoint"] = f"{state['remote_ip']}:{state.get('remote_port', '')}".rstrip(":")
    info["link_rx_bytes"] = counts.get("TCP/UDP read bytes")
    info["link_tx_bytes"] = counts.get("TCP/UDP write bytes")
    return info


def pushed_dns(env: dict[str, str]) -> list[str]:
    """IPv4 DNS servers the server pushed, in order.

    OpenVPN 2.5 and older: ``foreign_option_<n>=dhcp-option DNS <ip>``;
    2.6 also ``dns_server_<n>_address_<m>=<ip>`` (the ``--dns`` option).
    """
    found: list[tuple[tuple[int, ...], str]] = []
    for key, value in env.items():
        if key.startswith("foreign_option_"):
            parts = value.split()
            if len(parts) == 3 and parts[0] == "dhcp-option" and parts[1].upper() == "DNS":
                found.append(((0, _number(key[15:])), parts[2]))
        elif key.startswith("dns_server_") and "_address_" in key:
            server, _sep, address = key[11:].partition("_address_")
            found.append(((1, _number(server), _number(address)), value.strip()))
    servers = []
    for _order, value in sorted(found):
        try:
            if ipaddress.ip_address(value).version == 4 and value not in servers:
                servers.append(value)
        except ValueError:
            continue
    return servers


def _number(text: str) -> int:
    return int(text) if text.isdigit() else 0
