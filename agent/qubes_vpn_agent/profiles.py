"""VPN profiles: the files under ``/rw/config/vpn``.

* WireGuard: ``wireguard/<name>.conf`` (wg-quick format);
* OpenVPN: ``openvpn/<name>.ovpn`` or ``openvpn/<name>.conf``, with any files it
  names (certificates) beside it, and the username and password in
  ``openvpn/<name>.auth`` or ``openvpn/default.auth`` (see ``openvpn``).

A profile's name is its file name without the extension. It is the argument of
``vpn.Connect+<name>``, so it is held to the same strict pattern on the way in
as on the way out: a file whose name does not match is not a profile.
"""

from __future__ import annotations

import dataclasses
import os
import re

WIREGUARD = "wireguard"
OPENVPN = "openvpn"
PROTOCOLS = (WIREGUARD, OPENVPN)

#: Also the limit on what qrexec passes after ``vpn.Connect+``.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
MAX_PROFILES = 200

_EXTENSIONS = {WIREGUARD: (".conf",), OPENVPN: (".ovpn", ".conf")}


@dataclasses.dataclass(frozen=True)
class Profile:
    name: str
    protocol: str
    path: str


class ProfileError(Exception):
    """``code`` is the agent's error code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def valid_name(name: str) -> bool:
    return bool(NAME_RE.match(name)) and not name.endswith(".")


def list_profiles(wireguard_dir: str, openvpn_dir: str) -> list[Profile]:
    """Every profile, sorted by name then protocol."""
    found = []
    for protocol, directory in ((WIREGUARD, wireguard_dir), (OPENVPN, openvpn_dir)):
        try:
            entries = os.listdir(directory)
        except (FileNotFoundError, NotADirectoryError):
            continue
        for entry in entries:
            stem, ext = os.path.splitext(entry)
            if ext not in _EXTENSIONS[protocol] or not valid_name(stem):
                continue
            path = os.path.join(directory, entry)
            if os.path.isfile(path) and not os.path.islink(path):
                found.append(Profile(stem, protocol, path))
    found.sort(key=lambda p: (p.name, p.protocol, p.path))
    return found[:MAX_PROFILES]


def find_profile(name: str, wireguard_dir: str, openvpn_dir: str) -> Profile:
    """The profile called ``name``. Raises ProfileError with the reason."""
    if not valid_name(name):
        raise ProfileError("bad-argument")
    matches = [p for p in list_profiles(wireguard_dir, openvpn_dir) if p.name == name]
    if not matches:
        raise ProfileError("unknown-profile")
    if len(matches) > 1:
        raise ProfileError("ambiguous-profile")
    return matches[0]
