"""The manager's own settings and memory, in the vpn-manager qube's home.

``~/.config/qubes-vpn/config.ini``::

    [manager]
    # Seconds between polls, 2-5.
    poll_interval = 3
    # How a client qube gets a new net qube: "admin" (admin.vm.property.Set
    # +netvm) or "service" (dom0's vpn.SetNetvm, see docs/install.md).
    netvm_method = admin

``~/.local/state/qubes-vpn/profiles.json`` remembers the last profile each
VPN qube was connected to, for the tray's Connect and the profile list's
first choice. No keys or passwords are ever stored here: those stay in the
VPN qubes.
"""

from __future__ import annotations

import configparser
import dataclasses
import json
import os

from . import protocol
from .model import POLL_SECONDS

MIN_POLL, MAX_POLL = 2, 5
METHODS = ("admin", "service")


def _xdg(variable: str, *default: str) -> str:
    return os.environ.get(variable) or os.path.join(os.path.expanduser("~"), *default)


def config_path() -> str:
    return os.path.join(_xdg("XDG_CONFIG_HOME", ".config"), "qubes-vpn", "config.ini")


def state_path() -> str:
    return os.path.join(_xdg("XDG_STATE_HOME", ".local", "state"), "qubes-vpn", "profiles.json")


@dataclasses.dataclass
class Settings:
    poll_interval: int = POLL_SECONDS
    netvm_method: str = "admin"


def load(path: str | None = None) -> Settings:
    parser = configparser.ConfigParser()
    parser.read(path or config_path(), encoding="utf-8")
    section = parser["manager"] if parser.has_section("manager") else {}
    settings = Settings()
    try:
        settings.poll_interval = max(MIN_POLL, min(MAX_POLL, int(
            section.get("poll_interval", settings.poll_interval))))
    except ValueError:
        pass
    method = section.get("netvm_method", settings.netvm_method)
    if method in METHODS:
        settings.netvm_method = method
    return settings


class LastProfiles:
    """``{vpn qube: profile}``, kept between runs."""

    def __init__(self, path: str | None = None):
        self.path = path or state_path()
        self._data: dict[str, str] = {}
        try:
            with open(self.path, encoding="utf-8") as handle:
                data = json.load(handle)
        except (OSError, ValueError):
            data = {}
        if isinstance(data, dict):
            self._data = {k: v for k, v in data.items()
                          if isinstance(k, str) and isinstance(v, str)
                          and protocol.valid_qube_name(k) and protocol.valid_profile_name(v)}

    def get(self, vpn: str) -> str | None:
        return self._data.get(vpn)

    def set(self, vpn: str, profile: str) -> None:
        self._data[vpn] = profile
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump(self._data, handle, indent=1, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError:
            pass
