"""Where the agent keeps things, and how it runs commands.

Everything that touches the qube goes through :class:`Paths` and
:class:`Runner`, so the tests can point the agent at a temporary directory and
a fake command table instead of the real ``/rw``, ``/sys`` and ``systemctl``.

Persistence: an AppVM's root filesystem is reset at every start. The agent's
code and systemd units live in the template (``install.sh --template``) or in
``/usr/local`` (``install.sh --appvm``); profiles and keys live in
``/rw/config/vpn``, which survives; what the agent writes at run time lives in
``/run/qubes-vpn``, which is meant to vanish.
"""

from __future__ import annotations

import dataclasses
import os
import subprocess


@dataclasses.dataclass(frozen=True)
class Paths:
    """The agent's files. Defaults are the real ones."""

    config: str = "/rw/config/vpn"
    run: str = "/run/qubes-vpn"
    mgmt_socket: str = "/run/openvpn/mgmt.sock"
    sys_net: str = "/sys/class/net"
    proc_route: str = "/proc/net/route"

    @classmethod
    def under(cls, root: str) -> "Paths":
        """The same layout below ``root`` (tests)."""
        return cls(**{field.name: os.path.join(root, getattr(cls, field.name).lstrip("/"))
                      for field in dataclasses.fields(cls)})

    @property
    def wireguard_dir(self) -> str:
        return os.path.join(self.config, "wireguard")

    @property
    def openvpn_dir(self) -> str:
        return os.path.join(self.config, "openvpn")

    @property
    def agent_conf(self) -> str:
        return os.path.join(self.config, "agent.conf")

    @property
    def active(self) -> str:
        """The connection the agent started: protocol, profile, since, DNS."""
        return os.path.join(self.run, "active.json")

    @property
    def wg_conf(self) -> str:
        """wg-quick's copy of the profile; its name is the interface name."""
        return os.path.join(self.run, "vpn-wg.conf")

    @property
    def openvpn_env(self) -> str:
        """Which profile qubes-vpn-openvpn.service runs (EnvironmentFile)."""
        return os.path.join(self.run, "openvpn.env")

    @property
    def latency(self) -> str:
        return os.path.join(self.run, "latency")

    @property
    def lock(self) -> str:
        return os.path.join(self.run, "lock")


@dataclasses.dataclass
class Result:
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


#: OpenVPN runs its up/down script with only its own variables, no PATH; Python
#: would then look in /bin:/usr/bin only and miss nft, ip and wg in /usr/sbin.
PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


class Runner:
    """Runs a command with a time limit; never raises for a failed command."""

    def run(self, argv: list[str], timeout: float = 15.0,
            input_text: str | None = None) -> Result:
        env = dict(os.environ, LC_ALL="C", PATH=PATH)
        try:
            proc = subprocess.run(argv, input=input_text, capture_output=True, text=True,
                                  timeout=timeout, check=False, env=env)
        except FileNotFoundError:
            return Result(127, "", f"{argv[0]}: not found")
        except subprocess.TimeoutExpired:
            return Result(124, "", f"{argv[0]}: timed out")
        return Result(proc.returncode, proc.stdout, proc.stderr)


def read_text(path: str, limit: int = 1 << 20) -> str | None:
    """The file's text, or None when it is not there."""
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except (FileNotFoundError, NotADirectoryError):
        return None


def write_private(path: str, text: str) -> None:
    """Write ``text`` to ``path`` atomically, readable by root only."""
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(tmp, path)


def remove(path: str) -> None:
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
