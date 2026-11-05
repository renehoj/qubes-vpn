"""What each qrexec service does, for both protocols.

:class:`Agent` is the one interface over WireGuard and OpenVPN: connect to a
profile, disconnect, report status and counters. Each method returns the
``key=value`` pairs the service prints (``output.render``).

The agent remembers the connection it started in ``/run/qubes-vpn/active.json``
(protocol, profile, start time, DNS servers); the tunnel itself is a systemd
unit per protocol. At most one tunnel runs at a time: connecting stops the
other unit first.

Connecting writes the kill switch table before it starts the tunnel, and
refuses to start one if nft fails.

Settings (``vpn.Configure+<key>``, :meth:`Agent.configure`): a fixed list of
keys, :data:`CONFIG_KEYS`, each with its own check. The value comes on stdin;
an empty value removes the setting. ``autoconnect`` and ``ping_target`` go in
``agent.conf``, rewritten in place (comments and other lines kept);
``credentials`` writes or removes an OpenVPN ``.auth`` file. Nothing is ever
read back but the names: ``vpn.ListProfiles`` says which profiles have
credentials stored, never what they are.
"""

from __future__ import annotations

import errno
import fcntl
import ipaddress
import json
import logging
import os
import time

from . import killswitch, openvpn, stats, wireguard
from .output import Pairs
from .profiles import (MAX_PROFILES, OPENVPN, PROTOCOLS, WIREGUARD, ProfileError,
                       find_profile, list_profiles, valid_name)
from .system import Paths, Runner, read_text, remove, write_private

LATENCY_TTL = 10.0
#: What ``vpn.Configure+<key>`` may set.
CONFIG_KEYS = ("autoconnect", "ping_target", "credentials")
#: Longest value ``vpn.Configure`` reads from stdin.
MAX_CONFIG_INPUT = 2048
LOCK_TIMEOUT = 45.0
DEFAULT_PING_TARGET = "1.1.1.1"

logger = logging.getLogger("qubes-vpn-agent")

_TUNNELS = {
    WIREGUARD: (wireguard.INTERFACE, wireguard.UNIT),
    OPENVPN: (openvpn.INTERFACE, openvpn.UNIT),
}


class AgentError(Exception):
    """``code`` is what the service reports as ``error=``."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Agent:
    def __init__(self, paths: Paths | None = None, runner: Runner | None = None,
                 clock=time.time, management: openvpn.Management | None = None):
        self.paths = paths or Paths()
        self.runner = runner or Runner()
        self.clock = clock
        self.management = management or openvpn.Management(self.paths.mgmt_socket)

    # -- services --------------------------------------------------------
    def list_profiles(self) -> Pairs:
        pairs: Pairs = [("profile", f"{p.name}:{p.protocol}") for p in self._profiles()]
        active = self._active()
        if active is not None:
            pairs.append(("active", active["profile"]))
        conf = self._conf()
        pairs.append(("autoconnect", conf.get("autoconnect") or None))
        pairs.append(("ping_target", conf.get("ping_target") or None))
        pairs += [("credentials", name) for name in self._stored_credentials()]
        return pairs

    def connect(self, name: str) -> Pairs:
        try:
            profile = find_profile(name, self.paths.wireguard_dir, self.paths.openvpn_dir)
        except ProfileError as exc:
            raise AgentError(exc.code) from None
        # A profile that is refused leaves the running tunnel alone.
        dns: list[str] = []
        if profile.protocol == WIREGUARD:
            text = read_text(profile.path, limit=64 * 1024)
            if text is None:
                raise AgentError("unknown-profile")
            path, (config, dns) = self.paths.wg_conf, wireguard.prepare_config(text)
        else:
            text = self._openvpn_profile(profile)
            path, config = self.paths.openvpn_env, (
                f"PROFILE={profile.path}\n"
                f"PROFILE_DIR={os.path.dirname(profile.path)}\n"
                f"AUTH_ARGS={self._openvpn_auth_args(profile, text)}\n")
        with self._locked():
            self._stop_tunnels()
            write_private(path, config)
            self._write_active({"protocol": profile.protocol, "profile": profile.name,
                                "since": self.clock(), "dns": dns})
            self._apply_killswitch(dns)
            unit = _TUNNELS[profile.protocol][1]
            # OpenVPN reports readiness only once connected; Status follows that.
            no_block = ["--no-block"] if profile.protocol == OPENVPN else []
            result = self.runner.run(["systemctl", "start", *no_block, unit], timeout=30)
            if not result.ok:
                self._clear_active()
                self._apply_killswitch([])
                raise AgentError("start-failed")
        return [("result", "ok"), *self.status()]

    def disconnect(self) -> Pairs:
        with self._locked():
            self._stop_tunnels()
            self._clear_active()
            self._apply_killswitch([])
        return [("result", "ok"), *self.status()]

    def status(self) -> Pairs:
        active = self._active()
        if active is None:
            return [("state", "disconnected"), ("killswitch", self._killswitch_state())]
        info = self._probe(active)
        dns = active.get("dns") or []
        return [
            ("protocol", active["protocol"]),
            ("state", info.get("state")),
            ("profile", active["profile"]),
            ("interface", _TUNNELS[active["protocol"]][0]),
            ("endpoint", info.get("endpoint")),
            ("tunnel_ip", info.get("tunnel_ip")),
            ("since", int(active["since"])),
            ("dns", dns[0] if dns else None),
            ("handshake_age", info.get("handshake_age")),
            ("killswitch", self._killswitch_state()),
            ("error", info.get("error")),
        ]

    def stats(self) -> Pairs:
        now = self.clock()
        active = self._active()
        pairs: Pairs = []
        if active is None:
            pairs.append(("state", "disconnected"))
        else:
            info = self._probe(active)
            interface = _TUNNELS[active["protocol"]][0]
            pairs += [("protocol", active["protocol"]), ("state", info.get("state"))]
            pairs += sorted((stats.read_counters(self.paths.sys_net, interface) or {}).items())
            pairs += [
                ("link_rx_bytes", info.get("link_rx_bytes")),
                ("link_tx_bytes", info.get("link_tx_bytes")),
                ("handshake_age", info.get("handshake_age")),
                ("uptime", max(0, int(now - active["since"]))),
            ]
            if info.get("state") == "connected":
                pairs.append(("latency_ms", self._latency(interface, active.get("dns") or [])))
        route_text = read_text(self.paths.proc_route) or ""
        for address, rx, tx in stats.vif_counters(self.paths.sys_net, route_text):
            pairs.append(("vif", f"{address}:{rx}:{tx}"))
        return pairs

    def apply_killswitch(self) -> Pairs:
        """At boot, and by hand: the table, with the DNS of a running tunnel."""
        active = self._active()
        self._apply_killswitch((active or {}).get("dns") or [])
        return [("result", "ok"), ("killswitch", self._killswitch_state())]

    def autoconnect(self) -> Pairs:
        """At boot: connect to ``autoconnect=<profile>`` in agent.conf, if set."""
        name = self._conf().get("autoconnect")
        if not name:
            return [("result", "ok"), ("state", "disconnected")]
        return self.connect(name)

    def set_credentials(self, profile: str | None, username: str, password: str) -> Pairs:
        """Write the OpenVPN username and password for ``profile``, or for all."""
        if profile is not None and not valid_name(profile):
            raise AgentError("bad-argument")
        try:
            text = openvpn.format_credentials(username, password)
        except ValueError:
            raise AgentError("bad-credentials") from None
        directory = self.paths.openvpn_dir
        path = openvpn.credentials_path(directory, profile or openvpn.DEFAULT_CREDENTIALS)
        os.makedirs(directory, mode=0o700, exist_ok=True)
        write_private(path, text)
        return [("result", "ok")]

    def configure(self, key: str, data: bytes) -> Pairs:
        """``vpn.Configure+<key>``: set ``key`` to the value on stdin (``data``).

        Answers ``result=ok`` and then what ``vpn.ListProfiles`` says, so the
        caller sees the new settings.
        """
        if key not in CONFIG_KEYS:
            raise AgentError("bad-argument")
        if len(data) > MAX_CONFIG_INPUT:
            raise AgentError("bad-value")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise AgentError("bad-value") from None
        if text.endswith("\n"):
            text = text[:-1]
        if any(c in text for c in "\r\0"):
            raise AgentError("bad-value")
        with self._locked():
            if key == "credentials":
                self._configure_credentials(text.split("\n"))
            else:
                if "\n" in text:
                    raise AgentError("bad-value")
                value = self._check_setting(key, text.strip())
                self._write_conf(key, value)
        return [("result", "ok"), *self.list_profiles()]

    def _check_setting(self, key: str, value: str) -> str | None:
        if not value:
            return None
        if key == "autoconnect":
            try:
                find_profile(value, self.paths.wireguard_dir, self.paths.openvpn_dir)
            except ProfileError as exc:
                raise AgentError(exc.code) from None
            return value
        try:
            return str(ipaddress.IPv4Address(value))
        except ValueError:
            raise AgentError("bad-value") from None

    def _configure_credentials(self, lines: list[str]) -> None:
        """``<profile or default>``, username, password; both empty: remove."""
        if len(lines) != 3:
            raise AgentError("bad-credentials")
        name, username, password = lines
        if name != openvpn.DEFAULT_CREDENTIALS:
            try:
                profile = find_profile(name, self.paths.wireguard_dir, self.paths.openvpn_dir)
            except ProfileError as exc:
                raise AgentError(exc.code) from None
            if profile.protocol != OPENVPN:
                raise AgentError("not-openvpn")
        if not username and not password:
            remove(openvpn.credentials_path(self.paths.openvpn_dir, name))
            return
        self.set_credentials(name, username, password)

    def _stored_credentials(self) -> list[str]:
        """The names with a credentials file: ``default`` and profile names."""
        try:
            entries = os.listdir(self.paths.openvpn_dir)
        except (FileNotFoundError, NotADirectoryError):
            return []
        names = []
        for entry in sorted(entries):
            stem, ext = os.path.splitext(entry)
            path = os.path.join(self.paths.openvpn_dir, entry)
            if ext == openvpn.CREDENTIALS_EXT and valid_name(stem) \
                    and os.path.isfile(path) and not os.path.islink(path):
                names.append(stem)
        return names[:MAX_PROFILES]

    def openvpn_event(self, env: dict[str, str]) -> Pairs:
        """OpenVPN's ``--up``/``--down`` script: follow the pushed DNS servers.

        Takes no lock: Disconnect holds it while systemd stops OpenVPN, which
        runs this.
        """
        if env.get("script_type") == "up":
            dns = openvpn.pushed_dns(env)
            active = self._active()
            if active is not None and active["protocol"] == OPENVPN:
                active["dns"] = dns
                self._write_active(active)
            self._apply_killswitch(dns)
        elif env.get("script_type") == "down":
            self._apply_killswitch([])
        return [("result", "ok")]

    # -- the active connection -------------------------------------------
    def _active(self) -> dict | None:
        text = read_text(self.paths.active)
        if not text:
            return None
        try:
            data = json.loads(text)
        except ValueError:
            return None
        if not isinstance(data, dict) or data.get("protocol") not in PROTOCOLS:
            return None
        if not isinstance(data.get("profile"), str) or not isinstance(data.get("since"),
                                                                       (int, float)):
            return None
        return data

    def _write_active(self, data: dict) -> None:
        write_private(self.paths.active, json.dumps(data))

    def _clear_active(self) -> None:
        for path in (self.paths.active, self.paths.wg_conf, self.paths.openvpn_env,
                     self.paths.latency):
            remove(path)

    def _profiles(self):
        return list_profiles(self.paths.wireguard_dir, self.paths.openvpn_dir)

    def _openvpn_profile(self, profile) -> str:
        """The profile's text, refused if too large or it has unsafe directives."""
        text = read_text(profile.path, limit=openvpn.MAX_PROFILE + 1)
        if text is None:
            raise AgentError("unknown-profile")
        if len(text) > openvpn.MAX_PROFILE:
            logger.error("OpenVPN profile %s: larger than %d bytes", profile.name,
                         openvpn.MAX_PROFILE)
            raise AgentError("unsafe-profile")
        unsafe = openvpn.unsafe_directives(text)
        if unsafe:
            logger.error("OpenVPN profile %s: not allowed: %s", profile.name, ", ".join(unsafe))
            raise AgentError("unsafe-profile")
        return text

    def _openvpn_auth_args(self, profile, text: str) -> str:
        """``--auth-user-pass <file>`` when there is a credentials file.

        Without one, a profile that would make OpenVPN prompt is refused here,
        rather than failing over and over under systemd.
        """
        path = openvpn.find_credentials(self.paths.openvpn_dir, profile.name)
        if path is None:
            if openvpn.asks_for_credentials(text):
                raise AgentError("no-credentials")
            return ""
        if not openvpn.valid_credentials(read_text(path, limit=4096) or ""):
            raise AgentError("bad-credentials")
        return f"--auth-user-pass {path}"

    # -- the tunnels -----------------------------------------------------
    def _stop_tunnels(self) -> None:
        for _interface, unit in _TUNNELS.values():
            self.runner.run(["systemctl", "stop", unit], timeout=30)

    def _probe(self, active: dict) -> dict[str, object]:
        protocol = active["protocol"]
        interface, unit = _TUNNELS[protocol]
        if protocol == WIREGUARD:
            info = wireguard.probe(
                self.runner.run(["wg", "show", interface, "dump"]),
                self.runner.run(["ip", "-4", "-o", "addr", "show", "dev", interface]),
                active["since"], self.clock())
        else:
            info = openvpn.probe(self.management)
        return info or self._unit_state(unit)

    def _unit_state(self, unit: str) -> dict[str, object]:
        """No tunnel to ask: what systemd says about its unit."""
        state = self.runner.run(["systemctl", "is-active", unit]).stdout.strip()
        if state in ("activating", "reloading"):
            return {"state": "connecting"}
        if state == "active":
            return {"state": "connecting" if unit == openvpn.UNIT else "error",
                    "error": None if unit == openvpn.UNIT else "interface-missing"}
        if state == "failed":
            return {"state": "error", "error": "tunnel-failed"}
        return {"state": "disconnected", "error": "stopped"}

    # -- kill switch and latency -----------------------------------------
    def _apply_killswitch(self, dns: list[str]) -> None:
        result = self.runner.run(["nft", "-f", "-"], input_text=killswitch.render(dns))
        if not result.ok:
            logger.error("nft failed (exit %d): %s", result.returncode, result.stderr.strip())
            raise AgentError("killswitch-failed")

    def _killswitch_state(self) -> str:
        result = self.runner.run(["nft", "list", "table", "inet", killswitch.TABLE])
        return "on" if result.ok else "off"

    def _conf(self) -> dict[str, str]:
        """``/rw/config/vpn/agent.conf``: ``key = value`` lines, ``#`` comments."""
        conf = {}
        for line in (read_text(self.paths.agent_conf) or "").splitlines():
            key, sep, value = line.split("#", 1)[0].partition("=")
            if sep:
                conf[key.strip()] = value.strip()
        return conf

    def _write_conf(self, key: str, value: str | None) -> None:
        """Set ``key`` in agent.conf (None: remove it), keeping the other lines."""
        lines = (read_text(self.paths.agent_conf) or "").splitlines()
        kept, done = [], value is None
        for line in lines:
            name, sep, _rest = line.split("#", 1)[0].partition("=")
            if sep and name.strip() == key:
                if not done:
                    kept.append(f"{key} = {value}")
                    done = True
                continue
            kept.append(line)
        if not done:
            kept.append(f"{key} = {value}")
        write_private(self.paths.agent_conf, "".join(f"{line}\n" for line in kept))

    def _ping_target(self, dns: list[str]) -> str:
        try:
            return str(ipaddress.IPv4Address(self._conf()["ping_target"]))
        except (KeyError, ValueError):
            return dns[0] if dns else DEFAULT_PING_TARGET

    def _latency(self, interface: str, dns: list[str]) -> float | None:
        """Round trip through the tunnel, measured at most every LATENCY_TTL."""
        now = self.clock()
        cached = (read_text(self.paths.latency) or "").split()
        if len(cached) == 2:
            try:
                if now - float(cached[0]) < LATENCY_TTL:
                    return None if cached[1] == "-" else float(cached[1])
            except ValueError:
                pass
        result = self.runner.run(["ping", "-n", "-c", "1", "-W", "1", "-I", interface,
                                  self._ping_target(dns)], timeout=3)
        value = stats.parse_ping(result.stdout) if result.ok else None
        write_private(self.paths.latency, f"{now} {'-' if value is None else value}\n")
        return value

    # -- locking ---------------------------------------------------------
    def _locked(self):
        return _FileLock(self.paths.lock, LOCK_TIMEOUT)


class _FileLock:
    """One Connect or Disconnect at a time; a second waits, then gives up."""

    def __init__(self, path: str, timeout: float):
        self.path = path
        self.timeout = timeout
        self.fd = -1

    def __enter__(self):
        os.makedirs(os.path.dirname(self.path), mode=0o700, exist_ok=True)
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError as exc:
                if exc.errno not in (errno.EAGAIN, errno.EACCES) or time.monotonic() > deadline:
                    os.close(self.fd)
                    raise AgentError("busy") from None
                time.sleep(0.1)

    def __exit__(self, *_exc):
        os.close(self.fd)
