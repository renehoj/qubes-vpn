"""In-memory backend with demo data, for development outside the vpn-manager qube.

The qubes are qubes-systemlist's demo set, as qubes-firewall's mock has them:
``sys-vpn`` (WireGuard), ``sys-vpn-secure`` (OpenVPN, chained through
``sys-vpn``: VPN over VPN) and a halted ``sys-vpn-de``, with the browsers
and a disposable behind them.

The agents are simulated down to their output: every answer is
``key=value`` text and goes through the same parser as a real one. Traffic
grows with the clock, at speeds that wander.
"""

from __future__ import annotations

import math
import threading
import time

from ..model import Inventory, Qube
from .base import Backend, BackendError

#: name: (vpn, client, running, net qube, ip)
_QUBES = {
    "sys-vpn": (True, False, True, "sys-firewall", "10.137.0.20"),
    "sys-vpn-secure": (True, False, True, "sys-vpn", "10.137.0.21"),
    "sys-vpn-de": (True, False, False, "sys-firewall", "10.137.0.22"),
    "browser-social": (False, True, True, "sys-vpn", "10.137.0.31"),
    "browser-streaming": (False, True, True, "sys-vpn", "10.137.0.32"),
    "browser-untrusted": (False, True, False, "sys-vpn", "10.137.0.33"),
    "disp1234": (False, True, True, "sys-vpn-secure", "10.137.0.34"),
    "personal": (False, True, True, "sys-firewall", "10.137.0.35"),
    "work": (False, True, False, "sys-firewall", "10.137.0.36"),
}

_PROFILES = {
    "sys-vpn": [("se-got-wg-001", "wireguard"), ("se-sto-wg-004", "wireguard"),
                ("nl-ams-wg-002", "wireguard"), ("ch-zrh-ovpn", "openvpn")],
    "sys-vpn-secure": [("work-gateway", "openvpn"), ("work-gateway-tcp", "openvpn")],
    "sys-vpn-de": [("de-fra-wg-001", "wireguard"), ("de-ber-ovpn", "openvpn")],
}

#: Who starts connected, to what.
_CONNECTED = {"sys-vpn": "se-got-wg-001", "sys-vpn-secure": "work-gateway"}

_ENDPOINTS = {"wireguard": "185.65.134.{n}:51820", "openvpn": "198.51.100.{n}:1194"}
#: Bytes per second a client pulls on average.
_SPEED = {"browser-social": 120_000, "browser-streaming": 2_400_000, "disp1234": 40_000,
          "sys-vpn-secure": 0}
CONNECT_SECONDS = 2.0


class _Agent:
    """One simulated VPN qube agent."""

    def __init__(self, name: str, clock):
        self.name = name
        self.clock = clock
        self.protocol: str | None = None
        self.profile: str | None = None
        self.since = 0.0

    def connect(self, profile: str, protocol: str) -> None:
        self.profile, self.protocol, self.since = profile, protocol, self.clock()

    def disconnect(self) -> None:
        self.profile = self.protocol = None

    def state(self) -> str:
        if self.profile is None:
            return "disconnected"
        return "connecting" if self.clock() - self.since < CONNECT_SECONDS else "connected"

    def status(self) -> list[tuple[str, object]]:
        if self.profile is None:
            return [("state", "disconnected"), ("killswitch", "on")]
        number = sum(map(ord, self.profile)) % 200 + 2
        connected = self.state() == "connected"
        pairs = [("protocol", self.protocol), ("state", self.state()),
                 ("profile", self.profile),
                 ("interface", "vpn-wg" if self.protocol == "wireguard" else "vpn-tun"),
                 ("endpoint", _ENDPOINTS[self.protocol].format(n=number) if connected else None),
                 ("tunnel_ip", f"10.64.{number}.7" if connected else None),
                 ("since", int(time.time() - (self.clock() - self.since))),
                 ("dns", "10.64.0.1" if connected else None)]
        if self.protocol == "wireguard" and connected:
            pairs.append(("handshake_age", int(self.clock() - self.since) % 120))
        pairs.append(("killswitch", "on"))
        return pairs


class MockBackend(Backend):
    """Simulates the qubes and their agents. ``delay`` scales the simulated
    qrexec time; ``clock`` drives traffic and connecting (tests)."""

    name = "demo data"
    is_demo = True

    def __init__(self, delay: float = 1.0, clock=time.monotonic):
        self.delay = delay
        self.clock = clock
        self._lock = threading.RLock()
        self._qubes = {name: list(row) for name, row in _QUBES.items()}
        self._agents = {name: _Agent(name, clock) for name, row in _QUBES.items() if row[0]}
        self._started = clock()
        for name, profile in _CONNECTED.items():
            protocol = dict(_PROFILES[name])[profile]
            self._agents[name].connect(profile, protocol)
            self._agents[name].since -= 3600 + 17 * len(name)
        #: Calls refused as qrexec would (tests): (target, service).
        self.refuse: set[tuple[str, str]] = set()
        #: Raw text a qube answers instead of its agent's (tests).
        self.answers: dict[tuple[str, str], bytes] = {}

    def _sleep(self, seconds: float) -> None:
        if self.delay:
            time.sleep(seconds * self.delay)

    def _row(self, name: str) -> list:
        try:
            return self._qubes[name]
        except KeyError:
            raise BackendError(f"No such qube: {name}") from None

    # -- qubesd ----------------------------------------------------------
    def inventory(self) -> Inventory:
        self._sleep(0.1)
        with self._lock:
            return Inventory({name: Qube(name, *row) for name, row in self._qubes.items()})

    def start(self, name: str) -> None:
        self._sleep(1.5)
        with self._lock:
            self._row(name)[2] = True

    def shutdown(self, name: str) -> None:
        self._sleep(1.0)
        with self._lock:
            users = [n for n, row in self._qubes.items() if row[3] == name and row[2]]
            if users:
                raise BackendError(f"Could not shut down {name}: there are other VMs "
                                   f"connected to this VM: {', '.join(users)}")
            self._row(name)[2] = False
            if name in self._agents:
                self._agents[name].disconnect()

    def _set_netvm(self, client: str, netvm: str | None) -> None:
        self._sleep(0.3)
        with self._lock:
            row = self._row(client)
            if netvm is not None and row[2] and netvm in self._qubes \
                    and not self._qubes[netvm][2]:
                raise BackendError(f"Could not change the net qube of {client}: "
                                   f"Cannot dynamically attach to stopped NetVM: {netvm}")
            row[3] = netvm

    # -- the agents ------------------------------------------------------
    def _call(self, target: str, service: str, argument: str | None = None) -> bytes:
        self._sleep(0.05)
        with self._lock:
            row = self._row(target)
            if (target, service) in self.refuse or not row[0] or not row[2]:
                raise BackendError(f"{service} in {target} failed (exit 126): Request refused")
            if (target, service) in self.answers:
                return self.answers[(target, service)]
            agent = self._agents[target]
            if service == "vpn.Status":
                pairs = agent.status()
            elif service == "vpn.Stats":
                pairs = self._stats(target, agent)
            elif service == "vpn.ListProfiles":
                pairs = [("profile", f"{n}:{p}") for n, p in _PROFILES[target]]
                pairs += [("active", agent.profile)]
            elif service == "vpn.Connect":
                profiles = dict(_PROFILES[target])
                if argument not in profiles:
                    pairs = [("result", "error"), ("error", "unknown-profile")]
                else:
                    agent.connect(argument, profiles[argument])
                    pairs = [("result", "ok"), *agent.status()]
            elif service == "vpn.Disconnect":
                agent.disconnect()
                pairs = [("result", "ok"), *agent.status()]
            else:
                raise BackendError(f"{service} in {target} failed (exit 126): Request refused")
        return "".join(f"{k}={v}\n" for k, v in pairs if v is not None).encode("ascii")

    def _traffic(self, name: str) -> tuple[int, int]:
        """Bytes ``name`` received and sent so far, from the clock."""
        elapsed = self.clock() - self._started + 600
        speed = _SPEED.get(name, 8_000)
        if name == "sys-vpn-secure":
            speed = _SPEED["disp1234"]
        wobble = 0.6 * math.sin(elapsed / 7.0 + len(name)) * 7.0
        down = int(speed * (elapsed + wobble)) + 1_834_291_022 % (len(name) * 9_999_991)
        return down, down // 18 + 4_422_109

    def _stats(self, target: str, agent: _Agent) -> list[tuple[str, object]]:
        pairs: list[tuple[str, object]] = [("state", agent.state())]
        downstream = [n for n, row in self._qubes.items() if row[3] == target and row[2]]
        if agent.state() == "connected":
            down = up = 0
            for name in downstream:
                d, u = self._traffic(name)
                down, up = down + d, up + u
            age = int(self.clock() - agent.since)
            pairs = [("protocol", agent.protocol), ("state", "connected"),
                     ("rx_bytes", down), ("tx_bytes", up),
                     ("rx_packets", down // 1200), ("tx_packets", up // 400),
                     ("link_rx_bytes", int(down * 1.04)), ("link_tx_bytes", int(up * 1.1)),
                     ("uptime", age),
                     ("latency_ms", round(22 + 6 * math.sin(self.clock() / 5), 1))]
            if agent.protocol == "wireguard":
                pairs.append(("handshake_age", age % 120))
        for name in sorted(downstream):
            d, u = self._traffic(name) if agent.state() == "connected" else (0, 0)
            pairs.append(("vif", f"{_QUBES[name][4]}:{u}:{d}"))
        return pairs
