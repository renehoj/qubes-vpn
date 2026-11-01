"""What the VPN window shows, without GTK or qubesadmin.

* :class:`Inventory`: the VPN qubes (tag ``vpn``) and client qubes (tag
  ``vpn-client``), with their net qubes and addresses, as read from qubesd;
* :class:`Tunnel` and :class:`Sample`: a VPN qube's ``vpn.Status`` and
  ``vpn.Stats``, already validated (``protocol``);
* :class:`Rate`: speed from two counter readings, and the history the graphs
  draw;
* :class:`Monitor`: one poll of everything, returned as a :class:`Snapshot`
  the window can draw from another thread;
* :func:`tree`: the overview's rows, VPN qubes with what goes through them,
  chains included (VPN over VPN);
* the texts: speeds, ages, states, the subtitle, the tray's tooltip, the
  warnings before an action.
"""

from __future__ import annotations

import collections
import concurrent.futures
import dataclasses
import logging
import threading
import time

from . import protocol
from .protocol import Answer

logger = logging.getLogger("qubes-vpn")

#: Seconds between polls; the window may be told otherwise (2-5 s is sane).
POLL_SECONDS = 3
#: Re-read the qube list (which qubes run, their net qubes) this often.
INVENTORY_SECONDS = 15
#: Samples kept per graph: six minutes at the default poll.
HISTORY = 120

VPN, CLIENT, GROUP, UNLISTED = "vpn", "client", "group", "unlisted"
UNLISTED_HINT = "a qube not tagged vpn-client (qvm-tags <qube> add vpn-client)"
COLUMNS = ("Qube", "State", "Profile", "↓", "↑", "Details")
DIRECT_GROUP = "Not through a VPN"


# -- qubes ---------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Qube:
    name: str
    is_vpn: bool
    is_client: bool
    running: bool
    netvm: str | None
    ip: str | None = None


@dataclasses.dataclass
class Inventory:
    qubes: dict[str, Qube]

    @property
    def vpn_names(self) -> list[str]:
        return sorted(name for name, qube in self.qubes.items() if qube.is_vpn)

    @property
    def client_names(self) -> list[str]:
        return sorted(name for name, qube in self.qubes.items()
                      if qube.is_client and not qube.is_vpn)

    def is_vpn(self, name: str | None) -> bool:
        return name is not None and name in self.qubes and self.qubes[name].is_vpn

    def downstream(self, name: str) -> list[Qube]:
        """The listed qubes whose net qube is ``name``."""
        return sorted((q for q in self.qubes.values() if q.netvm == name),
                      key=lambda q: (not q.is_vpn, q.name))

    def route(self, name: str) -> list[str]:
        """``name`` and its net qubes upward, as far as the list knows them,
        plus the first one it does not (``sys-firewall``)."""
        route, seen = [name], {name}
        current = self.qubes.get(name)
        while current is not None and current.netvm and current.netvm not in seen:
            route.append(current.netvm)
            seen.add(current.netvm)
            current = self.qubes.get(current.netvm)
        return route

    def tunnels_of(self, name: str) -> list[str]:
        """The VPN qubes ``name``'s traffic goes through, nearest first."""
        return [hop for hop in self.route(name)[1:] if self.is_vpn(hop)]

    def address_map(self) -> dict[str, str]:
        return {q.ip: q.name for q in self.qubes.values() if q.ip}


# -- what an agent said ------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Tunnel:
    """A VPN qube's ``vpn.Status``."""

    state: str = protocol.DISCONNECTED
    protocol: str | None = None
    profile: str | None = None
    endpoint: str | None = None
    tunnel_ip: str | None = None
    since: int | None = None
    dns: str | None = None
    handshake_age: int | None = None
    killswitch: str | None = None
    error: str | None = None

    @classmethod
    def from_answer(cls, answer: Answer) -> "Tunnel":
        values = {field.name: answer.get(field.name) for field in dataclasses.fields(cls)}
        values["state"] = values["state"] or (protocol.ERROR if answer.error
                                              else protocol.DISCONNECTED)
        return cls(**values)

    @property
    def is_up(self) -> bool:
        return self.state == protocol.CONNECTED


@dataclasses.dataclass(frozen=True)
class Sample:
    """A VPN qube's ``vpn.Stats``, the parts that are not speeds."""

    rx_bytes: int | None = None
    tx_bytes: int | None = None
    link_rx_bytes: int | None = None
    link_tx_bytes: int | None = None
    handshake_age: int | None = None
    uptime: int | None = None
    latency_ms: float | None = None

    @classmethod
    def from_answer(cls, answer: Answer) -> "Sample":
        return cls(**{field.name: answer.get(field.name) for field in dataclasses.fields(cls)})


class Rate:
    """Speeds from successive byte counters, with a history for the graph.

    A counter that goes down (the interface was recreated) starts over, at
    speed zero, instead of showing a negative or enormous speed.
    """

    def __init__(self, history: int = HISTORY):
        self.history: collections.deque = collections.deque(maxlen=history)
        self.down = 0.0
        self.up = 0.0
        self.total_down = 0
        self.total_up = 0
        self._last: tuple[float, int, int] | None = None

    def update(self, when: float, down_bytes: int, up_bytes: int) -> None:
        if self._last is not None:
            then, last_down, last_up = self._last
            elapsed = when - then
            if elapsed > 0 and down_bytes >= last_down and up_bytes >= last_up:
                self.down = (down_bytes - last_down) / elapsed
                self.up = (up_bytes - last_up) / elapsed
            else:
                self.down = self.up = 0.0
            self.history.append((self.down, self.up))
        self._last = (when, down_bytes, up_bytes)
        self.total_down, self.total_up = down_bytes, up_bytes

    def idle(self) -> None:
        """No reading this time (qube halted, poll failed)."""
        self._last = None
        self.down = self.up = 0.0
        self.history.append((0.0, 0.0))

    def traffic(self) -> "Traffic":
        return Traffic(self.down, self.up, self.total_down, self.total_up, tuple(self.history))


@dataclasses.dataclass(frozen=True)
class Traffic:
    down: float = 0.0
    up: float = 0.0
    total_down: int = 0
    total_up: int = 0
    history: tuple = ()


@dataclasses.dataclass
class Snapshot:
    """Everything one poll found; the window only reads these."""

    inventory: Inventory
    tunnels: dict[str, Tunnel] = dataclasses.field(default_factory=dict)
    samples: dict[str, Sample] = dataclasses.field(default_factory=dict)
    traffic: dict[str, Traffic] = dataclasses.field(default_factory=dict)
    #: Per VPN qube: why it could not be asked.
    errors: dict[str, str] = dataclasses.field(default_factory=dict)
    #: Lines the agents sent that were dropped (should stay 0).
    dropped: int = 0
    #: Per VPN qube: addresses behind it that are no listed qube (not tagged).
    unlisted: dict[str, list[str]] = dataclasses.field(default_factory=dict)


class Monitor:
    """Polls the backend; one poll at a time, from any one thread.

    The inventory is re-read every INVENTORY_SECONDS, or when asked (after an
    action). Running VPN qubes are asked ``vpn.Status`` and, while the window
    shows speeds, ``vpn.Stats``, in parallel. Halted ones are never asked:
    the policy would start them (or refuse, with ``autostart=no``).
    """

    def __init__(self, backend, clock=time.monotonic, workers: int = 4):
        self.backend = backend
        self.clock = clock
        self.workers = workers
        self.inventory: Inventory | None = None
        self._inventory_at = float("-inf")
        self._rates: dict[str, Rate] = {}
        self._lock = threading.Lock()

    def invalidate(self) -> None:
        """Re-read the inventory at the next poll."""
        self._inventory_at = float("-inf")

    def poll(self, with_stats: bool = True) -> Snapshot:
        with self._lock:
            return self._poll(with_stats)

    def _poll(self, with_stats: bool) -> Snapshot:
        now = self.clock()
        if self.inventory is None or now - self._inventory_at >= INVENTORY_SECONDS:
            self.inventory = self.backend.inventory()
            self._inventory_at = now
        inventory = self.inventory
        snapshot = Snapshot(inventory)
        running = [name for name in inventory.vpn_names if inventory.qubes[name].running]

        def ask(name):
            status = self.backend.status(name)
            stats = self.backend.stats(name) if with_stats else None
            return name, status, stats

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = [pool.submit(ask, name) for name in running]
            answers = {}
            for future in futures:
                try:
                    name, status, stats = future.result()
                except Exception as exc:  # pylint: disable=broad-except
                    name = running[futures.index(future)]
                    logger.info("Could not ask %s: %s", name, exc)
                    snapshot.errors[name] = str(exc)
                    continue
                answers[name] = (status, stats)

        addresses = inventory.address_map()
        seen = set()
        for name in inventory.vpn_names:
            if name not in answers:
                continue
            status, stats = answers[name]
            snapshot.tunnels[name] = Tunnel.from_answer(status)
            snapshot.dropped += status.dropped
            if stats is None:
                continue
            snapshot.dropped += stats.dropped
            snapshot.samples[name] = Sample.from_answer(stats)
            if stats.get("rx_bytes") is not None and stats.get("tx_bytes") is not None:
                self._rate(name).update(now, stats.get("rx_bytes"), stats.get("tx_bytes"))
                seen.add(name)
            for vif in stats.vifs:
                downstream = addresses.get(vif.address)
                if downstream is None:
                    # A qube the policy does not list: shown by address only.
                    snapshot.unlisted.setdefault(name, []).append(vif.address)
                    continue
                # Only a qube that really uses this VPN qube: an address the
                # VPN qube made up must not move another qube's numbers.
                if inventory.qubes[downstream].netvm != name:
                    continue
                # A chained VPN qube that answered counts its own tunnel.
                if downstream in answers and answers[downstream][1] is not None:
                    continue
                # From the VPN qube, rx is what the downstream qube sent.
                self._rate(downstream).update(now, vif.tx_bytes, vif.rx_bytes)
                seen.add(downstream)
        if with_stats:
            for name, rate in self._rates.items():
                if name not in seen:
                    rate.idle()
            snapshot.traffic = {name: rate.traffic() for name, rate in self._rates.items()
                                if name in inventory.qubes}
        return snapshot

    def _rate(self, name: str) -> Rate:
        if name not in self._rates:
            self._rates[name] = Rate()
        return self._rates[name]


# -- texts ---------------------------------------------------------------------
def human_rate(per_second: float) -> str:
    return f"{human_bytes(per_second)}/s"


def human_bytes(count: float) -> str:
    for unit in ("B", "kB", "MB", "GB", "TB"):
        if count < 1000 or unit == "TB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1000
    return ""  # unreachable


def human_age(seconds: int) -> str:
    if seconds < 90:
        return f"{seconds} s"
    if seconds < 90 * 60:
        return f"{seconds // 60} min"
    if seconds < 48 * 3600:
        return f"{seconds // 3600} h {seconds % 3600 // 60} min"
    return f"{seconds // 86400} d"


def human_duration(seconds: int) -> str:
    hours, rest = divmod(seconds, 3600)
    return f"{hours}:{rest // 60:02d}:{rest % 60:02d}"


STATE_TEXT = {
    protocol.DISCONNECTED: "disconnected",
    protocol.CONNECTING: "connecting…",
    protocol.CONNECTED: "connected",
    protocol.STALE: "no handshake",
    protocol.DISCONNECTING: "disconnecting…",
    protocol.ERROR: "error",
}


def vpn_state_text(snapshot: Snapshot, name: str) -> str:
    qube = snapshot.inventory.qubes[name]
    if not qube.running:
        return "halted"
    if name in snapshot.errors:
        return "no answer"
    tunnel = snapshot.tunnels.get(name)
    return STATE_TEXT[tunnel.state] if tunnel else "…"


def profile_text(tunnel: Tunnel | None) -> str:
    if tunnel is None or tunnel.profile is None:
        return ""
    if tunnel.protocol is None:
        return tunnel.profile
    return f"{tunnel.profile} ({protocol.PROTOCOL_TEXT[tunnel.protocol]})"


def vpn_details(snapshot: Snapshot, name: str) -> str:
    qube = snapshot.inventory.qubes[name]
    if not qube.running:
        return f"via {qube.netvm}" if qube.netvm else "no net qube"
    if name in snapshot.errors:
        return "the VPN qube did not answer"
    tunnel = snapshot.tunnels.get(name)
    if tunnel is None:
        return ""
    parts = []
    if tunnel.killswitch == "off":
        parts.append("kill switch off!")
    if tunnel.error:
        parts.append(protocol.error_text(tunnel.error))
    sample = snapshot.samples.get(name, Sample())
    age = sample.handshake_age if sample.handshake_age is not None else tunnel.handshake_age
    if tunnel.state in (protocol.CONNECTED, protocol.STALE, protocol.CONNECTING):
        if sample.latency_ms is not None:
            parts.append(f"{sample.latency_ms:.0f} ms")
        if age is not None:
            parts.append(f"handshake {human_age(age)} ago")
        if sample.uptime is not None and tunnel.state == protocol.CONNECTED:
            parts.append(f"up {human_duration(sample.uptime)}")
        if tunnel.endpoint:
            parts.append(tunnel.endpoint)
    return " · ".join(parts)


@dataclasses.dataclass
class Node:
    """A row of the overview: a VPN qube, a client qube or a group heading."""

    kind: str
    name: str
    cells: tuple[str, ...]
    children: list["Node"] = dataclasses.field(default_factory=list)


def _rate_cells(snapshot: Snapshot, name: str, running: bool) -> tuple[str, str]:
    traffic = snapshot.traffic.get(name)
    # The first reading has nothing to compare with yet.
    if traffic is None or not running or not traffic.history:
        return "", ""
    return human_rate(traffic.down), human_rate(traffic.up)


def _vpn_node(snapshot: Snapshot, name: str, seen: set[str]) -> Node:
    seen.add(name)
    qube = snapshot.inventory.qubes[name]
    tunnel = snapshot.tunnels.get(name) if qube.running else None
    down, up = _rate_cells(snapshot, name, qube.running)
    node = Node(VPN, name, (name, vpn_state_text(snapshot, name), profile_text(tunnel),
                            down, up, vpn_details(snapshot, name)))
    for child in snapshot.inventory.downstream(name):
        if child.name in seen:
            continue
        if child.is_vpn:
            node.children.append(_vpn_node(snapshot, child.name, seen))
        else:
            seen.add(child.name)
            node.children.append(_client_node(snapshot, child, ""))
    for address in snapshot.unlisted.get(name, ()):
        node.children.append(Node(UNLISTED, address,
                                  (address, "not listed", "", "", "", UNLISTED_HINT)))
    return node


def _client_node(snapshot: Snapshot, qube: Qube, details: str) -> Node:
    down, up = _rate_cells(snapshot, qube.name, qube.running)
    state = "running" if qube.running else "halted"
    return Node(CLIENT, qube.name, (qube.name, state, "", down, up, details or (qube.ip or "")))


def tree(snapshot: Snapshot) -> list[Node]:
    """VPN qubes at the top of a chain, each with what goes through it (VPN
    qubes first, then clients), then the clients that use no VPN."""
    inventory = snapshot.inventory
    seen: set[str] = set()
    roots = [_vpn_node(snapshot, name, seen) for name in inventory.vpn_names
             if not inventory.is_vpn(inventory.qubes[name].netvm)]
    # A loop of VPN qubes has no top; show its members anyway.
    roots += [_vpn_node(snapshot, name, seen) for name in inventory.vpn_names
              if name not in seen]
    direct = [inventory.qubes[name] for name in inventory.client_names if name not in seen]
    if direct:
        group = Node(GROUP, DIRECT_GROUP, (DIRECT_GROUP, "", "", "", "", ""))
        for qube in direct:
            details = f"net qube {qube.netvm}" if qube.netvm else "no net qube"
            group.children.append(_client_node(snapshot, qube, details))
        roots.append(group)
    return roots


def summary(snapshot: Snapshot) -> str:
    """The window's subtitle."""
    inventory = snapshot.inventory
    vpns = inventory.vpn_names
    if not vpns:
        return "no VPN qubes (tag a qube with vpn)"
    up = sum(1 for name in vpns if snapshot.tunnels.get(name, Tunnel()).is_up)
    through = sum(1 for name in inventory.client_names if inventory.tunnels_of(name))
    parts = [f"{up} of {len(vpns)} tunnel{'s' if len(vpns) != 1 else ''} up",
             f"{through} of {len(inventory.client_names)} client qubes through a VPN"]
    if any(t.killswitch == "off" for t in snapshot.tunnels.values()):
        parts.append("kill switch off")
    return " · ".join(parts)


def route_text(inventory: Inventory, name: str) -> str:
    return " → ".join(inventory.route(name))


# -- tray ----------------------------------------------------------------------
CONNECTED_ALL, ATTENTION, NONE = "connected", "attention", "none"


def overall(snapshot: Snapshot) -> str:
    """The tray icon: every running tunnel up, something wrong, or nothing up."""
    running = [n for n in snapshot.inventory.vpn_names if snapshot.inventory.qubes[n].running]
    states = [snapshot.tunnels[n].state if n in snapshot.tunnels else protocol.ERROR
              for n in running]
    if not states or all(s == protocol.DISCONNECTED for s in states):
        return NONE
    if all(s == protocol.CONNECTED for s in states) and not any(
            t.killswitch == "off" for t in snapshot.tunnels.values()):
        return CONNECTED_ALL
    return ATTENTION


def tooltip(snapshot: Snapshot) -> str:
    lines = ["VPN"]
    for name in snapshot.inventory.vpn_names:
        tunnel = snapshot.tunnels.get(name)
        profile = f" ({tunnel.profile})" if tunnel is not None and tunnel.profile else ""
        lines.append(f"{name}: {vpn_state_text(snapshot, name)}{profile}")
    return "\n".join(lines)


# -- moving a client ---------------------------------------------------------
def netvm_choices(snapshot: Snapshot, client: str) -> list[tuple[str | None, str]]:
    """Where ``client`` can be moved: (net qube or None, label).

    The VPN qubes, except ones that would make a loop; the net qubes other
    listed qubes use (``sys-firewall``), so a qube can go back; no network.
    """
    inventory = snapshot.inventory
    choices: list[tuple[str | None, str]] = []
    for name in inventory.vpn_names:
        if name == client or client in inventory.route(name):
            continue
        tunnel = snapshot.tunnels.get(name)
        label = f"{name} · {vpn_state_text(snapshot, name)}"
        if tunnel is not None and tunnel.profile:
            label += f" ({tunnel.profile})"
        choices.append((name, label))
    others = sorted({q.netvm for q in inventory.qubes.values()
                     if q.netvm and not inventory.is_vpn(q.netvm) and q.netvm != client})
    choices += [(name, f"{name} · not a VPN") for name in others]
    choices.append((None, "(no network)"))
    return choices


def move_warnings(snapshot: Snapshot, client: str, netvm: str | None) -> list[str]:
    inventory = snapshot.inventory
    warnings = []
    if netvm is None:
        warnings.append(f"{client} will have no network.")
    elif not inventory.is_vpn(netvm):
        warnings.append(f"{client}'s traffic will not go through a VPN.")
    else:
        tunnel = snapshot.tunnels.get(netvm)
        if not inventory.qubes[netvm].running:
            warnings.append(f"{netvm} is halted; it will be started first.")
        elif tunnel is None or not tunnel.is_up:
            warnings.append(f"{netvm} is not connected: {client} has no network "
                            "until it is (the kill switch blocks it).")
    return warnings


def disconnect_warnings(snapshot: Snapshot, vpn: str) -> list[str]:
    users = [q.name for q in snapshot.inventory.downstream(vpn) if q.running]
    if not users:
        return []
    return [f"{', '.join(users)} lose{'s' if len(users) == 1 else ''} the network until "
            f"{vpn} connects again (the kill switch blocks it)."]


def shutdown_problem(snapshot: Snapshot, vpn: str) -> str | None:
    users = [q.name for q in snapshot.inventory.downstream(vpn) if q.running]
    if not users:
        return None
    return (f"{vpn} is the net qube of {', '.join(users)}, which "
            f"{'is' if len(users) == 1 else 'are'} running; move or stop "
            f"{'it' if len(users) == 1 else 'them'} first.")
