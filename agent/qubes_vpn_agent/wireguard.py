"""WireGuard: wg-quick under systemd, read back with ``wg show <if> dump``.

``qubes-vpn-wireguard.service`` runs ``wg-quick up /run/qubes-vpn/vpn-wg.conf``;
wg-quick names the interface after the file, so the tunnel is always
``vpn-wg`` and the kill switch can name it in advance.

The copy differs from the profile in three ways:

* ``DNS =`` lines are taken out. wg-quick would hand them to resolvconf, which
  does nothing for the qubes behind this one; the agent DNATs their DNS to
  these servers instead (``killswitch``).
* IPv6 addresses are taken out of ``Address``, ``AllowedIPs`` and ``DNS``. The
  kill switch drops all IPv6 from downstream qubes, and a qube without IPv6
  would make wg-quick fail on them.
* ``PreUp``, ``PostUp``, ``PreDown`` and ``PostDown`` are taken out. wg-quick
  runs them as root in bash, so a profile could run anything, the kill
  switch's table included (providers' own kill switch lines are such hooks;
  the agent's kill switch replaces them).
"""

from __future__ import annotations

import dataclasses
import ipaddress

from .system import Result

PROTOCOL = "wireguard"
INTERFACE = "vpn-wg"
UNIT = "qubes-vpn-wireguard.service"
#: WireGuard re-handshakes every two minutes while traffic flows; three
#: minutes without one means the peer is probably gone.
STALE_AFTER = 180
#: wg-quick's hooks: shell commands, run as root.
HOOKS = ("preup", "postup", "predown", "postdown")


def _ipv4(text: str) -> bool:
    try:
        return ipaddress.ip_network(text.strip(), strict=False).version == 4
    except ValueError:
        return False


def prepare_config(text: str) -> tuple[str, list[str]]:
    """The profile as wg-quick should run it, and its IPv4 DNS servers."""
    out, dns = [], []
    for line in text.splitlines():
        body = line.split("#", 1)[0]
        key, sep, value = body.partition("=")
        key = key.strip().lower()
        if not sep:
            out.append(line)
            continue
        if key in HOOKS:
            continue
        items = [item.strip() for item in value.split(",") if item.strip()]
        if key == "dns":
            # Search domains are dropped with the IPv6 servers.
            dns.extend(item for item in items if _ipv4(item) and "/" not in item)
            continue
        if key in ("address", "allowedips"):
            kept = [item for item in items if _ipv4(item)]
            if not kept:
                continue
            out.append(f"{key_case(line)} = {', '.join(kept)}")
            continue
        out.append(line)
    return "\n".join(out) + "\n", dns


def key_case(line: str) -> str:
    """The key of ``line`` as the profile spelled it."""
    return line.split("=", 1)[0].strip()


@dataclasses.dataclass
class Peer:
    endpoint: str
    latest_handshake: int
    rx_bytes: int
    tx_bytes: int


def parse_dump(text: str) -> list[Peer]:
    """The peers in ``wg show <if> dump`` (the first line is the interface)."""
    peers = []
    for line in text.splitlines()[1:]:
        fields = line.split("\t")
        if len(fields) < 8:
            continue
        try:
            peers.append(Peer(
                endpoint="" if fields[2] == "(none)" else fields[2],
                latest_handshake=int(fields[4]),
                rx_bytes=int(fields[5]),
                tx_bytes=int(fields[6]),
            ))
        except ValueError:
            continue
    return peers


def parse_address(text: str) -> str | None:
    """The first IPv4 address in ``ip -4 -o addr show dev <if>``."""
    for line in text.splitlines():
        fields = line.split()
        if "inet" in fields:
            index = fields.index("inet")
            if index + 1 < len(fields):
                return fields[index + 1].split("/", 1)[0]
    return None


def probe(dump: Result, addr: Result, since: float, now: float) -> dict[str, object]:
    """State, endpoint, tunnel address and handshake age of a running tunnel.

    ``dump`` is ``wg show vpn-wg dump``; when it failed the interface is not
    there, and the caller asks systemd why.
    """
    if not dump.ok:
        return {}
    peers = parse_dump(dump.stdout)
    info: dict[str, object] = {"tunnel_ip": parse_address(addr.stdout) if addr.ok else None}
    if not peers:
        info.update(state="error", error="no-peer")
        return info
    peer = max(peers, key=lambda p: p.latest_handshake)
    info["endpoint"] = peer.endpoint or None
    info["link_rx_bytes"] = sum(p.rx_bytes for p in peers)
    info["link_tx_bytes"] = sum(p.tx_bytes for p in peers)
    if peer.latest_handshake:
        age = max(0, int(now - peer.latest_handshake))
        info["handshake_age"] = age
        info["state"] = "connected" if age <= STALE_AFTER else "stale"
    else:
        # No handshake yet: still connecting for a while, then given up on.
        info["state"] = "connecting" if now - since <= STALE_AFTER else "stale"
    return info
