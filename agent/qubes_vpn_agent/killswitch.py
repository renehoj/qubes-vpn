"""Kill switch and DNS: one nftables table of the agent's own, ``inet qubes-vpn``.

Qubes' own tables (``ip qubes``, ``ip6 qubes``) are not touched; this table
hooks in just before them, and a drop in any base chain is final:

* **forward**: from a downstream qube (``vif*``), IPv4 may only leave through
  a tunnel interface; everything else is dropped. With no tunnel up, the
  downstream qubes have no network at all, rather than the VPN qube's own.
* **IPv6**: dropped from downstream qubes, forwarded or addressed to this qube.
  The tunnels are set up IPv4-only (see ``wireguard`` and ``openvpn``).
* **DNS**: the downstream qubes ask 10.139.1.1 and 10.139.1.2; Qubes DNATs
  those to the VPN qube's own resolvers, which would go out unencrypted. This
  table DNATs them first, to the VPN's DNS servers, at a higher priority; the
  first NAT for a connection is the one that sticks. With no VPN DNS servers
  there is no rule here, Qubes' DNAT applies, and the forward chain drops the
  result because it would leave through the uplink.

The table is written whole, in one ``nft -f`` transaction, at boot
(``qubes-vpn-killswitch.service``) and again whenever the DNS servers change.
"""

from __future__ import annotations

import ipaddress

from . import openvpn, wireguard

TABLE = "qubes-vpn"
TUNNELS = (wireguard.INTERFACE, openvpn.INTERFACE)
QUBES_DNS = ("10.139.1.1", "10.139.1.2")


def render(dns: list[str]) -> str:
    """The nft script for the table, DNATing to ``dns`` (IPv4; may be empty)."""
    servers = [str(ipaddress.IPv4Address(server)) for server in dns][:2]
    tunnels = ", ".join(f'"{name}"' for name in TUNNELS)
    lines = [
        # Create-then-delete makes the first run and every later one the same.
        f"table inet {TABLE} {{}}",
        f"delete table inet {TABLE}",
        f"table inet {TABLE} {{",
        "    chain forward {",
        "        type filter hook forward priority filter - 10; policy accept;",
        '        iifname "vif*" meta nfproto ipv6 counter drop comment "no IPv6 from downstream"',
        f'        iifname "vif*" oifname {{ {tunnels} }} accept',
        '        iifname "vif*" counter drop comment "kill switch"',
        "    }",
        "    chain input {",
        "        type filter hook input priority filter - 10; policy accept;",
        '        iifname "vif*" meta nfproto ipv6 counter drop comment "no IPv6 from downstream"',
        "    }",
        "    chain dnat-dns {",
        "        type nat hook prerouting priority dstnat - 10; policy accept;",
    ]
    for index, qubes_dns in enumerate(QUBES_DNS if servers else ()):
        target = servers[min(index, len(servers) - 1)]
        lines.append(f'        iifname "vif*" ip daddr {qubes_dns} meta l4proto {{ tcp, udp }} '
                     f"th dport 53 counter dnat ip to {target}")
    lines += ["    }", "}"]
    return "\n".join(lines) + "\n"
