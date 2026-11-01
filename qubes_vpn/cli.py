"""Headless use, from the vpn-manager qube's terminal: the phase-1 check.

``qubes-vpn-cli``                       every VPN qube and what goes through it
``qubes-vpn-cli status <vpn>``          vpn.Status, validated
``qubes-vpn-cli stats <vpn>``           vpn.Stats, validated
``qubes-vpn-cli profiles <vpn>``        vpn.ListProfiles
``qubes-vpn-cli connect <vpn> <p>``     vpn.Connect+<p>
``qubes-vpn-cli disconnect <vpn>``      vpn.Disconnect
``qubes-vpn-cli move <qube> <netvm>``   change a client qube's net qube (``none``: none)

Everything printed went through the same validation as the window's.
"""

from __future__ import annotations

import argparse
import sys

from . import model, protocol, settings
from .backend import KINDS, BackendError, create_backend
from .protocol import Answer


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="qubes-vpn-cli",
                                     description="VPN qubes, headless.")
    parser.add_argument("--backend", choices=KINDS, default="auto")
    parser.add_argument("--mock", dest="backend", action="store_const", const="mock")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("list", help="every VPN qube and what goes through it (default)")
    for name in ("status", "stats", "profiles", "disconnect"):
        sub.add_parser(name).add_argument("vpn")
    connect = sub.add_parser("connect")
    connect.add_argument("vpn")
    connect.add_argument("profile")
    move = sub.add_parser("move")
    move.add_argument("qube")
    move.add_argument("netvm", help="a net qube, or none")
    return parser.parse_args(argv)


def format_table(rows: list[tuple[str, ...]]) -> str:
    widths = [max(len(row[i]) for row in rows) for i in range(len(rows[0]))]
    return "\n".join("  ".join(cell.ljust(w) for cell, w in zip(row, widths)).rstrip()
                     for row in rows)


def print_answer(answer: Answer, out) -> None:
    for key, value in answer.values.items():
        print(f"{key}={value}", file=out)
    for profile in answer.profiles:
        print(f"profile={profile.name} ({protocol.PROTOCOL_TEXT[profile.protocol]})", file=out)
    for vif in answer.vifs:
        print(f"vif={vif.address} rx={vif.rx_bytes} tx={vif.tx_bytes}", file=out)
    if answer.error:
        print(f"# {protocol.error_text(answer.error)}", file=out)
    if answer.dropped:
        print(f"# {answer.dropped} line(s) dropped by validation", file=out)


def print_tree(snapshot: model.Snapshot, out) -> None:
    rows = [model.COLUMNS]

    def walk(nodes, depth):
        for node in nodes:
            cells = list(node.cells)
            cells[0] = "  " * depth + cells[0]
            rows.append(tuple(cells))
            walk(node.children, depth + 1)

    walk(model.tree(snapshot), 0)
    print(model.summary(snapshot), file=out)
    print(format_table(rows), file=out)


def main(argv: list[str] | None = None, out=None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    out = out or sys.stdout
    backend = create_backend(args.backend, settings.load().netvm_method)
    if args.backend == "auto" and backend.is_demo:
        print(f"# {backend.name}: qubesadmin is not installed", file=out)
    try:
        if args.command in (None, "list"):
            print_tree(model.Monitor(backend).poll(), out)
        elif args.command == "status":
            print_answer(backend.status(args.vpn), out)
        elif args.command == "stats":
            print_answer(backend.stats(args.vpn), out)
        elif args.command == "profiles":
            print_answer(backend.profiles(args.vpn), out)
        elif args.command == "connect":
            print_answer(backend.connect(args.vpn, args.profile), out)
        elif args.command == "disconnect":
            print_answer(backend.disconnect(args.vpn), out)
        elif args.command == "move":
            backend.set_netvm(args.qube, None if args.netvm == "none" else args.netvm)
            print(f"{args.qube}: net qube {args.netvm}", file=out)
    except BackendError as exc:
        print(f"qubes-vpn-cli: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
