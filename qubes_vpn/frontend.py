"""``qubes-vpn``: the VPN window, on its own or behind a tray icon.

``qubes-vpn`` shows the window and quits when it closes; ``qubes-vpn --tray``
(the vpn-manager qube's autostart entry) shows the tray icon, and the window
when the icon is clicked.
"""

from __future__ import annotations

import argparse
import logging
import sys

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
from gi.repository import Gtk, Gdk  # noqa: E402,F401  pylint: disable=unused-import

from . import settings  # noqa: E402
from .backend import KINDS, create_backend  # noqa: E402
from .model import Monitor  # noqa: E402
from .window import WINDOW_ALPHA, Poller, VpnWindow  # noqa: E402


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="qubes-vpn",
        description="Manage the VPN qubes and which qubes go through them.",
    )
    parser.add_argument("--tray", action="store_true",
                        help="show a tray icon; the window opens from it")
    parser.add_argument("--backend", choices=KINDS, default="auto",
                        help="where qubes come from (default auto: qubesadmin "
                             "when installed, demo data otherwise)")
    parser.add_argument("--mock", dest="backend", action="store_const", const="mock",
                        help="same as --backend mock")
    parser.add_argument("-i", "--interval", type=int, default=None,
                        help="seconds between polls, 2-5 (default from config.ini, else 3)")
    parser.add_argument("-a", "--alpha", type=float, default=WINDOW_ALPHA,
                        help=f"window background opacity, 0.0-1.0 (default {WINDOW_ALPHA})")
    args = parser.parse_args(argv)
    args.alpha = max(0.0, min(1.0, args.alpha))
    return args


def main(argv: list[str] | None = None) -> int:
    """Entry point. Exit code 6 means there is no display."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    logging.basicConfig(level=logging.INFO)
    if not Gtk.init_check()[0]:
        return 6
    config = settings.load()
    interval = config.poll_interval if args.interval is None else max(
        settings.MIN_POLL, min(settings.MAX_POLL, args.interval))
    backend = create_backend(args.backend, config.netvm_method)
    logging.getLogger("qubes-vpn").info("Backend: %s", backend.name)
    poller = Poller(Monitor(backend), interval)
    if args.tray:
        # pylint: disable=import-outside-toplevel
        from .tray import Tray
        window = VpnWindow(backend, poller, alpha=args.alpha, hide_on_close=True)
        Tray(window, poller, on_quit=Gtk.main_quit)
    else:
        window = VpnWindow(backend, poller, alpha=args.alpha, on_close=Gtk.main_quit)
        window.present_page()
    poller.start()
    Gtk.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
