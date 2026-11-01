"""The tray icon (``qubes-vpn --tray``, autostarted in the vpn-manager qube).

A ``Gtk.StatusIcon``: Qubes' GUI agent puts it in dom0's tray, framed in the
vpn-manager qube's colour. The icon says whether every running tunnel is up,
something needs a look, or nothing is connected, drawn as a white glyph on a
dark (#2B303C) square so it reads the same in any tray; the tooltip lists the VPN
qubes. Left click shows or hides the window; the menu connects (to the last
profile) or disconnects each running VPN qube, and quits.
"""

from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import GdkPixbuf, GLib, Gtk  # noqa: E402

from . import model, protocol  # noqa: E402
from .window import Poller, VpnWindow  # noqa: E402

#: Themed icon names per overall state, first one the theme has wins.
ICONS = {
    model.CONNECTED_ALL: ("network-vpn", "network-vpn-symbolic", "network-wired"),
    model.ATTENTION: ("network-vpn-acquiring", "network-vpn-acquiring-symbolic",
                      "dialog-warning"),
    model.NONE: ("network-vpn-disconnected", "network-vpn-disabled-symbolic",
                 "network-vpn-no-route-symbolic", "network-offline"),
}


def icon_name(state: str, theme: Gtk.IconTheme | None = None) -> str:
    theme = theme or Gtk.IconTheme.get_default()
    candidates = ICONS[state]
    for name in candidates:
        if theme.has_icon(name):
            return name
    return candidates[-1]


#: The tray icon's square (RGBA) and glyph colour (RGB).
BACKGROUND = 0x2B303CFF
FOREGROUND = b"\xff\xff\xff"


def render_icon(state: str, size: int, theme: Gtk.IconTheme | None = None) -> GdkPixbuf.Pixbuf:
    """The state's themed icon as a white silhouette on a BACKGROUND square."""
    theme = theme or Gtk.IconTheme.get_default()
    size = max(size, 16)
    icon = GdkPixbuf.Pixbuf.new(GdkPixbuf.Colorspace.RGB, True, 8, size, size)
    icon.fill(BACKGROUND)
    try:
        glyph = theme.load_icon(icon_name(state, theme), round(size * 0.75),
                                Gtk.IconLookupFlags.FORCE_SIZE)
    except GLib.Error:
        return icon
    # Keep only the glyph's alpha, so a coloured theme icon turns white too.
    glyph = glyph.add_alpha(False, 0, 0, 0)
    width, height, stride = glyph.get_width(), glyph.get_height(), glyph.get_rowstride()
    pixels = bytearray(glyph.get_pixels())
    for row in range(height):
        for col in range(width):
            at = row * stride + col * 4
            pixels[at:at + 3] = FOREGROUND
    white = GdkPixbuf.Pixbuf.new_from_bytes(GLib.Bytes.new(bytes(pixels)),
                                            GdkPixbuf.Colorspace.RGB, True, 8,
                                            width, height, stride)
    x, y = (size - width) // 2, (size - height) // 2
    white.composite(icon, x, y, width, height, x, y, 1, 1,
                    GdkPixbuf.InterpType.BILINEAR, 255)
    return icon


class Tray:
    def __init__(self, window: VpnWindow, poller: Poller, on_quit):
        self.window = window
        self.poller = poller
        self.on_quit = on_quit
        self.snapshot: model.Snapshot | None = None
        self.state = model.NONE
        self.icon = Gtk.StatusIcon()
        self.icon.set_title("VPN")
        self._show(model.NONE)
        self.icon.set_tooltip_text("VPN: reading the qubes…")
        self.icon.connect("activate", lambda *_: self.toggle())
        self.icon.connect("popup-menu", self._popup)
        self.icon.connect("size-changed", self._resized)
        poller.add_listener(self._polled)

    def _show(self, state: str, size: int | None = None) -> None:
        self.state = state
        self.icon.set_from_pixbuf(render_icon(state, size or self.icon.get_size()))

    def _resized(self, _icon, size: int) -> bool:
        self._show(self.state, size)
        return True

    def _polled(self, snapshot: model.Snapshot | None, error: Exception | None) -> None:
        if snapshot is None:
            self._show(model.ATTENTION)
            self.icon.set_tooltip_text(f"VPN: {error}")
            return
        self.snapshot = snapshot
        self._show(model.overall(snapshot))
        self.icon.set_tooltip_text(model.tooltip(snapshot))

    def toggle(self) -> None:
        if self.window.get_visible():
            self.window.close_window()
        else:
            self.window.present_page()

    def menu(self) -> Gtk.Menu:
        menu = Gtk.Menu()
        item = Gtk.MenuItem.new_with_mnemonic("_Open VPN manager")
        item.connect("activate", lambda *_: self.window.present_page())
        menu.append(item)
        snapshot = self.snapshot
        if snapshot is not None:
            entries = []
            for name in snapshot.inventory.vpn_names:
                if not snapshot.inventory.qubes[name].running:
                    continue
                tunnel = snapshot.tunnels.get(name)
                if tunnel is not None and tunnel.state != protocol.DISCONNECTED:
                    entries.append((f"Disconnect {name}",
                                    lambda _i, n=name: self.window.disconnect(n)))
                else:
                    last = self.window.last_profiles.get(name)
                    label = f"Connect {name} ({last})" if last else f"Connect {name}…"
                    entries.append((label, lambda _i, n=name: self._connect(n)))
            if entries:
                menu.append(Gtk.SeparatorMenuItem())
            for label, callback in entries:
                item = Gtk.MenuItem(label=label)
                item.connect("activate", callback)
                menu.append(item)
        menu.append(Gtk.SeparatorMenuItem())
        item = Gtk.MenuItem.new_with_mnemonic("_Quit")
        item.connect("activate", lambda *_: self.on_quit())
        menu.append(item)
        menu.show_all()
        return menu

    def _connect(self, name: str) -> None:
        if not self.window.connect_last(name):
            # No profile to reuse: pick one in the window.
            self.window.present_page()
            self.window._select((model.VPN, name))  # pylint: disable=protected-access
            self.window.open_profiles()

    def _popup(self, _icon, button, time) -> None:
        self._menu = self.menu()  # kept, or GTK drops it while it is open
        self._menu.popup(None, None, Gtk.StatusIcon.position_menu, self.icon, button, time)
