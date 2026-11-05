"""The VPN window (GTK 3).

The VPN qubes, what goes through each of them (chains included) and how fast,
in qubes-firewall's window: the undecorated, translucent chrome of
qubes-systemlist's action dialog, the stock Qubes menu's stylesheet
underneath, and the launcher's red for focus.

:class:`VpnWindow` is used two ways:

* by ``frontend.main`` on its own (``qubes-vpn``): closing it quits;
* by the tray (``qubes-vpn --tray``): closing it hides it, and the tray
  keeps polling for its icon.

The window has five pages that share its footer: the overview (a tree of
qubes, the tools under it and the selected row's traffic graph), the profile
list of a VPN qube, a VPN qube's settings (``vpn.Configure``), the net qube
list of a client qube, and the warnings shown before an action that has any. Every action runs in a worker thread and is
followed by a fresh poll.

Keyboard, in the overview: Up/Down select, Enter does the row's main thing
(halted VPN qube: start it; running one: its profiles; client qube: move it),
Alt + an underlined letter presses a button, Ctrl+R or F5 refreshes, Escape
closes. On the other pages, Enter or Ctrl+Enter accepts and Escape goes back.

``_is_theme_light``, ``_load_theme`` and ``_prepare_transparency`` are the same
as in qubes-firewall, qubes-settings and qubes-systemlist, which mirror
``qubes_menu.appmenu`` (the Qubes OS Project, LGPL-2.1+).
"""

from __future__ import annotations

import html
import importlib.resources
import logging
import threading
from typing import Callable

import gi

# Both namespaces must be pinned, and Gtk must come first: dom0 has GTK4
# installed, so a bare Gdk import resolves to 4.0 and Gtk 3.0 then refuses to
# load. Same rule as qubes-firewall and upstream's qubes_menu.appmenu.
gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gtk, Gdk, GLib, Pango  # noqa: E402

try:
    # The graph draws with cairo through PyGObject (python3-gi-cairo).
    gi.require_foreign("cairo")
    HAVE_CAIRO = True
except ImportError:
    HAVE_CAIRO = False

from . import model, protocol  # noqa: E402
from .backend import Backend  # noqa: E402
from .settings import LastProfiles  # noqa: E402

logger = logging.getLogger("qubes-vpn")

WINDOW_NAME = "qubes-vpn-window"
PANE_CLASS = "vpn-pane"
#: Window background opacity; qubes-systemlist's default.
WINDOW_ALPHA = 0.92
ALPHA_PLACEHOLDER = "@ALPHA@"
WINDOW_WIDTH = 820
LIST_HEIGHT = 260
GRAPH_HEIGHT = 90

OVERVIEW, PROFILES, SETTINGS, MOVE, CONFIRM = (
    "overview", "profiles", "settings", "move", "confirm")

HINTS = {
    OVERVIEW: "↵ connect / start / move  ·  Ctrl+R refresh  ·  Esc close",
    PROFILES: "↵ connect  ·  Esc back",
    SETTINGS: "Ctrl+↵ save  ·  Esc back",
    MOVE: "↵ move  ·  Esc back",
    CONFIRM: "Esc back",
}
#: Footer buttons per page: (left, right). Both keep their Alt mnemonic; the
#: confirm page's right one is set per action.
BUTTONS = {
    OVERVIEW: ("Cl_ose", "_Refresh"),
    PROFILES: ("_Back", "_Connect"),
    SETTINGS: ("_Back", "_Save"),
    MOVE: ("_Back", "_Move"),
    CONFIRM: ("_Back", "_Continue"),
}

#: Overview tree columns: the visible texts, then kind and qube name.
KIND_COLUMN = len(model.COLUMNS)
NAME_COLUMN = KIND_COLUMN + 1
#: Details again, escaped: GTK reads a tree's tooltip column as markup.
TOOLTIP_COLUMN = NAME_COLUMN + 1
DETAILS = model.COLUMNS.index("Details")

_DOWN_FALLBACK = (0.75, 0.38, 0.42)
_UP_FALLBACK = (0.56, 0.61, 0.70)


# -- theme (same as qubes-firewall) --------------------------------------------
def _is_theme_light(widget: Gtk.Widget) -> bool:
    """Is the current system theme light? (mirrors qubes_menu.appmenu)"""
    context = widget.get_style_context()
    background = context.get_background_color(Gtk.StateFlags.NORMAL)
    text = context.get_color(Gtk.StateFlags.NORMAL)
    background_intensity = background.red + background.blue + background.green
    text_intensity = text.red + text.blue + text.green
    return text_intensity < background_intensity


def _add_css(css: str) -> None:
    provider = Gtk.CssProvider()
    provider.load_from_data(css.encode("utf-8"))
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )


def _load_theme(window: Gtk.Widget) -> bool:
    """Apply the stock menu's light or dark stylesheet; False if not installed."""
    try:
        package = importlib.resources.files("qubes_menu")
    except ImportError:
        return False
    name = "qubes-menu-light.css" if _is_theme_light(window) else "qubes-menu-dark.css"
    resource = package / name
    if not resource.is_file():
        return False
    with importlib.resources.as_file(resource) as path:
        provider = Gtk.CssProvider()
        provider.load_from_path(str(path))
    Gtk.StyleContext.add_provider_for_screen(
        Gdk.Screen.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )
    return True


def _own_css(name: str) -> str:
    return (importlib.resources.files("qubes_vpn") / name).read_text(encoding="utf-8")


def _prepare_transparency(window: Gtk.Window) -> bool:
    """Give the window an RGBA visual so CSS alpha is honoured.

    Must run before the window is first realised, or it stays opaque for good.
    """
    screen = window.get_screen()
    visual = screen.get_rgba_visual() if screen.is_composited() else None
    if visual is None:
        return False
    window.set_visual(visual)
    window.set_app_paintable(True)
    return True


_styled = False


def install_style(widget: Gtk.Widget, alpha: float = WINDOW_ALPHA,
                  theme: bool = True) -> None:
    """Load the stylesheets, once per process.

    ``theme=False`` skips the stock menu stylesheet (or its fallback): a caller
    that already loaded it for the screen, like qubes-systemlist, passes that.
    """
    global _styled  # pylint: disable=global-statement
    if _styled:
        return
    _styled = True
    if theme and not _load_theme(widget):
        logger.info("qubes_menu not installed; using fallback-theme.css")
        _add_css(_own_css("fallback-theme.css"))
    _add_css(_own_css("vpn.css").replace(ALPHA_PLACEHOLDER, f"{alpha:.3f}"))


# -- small helpers -------------------------------------------------------------
def run_in_thread(fn, *args, on_done=None, on_error=None) -> None:
    """Run a blocking backend call off the GTK thread; report back on it."""

    def deliver(callback, value):
        if callback is not None:
            callback(value)
        return False

    def work():
        try:
            result = fn(*args)
        except Exception as exc:  # pylint: disable=broad-except
            GLib.idle_add(deliver, on_error, exc)
            return
        GLib.idle_add(deliver, on_done, result)

    threading.Thread(target=work, daemon=True).start()


def _section(text: str = "") -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0)
    label.set_ellipsize(Pango.EllipsizeMode.END)
    label.get_style_context().add_class("section")
    return label


def _note(text: str = "") -> Gtk.Label:
    label = Gtk.Label(label=text, xalign=0)
    label.set_line_wrap(True)
    label.get_style_context().add_class("note")
    return label


def _list(store: Gtk.TreeModel, titles: tuple[str, ...], expand: str) -> Gtk.TreeView:
    tree = Gtk.TreeView(model=store)
    tree.get_style_context().add_class("qubes")
    tree.set_enable_search(False)
    tree.set_headers_clickable(False)
    for index, title in enumerate(titles):
        cell = Gtk.CellRendererText()
        cell.set_padding(4, 2)
        column = Gtk.TreeViewColumn(title, cell, text=index)
        if title == expand:
            cell.set_property("ellipsize", Pango.EllipsizeMode.END)
            column.set_expand(True)
            column.set_min_width(120)
        if title in ("↓", "↑"):
            cell.set_property("xalign", 1.0)
            column.set_min_width(80)
        tree.append_column(column)
    return tree


def _tooltip(node: model.Node) -> str:
    return html.escape(node.cells[DETAILS])


def _scroller(tree: Gtk.TreeView, height: int) -> Gtk.ScrolledWindow:
    scroller = Gtk.ScrolledWindow()
    scroller.get_style_context().add_class("qubes-scroller")
    scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
    scroller.set_min_content_height(height)
    scroller.add(tree)
    return scroller


# -- polling -------------------------------------------------------------------
class Poller:
    """Polls a :class:`~qubes_vpn.model.Monitor` every ``interval`` seconds,
    one poll at a time, in a worker thread; hands each snapshot (or error) to
    the listeners on the GTK thread.

    ``with_stats`` is on while someone shows speeds (the window); the tray
    alone only needs ``vpn.Status``.
    """

    def __init__(self, monitor: model.Monitor, interval: int = model.POLL_SECONDS):
        self.monitor = monitor
        self.interval = interval
        self.with_stats = False
        self.snapshot: model.Snapshot | None = None
        self.error: Exception | None = None
        self._listeners: list[Callable[[model.Snapshot | None, Exception | None], None]] = []
        self._running = False
        self._again = False
        self._timer = 0

    def add_listener(self, callback) -> None:
        self._listeners.append(callback)

    def remove_listener(self, callback) -> None:
        if callback in self._listeners:
            self._listeners.remove(callback)

    def start(self) -> None:
        if not self._timer:
            self._timer = GLib.timeout_add_seconds(self.interval, self._tick)
        self.poll_now()

    def stop(self) -> None:
        if self._timer:
            GLib.source_remove(self._timer)
            self._timer = 0

    def _tick(self) -> bool:
        self.poll_now()
        return True

    def poll_now(self, inventory: bool = False) -> None:
        """Poll as soon as possible; ``inventory`` re-reads the qube list."""
        if inventory:
            self.monitor.invalidate()
        if self._running:
            self._again = True
            return
        self._running = True
        run_in_thread(self.monitor.poll, self.with_stats,
                      on_done=self._done, on_error=self._failed)

    def _done(self, snapshot: model.Snapshot) -> None:
        self.snapshot, self.error = snapshot, None
        self._finish()

    def _failed(self, exc: Exception) -> None:
        logger.warning("Poll failed: %s", exc)
        self.error = exc
        self._finish()

    def _finish(self) -> None:
        self._running = False
        for callback in list(self._listeners):
            callback(self.snapshot, self.error)
        if self._again:
            self._again = False
            self.poll_now()


# -- the graph -----------------------------------------------------------------
class Graph(Gtk.DrawingArea):
    """Download and upload speed over the last HISTORY polls."""

    def __init__(self):
        super().__init__()
        self.set_size_request(-1, GRAPH_HEIGHT)
        self.get_style_context().add_class("graph")
        self.history: tuple = ()
        if HAVE_CAIRO:
            self.connect("draw", self._draw)
        else:
            logger.info("python3-gi-cairo is not installed; no traffic graph")

    def set_history(self, history: tuple) -> None:
        self.history = history
        self.queue_draw()

    def _colour(self, name: str, fallback: tuple[float, float, float]):
        found, rgba = self.get_style_context().lookup_color(name)
        return (rgba.red, rgba.green, rgba.blue) if found else fallback

    def _draw(self, _widget, cr) -> bool:
        width = self.get_allocated_width()
        height = self.get_allocated_height()
        Gtk.render_frame(self.get_style_context(), cr, 0, 0, width, height)
        if len(self.history) < 2:
            return False
        top = max(max(max(d, u) for d, u in self.history), 1000.0)
        step = (width - 4) / (model.HISTORY - 1)
        start = width - 2 - step * (len(self.history) - 1)

        def y(value):
            return height - 3 - (height - 16) * value / top

        for index, (colour, fill) in enumerate(((self._colour("launcher-red", _DOWN_FALLBACK),
                                                 0.18),
                                                (self._colour("buttons-bg", _UP_FALLBACK),
                                                 0.10))):
            cr.move_to(start, y(self.history[0][index]))
            for position, sample in enumerate(self.history[1:], 1):
                cr.line_to(start + step * position, y(sample[index]))
            cr.set_source_rgba(*colour, 1.0)
            cr.set_line_width(1.5)
            cr.stroke_preserve()
            cr.line_to(width - 2, height - 3)
            cr.line_to(start, height - 3)
            cr.close_path()
            cr.set_source_rgba(*colour, fill)
            cr.fill()
        cr.set_source_rgba(*self._colour("buttons-bg", _UP_FALLBACK), 0.9)
        cr.select_font_face("Sans")
        cr.set_font_size(9)
        cr.move_to(6, 11)
        cr.show_text(model.human_rate(top))
        return False


# -- the window ----------------------------------------------------------------
class VpnWindow(Gtk.Window):
    """The VPN qubes and their clients. Polls while shown.

    ``on_close()`` is called each time the window goes away: destroyed, or,
    with ``hide_on_close``, hidden (the tray shows it again with
    :meth:`present_page`).
    """

    def __init__(self, backend: Backend, poller: Poller, *,
                 parent: Gtk.Window | None = None,
                 on_close: Callable[[], None] | None = None,
                 hide_on_close: bool = False,
                 last_profiles: LastProfiles | None = None,
                 alpha: float = WINDOW_ALPHA, theme: bool = True):
        title = "VPN"
        if backend.is_demo:
            title += f" ({backend.name})"
        super().__init__(title=title)
        self.set_name(WINDOW_NAME)
        self.set_keep_above(True)
        self.set_decorated(False)
        self.set_resizable(False)
        self.set_default_size(WINDOW_WIDTH, -1)
        if parent is not None:
            self.set_transient_for(parent)
            self.set_modal(True)
            self.set_skip_taskbar_hint(True)
            self.set_skip_pager_hint(True)
            self.set_position(Gtk.WindowPosition.CENTER_ON_PARENT)
        else:
            self.set_position(Gtk.WindowPosition.CENTER)
        translucent = _prepare_transparency(self)
        install_style(self, alpha if translucent else 1.0, theme=theme)

        self.backend = backend
        self.poller = poller
        self.last_profiles = last_profiles or LastProfiles()
        self.snapshot: model.Snapshot | None = None
        self.page = OVERVIEW
        #: The qube the profile or move page is about.
        self.target: str | None = None
        #: What the confirm page's right button does.
        self._confirmed: Callable[[], None] | None = None
        self._on_close = on_close
        self._hide_on_close = hide_on_close
        self._closed = False
        self._busy = False
        self._error: str | None = None
        self._shape: list[tuple] = []
        #: The settings page's answer, to tell what changed.
        self._settings: protocol.Answer | None = None

        pane = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        pane.get_style_context().add_class(PANE_CLASS)
        self.add(pane)

        heading = Gtk.Label(xalign=0)
        heading.set_markup("<b>VPN</b>" + (f" · {html.escape(backend.name)}"
                                           if backend.is_demo else ""))
        heading.get_style_context().add_class("dialog-title")
        pane.pack_start(heading, False, False, 0)

        self.subtitle = Gtk.Label(label="Reading the qubes…", xalign=0)
        self.subtitle.set_ellipsize(Pango.EllipsizeMode.END)
        self.subtitle.get_style_context().add_class("dialog-subtitle")
        pane.pack_start(self.subtitle, False, False, 0)

        self.stack = Gtk.Stack()
        self.stack.set_margin_start(16)
        self.stack.set_margin_end(16)
        self.stack.set_vhomogeneous(False)
        self.stack.set_interpolate_size(False)
        pane.pack_start(self.stack, True, True, 0)
        self.stack.add_named(self._build_overview_page(), OVERVIEW)
        self.stack.add_named(self._build_profiles_page(), PROFILES)
        self.stack.add_named(self._build_settings_page(), SETTINGS)
        self.stack.add_named(self._build_move_page(), MOVE)
        self.stack.add_named(self._build_confirm_page(), CONFIRM)

        bottom = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        bottom.set_margin_top(10)
        bottom.set_margin_bottom(8)
        bottom.set_margin_end(8)
        pane.pack_start(bottom, False, False, 0)

        self.footer = Gtk.Label(label=HINTS[OVERVIEW], xalign=0)
        self.footer.set_ellipsize(Pango.EllipsizeMode.END)
        self.footer.get_style_context().add_class("footer")
        bottom.pack_start(self.footer, True, True, 0)

        self.cancel_button = Gtk.Button.new_with_mnemonic(BUTTONS[OVERVIEW][0])
        self.accept_button = Gtk.Button.new_with_mnemonic(BUTTONS[OVERVIEW][1])
        for button in (self.cancel_button, self.accept_button):
            button.get_style_context().add_class("action")
            bottom.pack_start(button, False, False, 0)
        self.accept_button.get_style_context().add_class("suggested")
        self.cancel_button.connect("clicked", lambda *_: self.back())
        self.accept_button.connect("clicked", lambda *_: self.accept())

        self.connect("key-press-event", self._on_key_press)
        self.connect("delete-event", lambda *_: self.close_window() or True)
        self.connect("map", lambda *_: self._mapped(True))
        self.connect("unmap", lambda *_: self._mapped(False))

        poller.add_listener(self._polled)
        self.stack.show_all()
        self.note.hide()
        self._update_tools()
        if poller.snapshot is not None:
            self._polled(poller.snapshot, poller.error)

    # -- pages -----------------------------------------------------------
    def _build_overview_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)

        self.note = _note()
        self.note.set_no_show_all(True)
        page.pack_start(self.note, False, False, 0)

        self.store = Gtk.TreeStore(*([str] * (len(model.COLUMNS) + 3)))
        self.tree = _list(self.store, model.COLUMNS, "Details")
        # Details is cut to the column; the whole text is the row's tooltip.
        self.tree.set_tooltip_column(TOOLTIP_COLUMN)
        self.tree.connect("row-activated", lambda *_: self.activate_row())
        self.tree.get_selection().connect("changed", lambda *_: self._selection_changed())
        page.pack_start(_scroller(self.tree, LIST_HEIGHT), True, True, 0)

        tools = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL)
        tools.set_margin_top(6)
        page.pack_start(tools, False, False, 0)
        self.tools: dict[str, Gtk.Button] = {}
        for key, text, callback in (
                ("connect", "_Connect…", self.open_profiles),
                ("disconnect", "_Disconnect", self.disconnect),
                ("start", "St_art", self.start_qube),
                ("shutdown", "Shut do_wn", self.shutdown_qube),
                ("settings", "_Settings…", self.open_settings),
                ("move", "_Move…", self.open_move)):
            button = Gtk.Button.new_with_mnemonic(text)
            button.get_style_context().add_class("action")
            button.get_style_context().add_class("tool")
            button.connect("clicked", lambda _b, cb=callback: cb())
            tools.pack_start(button, False, False, 0)
            self.tools[key] = button

        legend = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.graph_title = _section()
        legend.pack_start(self.graph_title, True, True, 0)
        self.legend_down = Gtk.Label(xalign=1)
        self.legend_down.get_style_context().add_class("legend-down")
        self.legend_up = Gtk.Label(xalign=1)
        self.legend_up.get_style_context().add_class("legend-up")
        legend.pack_start(self.legend_down, False, False, 0)
        legend.pack_start(self.legend_up, False, False, 0)
        page.pack_start(legend, False, False, 0)

        self.graph = Graph()
        page.pack_start(self.graph, False, False, 0)

        self.graph_note = Gtk.Label(xalign=0)
        self.graph_note.set_ellipsize(Pango.EllipsizeMode.END)
        self.graph_note.get_style_context().add_class("note")
        page.pack_start(self.graph_note, False, False, 0)
        return page

    def _build_profiles_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.profiles_header = _section()
        page.pack_start(self.profiles_header, False, False, 0)
        # Profile, protocol, "active"/"last used"; the name again, untouched.
        self.profile_store = Gtk.ListStore(str, str, str, str)
        self.profile_tree = _list(self.profile_store, ("Profile", "Protocol", ""), "Profile")
        self.profile_tree.connect("row-activated", lambda *_: self.accept())
        page.pack_start(_scroller(self.profile_tree, LIST_HEIGHT), True, True, 0)
        self.profiles_note = _note()
        page.pack_start(self.profiles_note, False, False, 0)
        return page

    def _build_settings_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.settings_header = _section()
        page.pack_start(self.settings_header, False, False, 0)

        def grid() -> Gtk.Grid:
            g = Gtk.Grid(column_spacing=12, row_spacing=6)
            g.set_margin_top(4)
            g.set_margin_bottom(4)
            return g

        def field(g: Gtk.Grid, row: int, text: str, widget: Gtk.Widget) -> None:
            label = Gtk.Label.new_with_mnemonic(text)
            label.set_xalign(0)
            label.set_mnemonic_widget(widget)
            label.get_style_context().add_class("field-title")
            widget.set_hexpand(True)
            g.attach(label, 0, row, 1, 1)
            g.attach(widget, 1, row, 1, 1)

        general = grid()
        self.autoconnect_combo = Gtk.ComboBoxText()
        field(general, 0, "Connect _at boot", self.autoconnect_combo)
        self.ping_entry = Gtk.Entry()
        self.ping_entry.set_placeholder_text("the VPN's DNS server, else 1.1.1.1")
        self.ping_entry.set_max_length(15)
        self.ping_entry.connect("activate", lambda *_: self.accept())
        field(general, 1, "_Latency against", self.ping_entry)
        page.pack_start(general, False, False, 0)

        self.credentials_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.credentials_box.pack_start(_section("OpenVPN username and password"),
                                        False, False, 0)
        secrets = grid()
        self.credentials_combo = Gtk.ComboBoxText()
        self.credentials_combo.connect("changed", lambda *_: self._credentials_target_changed())
        field(secrets, 0, "_For", self.credentials_combo)
        self.username_entry = Gtk.Entry()
        self.username_entry.set_max_length(protocol.MAX_SECRET)
        self.username_entry.connect("activate", lambda *_: self.password_entry.grab_focus())
        field(secrets, 1, "_Username", self.username_entry)
        self.password_entry = Gtk.Entry()
        self.password_entry.set_visibility(False)
        self.password_entry.set_input_purpose(Gtk.InputPurpose.PASSWORD)
        self.password_entry.set_max_length(protocol.MAX_SECRET)
        self.password_entry.connect("activate", lambda *_: self.accept())
        field(secrets, 2, "_Password", self.password_entry)
        self.forget_check = Gtk.CheckButton.new_with_mnemonic("Re_move the stored ones")
        self.forget_check.connect("toggled", lambda *_: self._forget_toggled())
        secrets.attach(self.forget_check, 1, 3, 1, 1)
        self.credentials_box.pack_start(secrets, False, False, 0)
        page.pack_start(self.credentials_box, False, False, 0)

        self.settings_note = _note()
        page.pack_start(self.settings_note, False, False, 0)
        return page

    def _build_move_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.move_header = _section()
        page.pack_start(self.move_header, False, False, 0)
        # Label; the net qube ("" for none).
        self.move_store = Gtk.ListStore(str, str)
        self.move_tree = _list(self.move_store, ("Net qube",), "Net qube")
        self.move_tree.connect("row-activated", lambda *_: self.accept())
        page.pack_start(_scroller(self.move_tree, LIST_HEIGHT), True, True, 0)
        self.move_note = _note()
        page.pack_start(self.move_note, False, False, 0)
        return page

    def _build_confirm_page(self) -> Gtk.Widget:
        page = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.confirm_header = _section("Check before going on")
        page.pack_start(self.confirm_header, False, False, 0)
        self.warning_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        page.pack_start(self.warning_box, False, False, 0)
        return page

    # -- showing ---------------------------------------------------------
    def present_page(self) -> None:
        """Show the window on the overview (the tray's left click)."""
        if self.page != OVERVIEW and not self._busy:
            self._show_page(OVERVIEW)
        self.show_all()
        self.note.set_visible(bool(self.note.get_text()))
        self.present()
        self.tree.grab_focus()

    def _mapped(self, shown: bool) -> None:
        self.poller.with_stats = shown
        if shown:
            self.poller.poll_now()

    # -- polls -----------------------------------------------------------
    def _polled(self, snapshot: model.Snapshot | None, error: Exception | None) -> None:
        if self._closed and not self._hide_on_close:
            return
        if error is not None and snapshot is None:
            self.subtitle.set_text("")
            self._set_note(f"Could not read the qubes: {error}")
            return
        if error is not None:
            self._set_note(f"The last poll failed: {error}")
        elif snapshot.dropped:
            self._set_note(f"A VPN qube sent {snapshot.dropped} line(s) the manager does not "
                           "accept; they were ignored.")
        else:
            self._set_note("")
        self.snapshot = snapshot
        self.subtitle.set_text(model.summary(snapshot))
        self._fill_tree(model.tree(snapshot))
        self._update_tools()
        self._update_graph()

    def _set_note(self, text: str) -> None:
        self.note.set_text(text)
        self.note.set_visible(bool(text))

    def _fill_tree(self, nodes: list[model.Node]) -> None:
        """Update the rows in place when the tree has the same shape, so the
        selection and the keyboard cursor stay put; rebuild it otherwise."""
        shape: list[tuple] = []

        def walk(items, depth):
            for node in items:
                shape.append((depth, node.kind, node.name))
                walk(node.children, depth + 1)

        walk(nodes, 0)
        if shape == self._shape:
            rows = iter(self._flat(nodes))
            columns = [*range(len(model.COLUMNS)), TOOLTIP_COLUMN]

            def update(store, _path, it):
                node = next(rows)
                store.set(it, columns, [*node.cells, _tooltip(node)])
                return False

            self.store.foreach(update)
            return
        selected = self.selected()
        self._shape = shape
        self.store.clear()

        def add(parent, items):
            for node in items:
                it = self.store.append(parent, [*node.cells, node.kind, node.name,
                                                _tooltip(node)])
                add(it, node.children)

        add(None, nodes)
        self.tree.expand_all()
        if not self._select(selected) and len(self.store):
            self._select(None)

    @staticmethod
    def _flat(nodes):
        for node in nodes:
            yield node
            yield from VpnWindow._flat(node.children)

    def selected(self) -> tuple[str, str] | None:
        """(kind, qube) of the selected row."""
        _store, it = self.tree.get_selection().get_selected()
        if it is None:
            return None
        return self.store.get_value(it, KIND_COLUMN), self.store.get_value(it, NAME_COLUMN)

    def _select(self, key: tuple[str, str] | None) -> bool:
        """Select the row of ``key``; None selects the first row."""
        found = []

        def match(store, path, it):
            if key is None or (store.get_value(it, KIND_COLUMN),
                               store.get_value(it, NAME_COLUMN)) == key:
                found.append(path.copy())
                return True
            return False

        self.store.foreach(match)
        if found:
            self.tree.set_cursor(found[0], None, False)
        return bool(found)

    def _selection_changed(self) -> None:
        self._update_tools()
        self._update_graph()

    def _update_tools(self) -> None:
        key = self.selected()
        snapshot = self.snapshot
        enabled = dict.fromkeys(self.tools, False)
        if key is not None and snapshot is not None and not self._busy:
            kind, name = key
            qube = snapshot.inventory.qubes.get(name)
            if qube is not None and kind == model.VPN:
                tunnel = snapshot.tunnels.get(name)
                enabled["connect"] = qube.running
                enabled["disconnect"] = qube.running and tunnel is not None and \
                    tunnel.state != protocol.DISCONNECTED
                enabled["start"] = not qube.running
                enabled["shutdown"] = qube.running
                enabled["settings"] = qube.running
                enabled["move"] = qube.is_client
            elif qube is not None and kind == model.CLIENT:
                enabled["move"] = True
        for key_name, button in self.tools.items():
            button.set_sensitive(enabled[key_name])

    def _update_graph(self) -> None:
        key = self.selected()
        snapshot = self.snapshot
        if key is None or snapshot is None or key[0] == model.GROUP \
                or key[1] not in snapshot.inventory.qubes:
            self.graph_title.set_text("Traffic")
            self.legend_down.set_text("")
            self.legend_up.set_text("")
            self.graph_note.set_text("Select a qube to see its traffic.")
            self.graph.set_history(())
            return
        name = key[1]
        traffic = snapshot.traffic.get(name, model.Traffic())
        self.graph_title.set_text(f"Traffic · {name}")
        self.legend_down.set_text(f"↓ {model.human_rate(traffic.down)}")
        self.legend_up.set_text(f"↑ {model.human_rate(traffic.up)}")
        route = model.route_text(snapshot.inventory, name)
        totals = (f"total ↓ {model.human_bytes(traffic.total_down)} "
                  f"↑ {model.human_bytes(traffic.total_up)}")
        self.graph_note.set_text(f"{route}  ·  {totals}")
        self.graph.set_history(traffic.history)

    # -- overview actions ------------------------------------------------
    def activate_row(self) -> None:
        """Enter or double-click: the selected row's main action."""
        key = self.selected()
        if key is None or self.snapshot is None or self.page != OVERVIEW:
            return
        kind, name = key
        qube = self.snapshot.inventory.qubes.get(name)
        if qube is None:
            return
        if kind == model.CLIENT:
            self.open_move()
        elif kind == model.VPN:
            (self.open_profiles if qube.running else self.start_qube)()

    def _selected_vpn(self) -> str | None:
        key = self.selected()
        if key is None or key[0] != model.VPN or self.page != OVERVIEW or self._busy:
            return None
        return key[1]

    def open_profiles(self) -> None:
        name = self._selected_vpn()
        if name is None or not self.snapshot.inventory.qubes[name].running:
            return
        self.target = name
        self.profiles_header.set_text(f"Connect {name}")
        self.profile_store.clear()
        self.profiles_note.set_text("Reading the profiles…")
        self._show_page(PROFILES)
        self.accept_button.set_sensitive(False)
        self.profile_tree.grab_focus()
        run_in_thread(self.backend.profiles, name,
                      on_done=lambda answer: self._profiles_loaded(name, answer),
                      on_error=self._action_failed)

    def _profiles_loaded(self, name: str, answer: protocol.Answer) -> None:
        if self.page != PROFILES or self.target != name:
            return
        active = answer.get("active")
        last = self.last_profiles.get(name)
        select = 0
        for index, profile in enumerate(answer.profiles):
            mark = "active" if profile.name == active else (
                "last used" if profile.name == last else "")
            if profile.name == (active or last):
                select = index
            self.profile_store.append([profile.name, protocol.PROTOCOL_TEXT[profile.protocol],
                                       mark, profile.name])
        if not answer.profiles:
            self.profiles_note.set_text(
                f"{name} has no profiles. Put WireGuard (.conf) or OpenVPN (.ovpn) files in "
                "/rw/config/vpn/wireguard or /rw/config/vpn/openvpn there.")
            return
        self.profiles_note.set_text(f"The keys and passwords stay in {name}; the manager "
                                    "only sends the profile's name.")
        path = Gtk.TreePath.new_from_indices([select])
        self.profile_tree.set_cursor(path, None, False)
        self.accept_button.set_sensitive(True)

    # -- settings --------------------------------------------------------
    def open_settings(self) -> None:
        name = self._selected_vpn()
        if name is None or not self.snapshot.inventory.qubes[name].running:
            return
        self.target = name
        self._settings = None
        self.settings_header.set_text(f"Settings for {name}")
        self.autoconnect_combo.remove_all()
        self.credentials_combo.remove_all()
        self.ping_entry.set_text("")
        self.credentials_box.hide()
        self.settings_note.set_text("Reading the settings…")
        self._show_page(SETTINGS)
        self.accept_button.set_sensitive(False)
        run_in_thread(self.backend.profiles, name,
                      on_done=lambda answer: self._settings_loaded(name, answer),
                      on_error=self._action_failed)

    def _settings_loaded(self, name: str, answer: protocol.Answer) -> None:
        if self.page != SETTINGS or self.target != name:
            return
        self._settings = answer
        autoconnect = answer.get("autoconnect")
        self.autoconnect_combo.append("", "(none)")
        for profile in answer.profiles:
            self.autoconnect_combo.append(
                profile.name, f"{profile.name} ({protocol.PROTOCOL_TEXT[profile.protocol]})")
        if autoconnect and autoconnect not in {p.name for p in answer.profiles}:
            self.autoconnect_combo.append(autoconnect, f"{autoconnect} (no such profile)")
        self.autoconnect_combo.set_active_id(autoconnect or "")
        self.ping_entry.set_text(answer.get("ping_target") or "")

        stored = set(answer.credentials)
        openvpn = [p.name for p in answer.profiles if p.protocol == "openvpn"]
        if openvpn or protocol.DEFAULT_CREDENTIALS in stored:
            for target, text in ((protocol.DEFAULT_CREDENTIALS,
                                  "every OpenVPN profile without its own"),
                                 *((p, p) for p in openvpn)):
                self.credentials_combo.append(
                    target, text + ("  ·  stored" if target in stored else ""))
            self.credentials_combo.set_active(0)
            self.credentials_box.show_all()
        self.settings_note.set_text(
            f"Saved in {name} (/rw/config/vpn, root only). The password goes from here "
            f"to {name} once and is not kept in the manager; it is never read back. "
            "Leave username and password empty to keep what is stored.")
        self.accept_button.set_sensitive(True)
        self.autoconnect_combo.grab_focus()

    def _credentials_target_changed(self) -> None:
        stored = self._settings is not None and \
            self.credentials_combo.get_active_id() in self._settings.credentials
        self.forget_check.set_active(False)
        self.forget_check.set_sensitive(stored)

    def _forget_toggled(self) -> None:
        forget = self.forget_check.get_active()
        for entry in (self.username_entry, self.password_entry):
            if forget:
                entry.set_text("")
            entry.set_sensitive(not forget)

    def _clear_secrets(self) -> None:
        self.username_entry.set_text("")
        self.password_entry.set_text("")
        self.forget_check.set_active(False)

    def _save_settings(self) -> None:
        name, answer = self.target, self._settings
        if name is None or answer is None:
            return
        changes: list[tuple] = []
        autoconnect = self.autoconnect_combo.get_active_id() or None
        if autoconnect != answer.get("autoconnect"):
            changes.append((self.backend.set_autoconnect, name, autoconnect))
        ping_target = self.ping_entry.get_text().strip() or None
        if ping_target is not None and not protocol.valid_ipv4(ping_target):
            self._show_error("The latency target must be an IPv4 address, or empty.")
            return
        if ping_target != answer.get("ping_target"):
            changes.append((self.backend.set_ping_target, name, ping_target))
        target = self.credentials_combo.get_active_id()
        if target is not None:
            profile = None if target == protocol.DEFAULT_CREDENTIALS else target
            username = self.username_entry.get_text()
            password = self.password_entry.get_text()
            if self.forget_check.get_active():
                changes.append((self.backend.set_credentials, name, profile, "", ""))
            elif username or password:
                if not (username and password):
                    self._show_error("Give both a username and a password.")
                    return
                changes.append((self.backend.set_credentials, name, profile,
                                username, password))
        self._clear_secrets()
        if not changes:
            self.back()
            return

        def work():
            for fn, *args in changes:
                fn(*args)

        self._run(f"Saving the settings of {name}…", work)

    def _connect_selected(self) -> None:
        _store, it = self.profile_tree.get_selection().get_selected()
        if it is None or self.target is None:
            return
        name, profile = self.target, self.profile_store.get_value(it, 3)
        self.last_profiles.set(name, profile)
        self._run(f"Connecting {name} to {profile}…", self.backend.connect, name, profile)

    def connect_last(self, name: str) -> bool:
        """The tray's Connect: the last profile, without the window. False if
        there is none to use."""
        profile = self.last_profiles.get(name)
        if profile is None or self._busy:
            return False
        self._run(f"Connecting {name} to {profile}…", self.backend.connect, name, profile)
        return True

    def disconnect(self, name: str | None = None) -> None:
        name = name or self._selected_vpn()
        if name is None or self.snapshot is None or self._busy:
            return
        warnings = model.disconnect_warnings(self.snapshot, name)
        action = lambda: self._run(f"Disconnecting {name}…", self.backend.disconnect, name)
        if warnings and self.page == OVERVIEW and self.get_visible():
            self._confirm(f"Disconnect {name}", warnings, "Disconnect _anyway", action)
        else:
            action()

    def start_qube(self) -> None:
        name = self._selected_vpn()
        if name is not None:
            self._run(f"Starting {name}…", self.backend.start, name)

    def shutdown_qube(self) -> None:
        name = self._selected_vpn()
        if name is None:
            return
        problem = model.shutdown_problem(self.snapshot, name)
        if problem:
            self._show_error(problem)
            return
        self._run(f"Shutting down {name}…", self.backend.shutdown, name)

    def open_move(self) -> None:
        key = self.selected()
        if key is None or self.snapshot is None or self.page != OVERVIEW or self._busy:
            return
        name = key[1]
        qube = self.snapshot.inventory.qubes.get(name)
        if qube is None or not qube.is_client:
            return
        self.target = name
        self.move_header.set_text(f"Net qube for {name} (now {qube.netvm or 'none'})")
        self.move_store.clear()
        select = 0
        for index, (netvm, label) in enumerate(model.netvm_choices(self.snapshot, name)):
            self.move_store.append([label, netvm or ""])
            if netvm == qube.netvm:
                select = index
        self.move_note.set_text("Only qubes tagged vpn-client can be moved. A running qube "
                                "changes net qube at once.")
        self._show_page(MOVE)
        self.move_tree.set_cursor(Gtk.TreePath.new_from_indices([select]), None, False)
        self.move_tree.grab_focus()

    def _move_selected(self) -> None:
        _store, it = self.move_tree.get_selection().get_selected()
        if it is None or self.target is None or self.snapshot is None:
            return
        client = self.target
        netvm = self.move_store.get_value(it, 1) or None
        if netvm == self.snapshot.inventory.qubes[client].netvm:
            self.back()
            return
        warnings = model.move_warnings(self.snapshot, client, netvm)
        if warnings:
            self._confirm(f"Move {client}", warnings, "Move _anyway",
                          lambda: self._move(client, netvm))
        else:
            self._move(client, netvm)

    def _move(self, client: str, netvm: str | None) -> None:
        inventory = self.snapshot.inventory

        def work():
            # A running qube can only be attached to a running net qube.
            if netvm in inventory.qubes and not inventory.qubes[netvm].running \
                    and inventory.qubes[client].running:
                self.backend.start(netvm)
            self.backend.set_netvm(client, netvm)

        self._run(f"Moving {client} to {netvm or 'no network'}…", work)

    # -- running actions -------------------------------------------------
    def _run(self, text: str, fn, *args) -> None:
        self._set_busy(True)
        if self.page != OVERVIEW:
            self._show_page(OVERVIEW)
        self._set_footer(text)
        logger.info("%s", text)
        run_in_thread(fn, *args, on_done=self._action_done, on_error=self._action_failed)

    def _action_done(self, _result) -> None:
        self._set_busy(False)
        self._set_footer(HINTS[self.page])
        self.poller.poll_now(inventory=True)

    def _action_failed(self, exc: Exception) -> None:
        logger.warning("Failed: %s", exc)
        self._set_busy(False)
        if self.page == PROFILES:
            self.profiles_note.set_text("")
        if self.page == SETTINGS:
            self.settings_note.set_text("")
        self._show_error(str(exc))
        self.poller.poll_now(inventory=True)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.accept_button.set_sensitive(not busy)
        self._update_tools()

    def _confirm(self, title: str, warnings: list[str], button: str,
                 action: Callable[[], None]) -> None:
        self.confirm_header.set_text(title)
        for child in self.warning_box.get_children():
            self.warning_box.remove(child)
        for text in warnings:
            label = Gtk.Label(label=f"• {text}", xalign=0)
            label.set_line_wrap(True)
            label.set_max_width_chars(90)
            label.get_style_context().add_class("warning")
            self.warning_box.pack_start(label, False, False, 0)
        self.warning_box.show_all()
        self._confirmed = action
        self._show_page(CONFIRM)
        self.accept_button.set_label(button)
        # Back, not the action: Enter twice must not go past the warnings.
        self.cancel_button.grab_focus()

    # -- pages and footer ------------------------------------------------
    def _show_page(self, page: str) -> None:
        if page != SETTINGS:
            # A typed password does not outlive the page.
            self._clear_secrets()
        self.page = page
        self.stack.set_visible_child_name(page)
        left, right = BUTTONS[page]
        self.cancel_button.set_label(left)
        self.accept_button.set_label(right)
        self.accept_button.set_sensitive(not self._busy)
        self._error = None
        self._set_footer(HINTS[page])
        # The stack is not homogeneous: let the window fit the new page.
        self.resize(WINDOW_WIDTH, 1)

    def _set_footer(self, text: str, error: bool = False) -> None:
        self.footer.set_text(text)
        self.footer.set_tooltip_text(text if error else None)
        context = self.footer.get_style_context()
        (context.add_class if error else context.remove_class)("error")

    def _show_error(self, text: str) -> None:
        # Stays until the page changes: an error that vanished before it was
        # read would leave the user guessing.
        self._error = text
        self._set_footer(text, error=True)

    # -- keys and closing ------------------------------------------------
    def _on_key_press(self, _widget, event) -> bool:
        ctrl = event.state & Gdk.ModifierType.CONTROL_MASK
        key = event.keyval
        if key == Gdk.KEY_Escape:
            self.back()
            return True
        if ctrl and key in (Gdk.KEY_Return, Gdk.KEY_KP_Enter) and self.page != OVERVIEW:
            self.accept()
            return True
        if (ctrl and key in (Gdk.KEY_r, Gdk.KEY_R)) or key == Gdk.KEY_F5:
            self.refresh()
            return True
        return False

    def refresh(self) -> None:
        self._set_footer("Refreshing…")
        self.poller.poll_now(inventory=True)
        GLib.timeout_add(600, lambda: (not self._busy and self._error is None
                                       and self._set_footer(HINTS[self.page])) and False)

    def accept(self) -> None:
        """The footer's right button: Refresh, Connect, Save, Move or the
        confirmed action."""
        if self._busy:
            return
        if self.page == OVERVIEW:
            self.refresh()
        elif self.page == PROFILES:
            self._connect_selected()
        elif self.page == SETTINGS:
            self._save_settings()
        elif self.page == MOVE:
            self._move_selected()
        elif self._confirmed is not None:
            action, self._confirmed = self._confirmed, None
            action()

    def back(self) -> None:
        """The footer's left button and Escape: back to the overview, or close."""
        if self.page == OVERVIEW:
            self.close_window()
            return
        if self._busy:
            return
        self._show_page(OVERVIEW)
        self.tree.grab_focus()

    def close_window(self) -> None:
        """Close (or hide, for the tray). An action keeps running."""
        if self._closed:
            return
        if self._hide_on_close:
            self.hide()
        else:
            self._closed = True
            self.poller.remove_listener(self._polled)
            self.destroy()
        if self._on_close is not None:
            self._on_close()

    def dismiss(self) -> None:
        """Destroy without reporting back (the caller is going away itself)."""
        self._on_close = None
        self._hide_on_close = False
        self.close_window()
