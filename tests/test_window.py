"""The GTK window against the demo backend. Skipped without GTK 3 or a display."""

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from qubes_vpn import window
    from gi.repository import Gdk, Gtk
    if not Gtk.init_check()[0]:
        raise ImportError("no display")
except (ImportError, ValueError) as exc:  # ValueError: Gtk 3.0 typelib missing
    window = None
    SKIP = f"GTK 3 not available: {exc}"
else:
    SKIP = ""

from qubes_vpn import model  # noqa: E402
from qubes_vpn.backend.mock import MockBackend  # noqa: E402
from qubes_vpn.settings import LastProfiles  # noqa: E402


def press(widget, keyval, state=0):
    event = Gdk.Event.new(Gdk.EventType.KEY_PRESS)
    event.keyval = keyval
    event.state = state
    widget.emit("key-press-event", event)


def wait_until(condition, timeout=5.0):
    """Run the main loop until ``condition()`` holds; worker threads report
    back through it, at no fixed number of iterations."""
    deadline = time.monotonic() + timeout
    while not condition() and time.monotonic() < deadline:
        drain()
        time.sleep(0.01)
    drain()


def drain():
    while Gtk.events_pending():
        Gtk.main_iteration_do(False)


@unittest.skipIf(window is None, SKIP)
class WindowTest(unittest.TestCase):
    def setUp(self):
        self.clock = [100.0]
        self.backend = MockBackend(delay=0, clock=lambda: self.clock[0])
        self.monitor = model.Monitor(self.backend, clock=lambda: self.clock[0])
        self.poller = window.Poller(self.monitor)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.closed = []

    def open(self, **kwargs):
        win = window.VpnWindow(
            self.backend, self.poller, on_close=lambda: self.closed.append(True),
            last_profiles=LastProfiles(os.path.join(self.tmp.name, "profiles.json")),
            **kwargs)
        self.addCleanup(win.dismiss)
        win.present_page()
        self.poll()
        return win

    def poll(self, step=3.0):
        count = len(self.polls) if hasattr(self, "polls") else 0
        self.polls = getattr(self, "polls", [])
        if not self.polls:
            self.poller.add_listener(lambda s, e: self.polls.append(s))
        self.clock[0] += step
        self.poller.poll_now()
        wait_until(lambda: len(self.polls) > count)

    def rows(self, win):
        found = []
        win.store.foreach(lambda store, path, it: found.append(
            (path.get_depth(), store.get_value(it, 0), store.get_value(it, 1))) and False)
        return found

    def select(self, win, kind, name):
        self.assertTrue(win._select((kind, name)))

    def test_tree_with_chains(self):
        win = self.open()
        rows = self.rows(win)
        self.assertEqual(rows[0], (1, "sys-vpn", "connected"))
        self.assertEqual(rows[1], (2, "sys-vpn-secure", "connected"))
        self.assertEqual(rows[2], (3, "disp1234", "running"))
        self.assertIn((1, "sys-vpn-de", "halted"), rows)
        self.assertIn((1, model.DIRECT_GROUP, ""), rows)
        self.assertIn("2 of 3 tunnels up", win.subtitle.get_text())

    def test_untagged_qube_tooltip_is_escaped(self):
        # GTK reads the tooltip column as markup; <qube> must not be a tag.
        self.backend.answers[("sys-vpn", "vpn.Stats")] = (
            b"state=connected\nrx_bytes=1\ntx_bytes=1\nvif=10.137.0.99:5:5\n")
        win = self.open()
        self.poll()
        tips = {}
        win.store.foreach(lambda store, _path, it: tips.setdefault(
            store.get_value(it, window.NAME_COLUMN),
            store.get_value(it, window.TOOLTIP_COLUMN)) and False)
        self.assertIn("&lt;qube&gt;", tips["10.137.0.99"])

    def test_selection_survives_polls(self):
        win = self.open()
        self.select(win, model.CLIENT, "browser-streaming")
        self.poll()
        self.poll()
        self.assertEqual(win.selected(), (model.CLIENT, "browser-streaming"))
        self.assertRegex(win.legend_down.get_text(), r"^↓ [0-9.]+ (kB|MB)/s$")
        self.assertGreaterEqual(len(win.graph.history), 2)
        self.assertIn("browser-streaming → sys-vpn → sys-firewall", win.graph_note.get_text())

    def test_tools_follow_the_selection(self):
        win = self.open()
        self.select(win, model.VPN, "sys-vpn")
        self.assertTrue(win.tools["disconnect"].get_sensitive())
        self.assertFalse(win.tools["start"].get_sensitive())
        self.assertFalse(win.tools["move"].get_sensitive())
        self.select(win, model.VPN, "sys-vpn-de")
        self.assertTrue(win.tools["start"].get_sensitive())
        self.assertFalse(win.tools["connect"].get_sensitive())
        self.select(win, model.CLIENT, "personal")
        self.assertTrue(win.tools["move"].get_sensitive())
        self.assertFalse(win.tools["disconnect"].get_sensitive())

    def test_connect_through_the_profile_page(self):
        win = self.open()
        self.select(win, model.VPN, "sys-vpn")
        press(win.tree, Gdk.KEY_Return)
        win.activate_row()
        self.assertEqual(win.page, window.PROFILES)
        wait_until(lambda: len(win.profile_store) > 0)
        self.assertEqual(win.profile_store[0][2], "active")
        win.profile_tree.set_cursor(Gtk.TreePath.new_from_indices([2]), None, False)
        press(win, Gdk.KEY_Return, Gdk.ModifierType.CONTROL_MASK)
        self.assertEqual(win.page, window.OVERVIEW)
        wait_until(lambda: not win._busy)
        self.assertEqual(self.backend._agents["sys-vpn"].profile, "nl-ams-wg-002")
        self.assertEqual(win.last_profiles.get("sys-vpn"), "nl-ams-wg-002")

    def test_disconnect_warns_about_clients(self):
        win = self.open()
        self.select(win, model.VPN, "sys-vpn")
        win.disconnect()
        self.assertEqual(win.page, window.CONFIRM)
        self.assertIs(win.get_focus(), win.cancel_button)
        press(win, Gdk.KEY_Escape)
        self.assertEqual(win.page, window.OVERVIEW)
        self.assertEqual(self.backend._agents["sys-vpn"].state(), "connected")
        win.disconnect()
        win.accept()
        wait_until(lambda: not win._busy)
        self.assertEqual(self.backend._agents["sys-vpn"].state(), "disconnected")

    def test_move_a_client(self):
        win = self.open()
        self.select(win, model.CLIENT, "personal")
        win.activate_row()
        self.assertEqual(win.page, window.MOVE)
        labels = [row[0] for row in win.move_store]
        self.assertEqual(labels[0], "sys-vpn · connected (se-got-wg-001)")
        win.move_tree.set_cursor(Gtk.TreePath.new_from_indices([0]), None, False)
        win.accept()
        wait_until(lambda: not win._busy)
        self.assertEqual(self.backend.inventory().qubes["personal"].netvm, "sys-vpn")
        self.poll()
        self.assertIn((2, "personal", "running"), self.rows(win))

    def test_move_to_a_halted_vpn_starts_it(self):
        win = self.open()
        self.select(win, model.CLIENT, "personal")
        win.open_move()
        index = [row[1] for row in win.move_store].index("sys-vpn-de")
        win.move_tree.set_cursor(Gtk.TreePath.new_from_indices([index]), None, False)
        win.accept()
        self.assertEqual(win.page, window.CONFIRM)
        win.accept()
        wait_until(lambda: not win._busy)
        qubes = self.backend.inventory().qubes
        self.assertTrue(qubes["sys-vpn-de"].running)
        self.assertEqual(qubes["personal"].netvm, "sys-vpn-de")

    def test_shutdown_with_clients_is_refused_in_the_footer(self):
        win = self.open()
        self.select(win, model.VPN, "sys-vpn")
        win.shutdown_qube()
        self.assertIn("error", win.footer.get_style_context().list_classes())
        self.assertIn("move or stop them first", win.footer.get_text())

    def test_failed_action_shows_the_error(self):
        win = self.open()
        self.select(win, model.VPN, "sys-vpn-secure")
        self.backend.refuse.add(("sys-vpn-secure", "vpn.ListProfiles"))
        win.open_profiles()
        wait_until(lambda: "Request refused" in win.footer.get_text())
        self.assertIn("error", win.footer.get_style_context().list_classes())

    def test_escape_closes_or_hides(self):
        win = self.open()
        press(win, Gdk.KEY_Escape)
        self.assertEqual(self.closed, [True])
        tray_win = self.open(hide_on_close=True)
        press(tray_win, Gdk.KEY_Escape)
        self.assertFalse(tray_win.get_visible())
        tray_win.present_page()
        self.assertTrue(tray_win.get_visible())

    def test_stats_only_while_shown(self):
        win = self.open(hide_on_close=True)
        self.assertTrue(self.poller.with_stats)
        win.close_window()
        drain()
        self.assertFalse(self.poller.with_stats)

    def test_dropped_lines_note(self):
        self.backend.answers[("sys-vpn", "vpn.Status")] = b"state=connected\nevil=1\n"
        win = self.open()
        self.assertTrue(win.note.get_visible())
        self.assertIn("1 line(s)", win.note.get_text())


@unittest.skipIf(window is None, SKIP)
class TrayTest(unittest.TestCase):
    def test_icon_and_menu(self):
        from qubes_vpn import tray  # pylint: disable=import-outside-toplevel
        backend = MockBackend(delay=0)
        poller = window.Poller(model.Monitor(backend))
        win = window.VpnWindow(backend, poller, hide_on_close=True)
        self.addCleanup(win.dismiss)
        icon = tray.Tray(win, poller, on_quit=lambda: None)
        polls = []
        poller.add_listener(lambda s, e: polls.append(s))
        poller.poll_now()
        wait_until(lambda: polls)
        self.assertIn("sys-vpn: connected", icon.icon.get_tooltip_text())
        menu = icon.menu()  # held: a dropped menu takes its items' labels with it
        labels = [item.get_label() for item in menu.get_children()]
        self.assertIn("Disconnect sys-vpn", labels)
        self.assertNotIn("Disconnect sys-vpn-de", labels)
        icon.toggle()
        self.assertTrue(win.get_visible())
        icon.toggle()
        self.assertFalse(win.get_visible())

    def test_icon_colours(self):
        from qubes_vpn import tray  # pylint: disable=import-outside-toplevel
        pixbuf = tray.render_icon(model.CONNECTED_ALL, 32)
        self.assertEqual((pixbuf.get_width(), pixbuf.get_height()), (32, 32))
        pixels = bytes(pixbuf.get_pixels())
        stride, channels = pixbuf.get_rowstride(), pixbuf.get_n_channels()
        colours = {pixels[row * stride + col * channels:][:3]
                   for row in range(32) for col in range(32)}
        self.assertEqual(pixels[:3], b"\x2b\x30\x3c")  # a corner is background
        # Every pixel is a blend of the background and white: no theme colour.
        for r, g, b in colours:
            self.assertTrue(-1 <= g - r <= 6 and -1 <= b - r <= 18, (r, g, b))


if __name__ == "__main__":
    unittest.main()
