"""The overview's data: speeds, the tree with chains, texts, warnings, settings."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qubes_vpn import model, settings  # noqa: E402
from qubes_vpn.backend.mock import MockBackend  # noqa: E402
from qubes_vpn.model import Inventory, Qube  # noqa: E402


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def snapshot_after(polls=2, step=3.0, backend=None):
    clock = Clock()
    backend = backend or MockBackend(delay=0, clock=clock)
    monitor = model.Monitor(backend, clock=clock)
    snapshot = None
    for _ in range(polls):
        snapshot = monitor.poll()
        clock.now += step
    return snapshot, monitor, backend, clock


class RateTest(unittest.TestCase):
    def test_speed_from_differences(self):
        rate = model.Rate()
        rate.update(0, 1000, 100)
        self.assertEqual(len(rate.history), 0)
        rate.update(2, 5000, 300)
        self.assertEqual((rate.down, rate.up), (2000.0, 100.0))
        self.assertEqual(rate.traffic().total_down, 5000)

    def test_counter_reset_is_not_a_spike(self):
        rate = model.Rate()
        rate.update(0, 10_000_000, 10)
        rate.update(3, 50, 5)
        self.assertEqual((rate.down, rate.up), (0.0, 0.0))
        rate.update(6, 350, 5)
        self.assertEqual(rate.down, 100.0)

    def test_history_is_bounded(self):
        rate = model.Rate(history=5)
        for t in range(20):
            rate.update(t, t * 10, 0)
        self.assertEqual(len(rate.history), 5)


class InventoryTest(unittest.TestCase):
    def setUp(self):
        self.inventory = MockBackend(delay=0).inventory()

    def test_route_through_a_chain(self):
        self.assertEqual(self.inventory.route("disp1234"),
                         ["disp1234", "sys-vpn-secure", "sys-vpn", "sys-firewall"])
        self.assertEqual(self.inventory.tunnels_of("disp1234"), ["sys-vpn-secure", "sys-vpn"])
        self.assertEqual(self.inventory.tunnels_of("personal"), [])

    def test_route_survives_a_loop(self):
        inventory = Inventory({"a": Qube("a", True, False, True, "b"),
                               "b": Qube("b", True, False, True, "a")})
        self.assertEqual(inventory.route("a"), ["a", "b"])


class MonitorTest(unittest.TestCase):
    def test_tree_shows_chains(self):
        snapshot, *_ = snapshot_after()
        nodes = model.tree(snapshot)
        self.assertEqual([n.name for n in nodes], ["sys-vpn", "sys-vpn-de", model.DIRECT_GROUP])
        sys_vpn = nodes[0]
        self.assertEqual([c.name for c in sys_vpn.children],
                         ["sys-vpn-secure", "browser-social", "browser-streaming",
                          "browser-untrusted"])
        self.assertEqual([c.name for c in sys_vpn.children[0].children], ["disp1234"])
        self.assertEqual([c.name for c in nodes[2].children], ["personal", "work"])
        self.assertEqual(sys_vpn.cells[1], "connected")
        self.assertEqual(sys_vpn.cells[2], "se-got-wg-001 (WireGuard)")
        self.assertEqual(nodes[1].cells[1], "halted")

    def test_speeds_for_tunnels_and_clients(self):
        snapshot, *_ = snapshot_after()
        streaming = snapshot.traffic["browser-streaming"]
        self.assertGreater(streaming.down, 500_000)
        self.assertGreater(streaming.down, streaming.up)
        self.assertGreater(snapshot.traffic["sys-vpn"].down, streaming.down)
        self.assertIn("disp1234", snapshot.traffic)
        # A chained VPN qube: its own tunnel, not also sys-vpn's vif for it.
        self.assertGreater(snapshot.traffic["sys-vpn-secure"].down, 10_000)
        self.assertNotIn("personal", snapshot.traffic)

    def test_first_poll_has_no_speeds(self):
        snapshot, *_ = snapshot_after(polls=1)
        cells = model.tree(snapshot)[0].cells
        self.assertEqual(cells[3:5], ("", ""))

    def test_halted_qubes_are_not_asked(self):
        backend = MockBackend(delay=0)
        calls = []
        original = backend._call
        backend._call = lambda target, *a: calls.append(target) or original(target, *a)
        model.Monitor(backend).poll()
        self.assertNotIn("sys-vpn-de", calls)

    def test_a_qube_that_does_not_answer(self):
        backend = MockBackend(delay=0)
        backend.refuse.add(("sys-vpn-secure", "vpn.Status"))
        snapshot, *_ = snapshot_after(backend=backend)
        self.assertIn("sys-vpn-secure", snapshot.errors)
        self.assertEqual(model.vpn_state_text(snapshot, "sys-vpn-secure"), "no answer")
        self.assertEqual(model.vpn_state_text(snapshot, "sys-vpn"), "connected")

    def test_a_vpn_qube_cannot_claim_another_qubes_traffic(self):
        backend = MockBackend(delay=0)
        # sys-vpn-secure reports a vif with personal's address.
        backend.answers[("sys-vpn-secure", "vpn.Stats")] = (
            b"state=connected\nrx_bytes=1\ntx_bytes=1\nvif=10.137.0.35:999999:999999\n")
        snapshot, *_ = snapshot_after(backend=backend)
        self.assertNotIn("personal", snapshot.traffic)

    def test_untagged_qubes_are_shown_by_address(self):
        backend = MockBackend(delay=0)
        backend.answers[("sys-vpn", "vpn.Stats")] = (
            b"state=connected\nrx_bytes=1\ntx_bytes=1\nvif=10.137.0.99:5:5\n")
        snapshot, *_ = snapshot_after(backend=backend)
        self.assertEqual(snapshot.unlisted, {"sys-vpn": ["10.137.0.99"]})
        node = next(n for n in model.tree(snapshot) if n.name == "sys-vpn")
        row = next(c for c in node.children if c.kind == model.UNLISTED)
        self.assertEqual(row.cells[:2], ("10.137.0.99", "not listed"))
        self.assertIn("vpn-client", row.cells[5])
        self.assertNotIn("10.137.0.99", snapshot.traffic)

    def test_dropped_lines_are_counted(self):
        backend = MockBackend(delay=0)
        backend.answers[("sys-vpn", "vpn.Status")] = b"state=connected\nevil=1\n"
        snapshot, *_ = snapshot_after(polls=1, backend=backend)
        self.assertEqual(snapshot.dropped, 1)

    def test_inventory_is_cached(self):
        _snapshot, monitor, backend, clock = snapshot_after(polls=1)
        backend.set_netvm("personal", "sys-vpn")
        self.assertEqual(monitor.poll().inventory.qubes["personal"].netvm, "sys-firewall")
        monitor.invalidate()
        self.assertEqual(monitor.poll().inventory.qubes["personal"].netvm, "sys-vpn")
        backend.set_netvm("personal", "sys-firewall")
        clock.now += model.INVENTORY_SECONDS
        self.assertEqual(monitor.poll().inventory.qubes["personal"].netvm, "sys-firewall")

    def test_status_only(self):
        clock = Clock()
        snapshot = model.Monitor(MockBackend(delay=0, clock=clock), clock=clock).poll(
            with_stats=False)
        self.assertEqual(snapshot.samples, {})
        self.assertIn("sys-vpn", snapshot.tunnels)


class TextTest(unittest.TestCase):
    def test_human(self):
        self.assertEqual(model.human_rate(512), "512 B/s")
        self.assertEqual(model.human_rate(2_400_000), "2.4 MB/s")
        self.assertEqual(model.human_bytes(1_834_291_022), "1.8 GB")
        self.assertEqual(model.human_age(42), "42 s")
        self.assertEqual(model.human_age(600), "10 min")
        self.assertEqual(model.human_duration(3723), "1:02:03")

    def test_summary_and_tray(self):
        snapshot, *_ = snapshot_after()
        self.assertEqual(model.summary(snapshot),
                         "2 of 3 tunnels up · 4 of 6 client qubes through a VPN")
        self.assertEqual(model.overall(snapshot), model.CONNECTED_ALL)
        self.assertIn("sys-vpn: connected (se-got-wg-001)", model.tooltip(snapshot))

    def test_overall_states(self):
        snapshot, _m, backend, _c = snapshot_after()
        backend.disconnect("sys-vpn-secure")
        snapshot = model.Monitor(backend).poll()
        self.assertEqual(model.overall(snapshot), model.ATTENTION)
        backend.disconnect("sys-vpn")
        self.assertEqual(model.overall(model.Monitor(backend).poll()), model.NONE)

    def test_kill_switch_off_is_loud(self):
        backend = MockBackend(delay=0)
        backend.answers[("sys-vpn", "vpn.Status")] = (
            b"state=connected\nprotocol=wireguard\nprofile=se1\nkillswitch=off\n")
        snapshot, *_ = snapshot_after(backend=backend)
        self.assertIn("kill switch off", model.summary(snapshot))
        self.assertTrue(model.vpn_details(snapshot, "sys-vpn").startswith("kill switch off!"))
        self.assertEqual(model.overall(snapshot), model.ATTENTION)

    def test_errors_are_shown_by_code(self):
        backend = MockBackend(delay=0)
        backend.answers[("sys-vpn", "vpn.Status")] = (
            b"state=error\nprotocol=wireguard\nprofile=se1\nerror=tunnel-failed\n")
        snapshot, *_ = snapshot_after(backend=backend)
        self.assertIn("the tunnel stopped with an error", model.vpn_details(snapshot, "sys-vpn"))


class MoveTest(unittest.TestCase):
    def test_choices_avoid_loops(self):
        snapshot, *_ = snapshot_after()
        values = [value for value, _label in model.netvm_choices(snapshot, "browser-social")]
        self.assertEqual(values, ["sys-vpn", "sys-vpn-de", "sys-vpn-secure", "sys-firewall",
                                  None])
        inventory = snapshot.inventory
        inventory.qubes["sys-vpn"] = Qube("sys-vpn", True, True, True, "sys-firewall")
        values = [v for v, _l in model.netvm_choices(snapshot, "sys-vpn")]
        self.assertNotIn("sys-vpn", values)
        self.assertNotIn("sys-vpn-secure", values)  # it runs through sys-vpn

    def test_warnings(self):
        snapshot, *_ = snapshot_after()
        self.assertEqual(model.move_warnings(snapshot, "personal", "sys-vpn"), [])
        self.assertIn("halted", model.move_warnings(snapshot, "personal", "sys-vpn-de")[0])
        self.assertIn("not go through a VPN",
                      model.move_warnings(snapshot, "browser-social", "sys-firewall")[0])
        self.assertIn("no network", model.move_warnings(snapshot, "personal", None)[0])
        self.assertIn("browser-social, browser-streaming",
                      model.disconnect_warnings(snapshot, "sys-vpn")[0])
        self.assertIsNotNone(model.shutdown_problem(snapshot, "sys-vpn"))
        self.assertIsNone(model.shutdown_problem(snapshot, "sys-vpn-de"))


class SettingsTest(unittest.TestCase):
    def test_defaults_and_limits(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "config.ini")
            self.assertEqual(settings.load(path), settings.Settings())
            Path(path).write_text("[manager]\npoll_interval = 60\nnetvm_method = admin\n")
            self.assertEqual(settings.load(path), settings.Settings(5, "admin"))
            Path(path).write_text("[manager]\npoll_interval = x\nnetvm_method = sudo\n")
            self.assertEqual(settings.load(path), settings.Settings())

    def test_last_profiles(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "sub", "profiles.json")
            profiles = settings.LastProfiles(path)
            self.assertIsNone(profiles.get("sys-vpn"))
            profiles.set("sys-vpn", "se1")
            self.assertEqual(settings.LastProfiles(path).get("sys-vpn"), "se1")
            Path(path).write_text('{"sys-vpn": "../x", "ok": "y", "1": 2}')
            self.assertEqual(settings.LastProfiles(path)._data, {"ok": "y"})


if __name__ == "__main__":
    unittest.main()
