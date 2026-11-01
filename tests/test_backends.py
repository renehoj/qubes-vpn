"""Backends without Qubes: qrexec-client-vm and qubesadmin replaced by fakes."""

import os
import stat
import sys
import tempfile
import textwrap
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qubes_vpn import protocol  # noqa: E402
from qubes_vpn.backend import BackendError, create_backend  # noqa: E402
from qubes_vpn.backend.mock import MockBackend  # noqa: E402
from qubes_vpn.backend.qrexec import QrexecClient, QrexecError  # noqa: E402


# -- a fake qubesadmin, installed before the backend imports it ----------------
class QubesException(Exception):
    pass


fake_qubesadmin = types.ModuleType("qubesadmin")
fake_qubesadmin.exc = types.ModuleType("qubesadmin.exc")
fake_qubesadmin.exc.QubesException = QubesException
fake_qubesadmin.Qubes = lambda: None
sys.modules.setdefault("qubesadmin", fake_qubesadmin)
sys.modules.setdefault("qubesadmin.exc", fake_qubesadmin.exc)

from qubes_vpn.backend import qubesadmin_backend  # noqa: E402

qubesadmin_backend.qubesadmin.exc.QubesException = QubesException


class FakeVM:
    def __init__(self, name, tags=(), running=True, netvm=None, ip=None, refuse=False):
        self.name = name
        self.tags = set(tags)
        self._running = running
        self._netvm = netvm
        self.ip = ip
        self.refuse = refuse
        self.calls = []

    def __str__(self):
        return self.name

    def is_running(self):
        if self.refuse:
            raise QubesException("Got empty response from qubesd. See journalctl in dom0")
        return self._running

    @property
    def netvm(self):
        return self._netvm

    @netvm.setter
    def netvm(self, value):
        self.calls.append(("netvm", value))
        self._netvm = FakeVM(value) if value else None

    def start(self):
        self.calls.append("start")
        self._running = True

    def shutdown(self):
        raise QubesException("There are other VMs connected to this VM")


class FakeDomains(dict):
    """qubesadmin's VMCollection: indexed by name, iterates over the VMs."""

    def __iter__(self):
        return iter(list(self.values()))


class FakeApp:
    def __init__(self, vms):
        self.domains = FakeDomains((vm.name, vm) for vm in vms)


class FakeQrexec:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def call(self, target, service, argument=None):
        self.calls.append((target, service, argument))
        return self.answers.get((target, service), b"")


def stub_command(directory, script):
    """A stand-in for qrexec-client-vm: a Python script run as the command."""
    path = Path(directory, "qrexec-stub.py")
    path.write_text(textwrap.dedent(script))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return (sys.executable, str(path))


class QrexecClientTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def client(self, script, **kwargs):
        return QrexecClient(stub_command(self.tmp.name, script), **kwargs)

    def test_argv_and_answer(self):
        client = self.client("""
            import sys
            print("args=" + "|".join(sys.argv[1:]))
            print("stdin=" + repr(sys.stdin.read()))
        """)
        out = client.call("sys-vpn", "vpn.Connect", "se1").decode()
        self.assertIn("args=--|sys-vpn|vpn.Connect+se1", out)
        self.assertIn("stdin=''", out)

    def test_refused(self):
        client = self.client("""
            import sys
            sys.stderr.write("Request refused\\n")
            sys.exit(126)
        """)
        with self.assertRaises(QrexecError) as ctx:
            client.call("sys-vpn", "vpn.Status")
        self.assertIn("exit 126", str(ctx.exception))
        self.assertIn("Request refused", str(ctx.exception))

    def test_answer_with_failure_code_is_still_read(self):
        client = self.client("""
            import sys
            print("result=error")
            sys.exit(1)
        """)
        self.assertEqual(client.call("sys-vpn", "vpn.Connect", "x"), b"result=error\n")

    def test_flood_is_cut_off(self):
        client = self.client("""
            import sys
            while True:
                sys.stdout.write("x" * 65536)
        """, max_bytes=1000)
        with self.assertRaises(QrexecError) as ctx:
            client.call("sys-vpn", "vpn.Stats")
        self.assertIn("more than 1000 bytes", str(ctx.exception))

    def test_hang_times_out(self):
        client = self.client("""
            import time
            time.sleep(30)
        """, timeout=0.5)
        with self.assertRaises(QrexecError) as ctx:
            client.call("sys-vpn", "vpn.Stats")
        self.assertIn("did not answer", str(ctx.exception))

    def test_missing_command(self):
        with self.assertRaises(QrexecError):
            QrexecClient(("/nonexistent/qrexec-client-vm",)).call("sys-vpn", "vpn.Status")


class QubesAdminBackendTest(unittest.TestCase):
    def make(self, netvm_method="admin", answers=None):
        self.vms = [
            FakeVM("dom0"),
            FakeVM("sys-vpn", {"vpn"}, True, FakeVM("sys-firewall"), "10.137.0.20"),
            FakeVM("work", {"vpn-client"}, False, FakeVM("sys-vpn"), "10.137.0.30"),
            FakeVM("hidden", {"vpn-client"}, refuse=True),
            FakeVM("other", ()),
        ]
        self.qrexec = FakeQrexec(answers or {})
        return qubesadmin_backend.QubesAdminBackend(FakeApp(self.vms), self.qrexec,
                                                    netvm_method=netvm_method)

    def test_inventory(self):
        inventory = self.make().inventory()
        self.assertEqual(sorted(inventory.qubes), ["sys-vpn", "work"])
        self.assertEqual(inventory.qubes["sys-vpn"].netvm, "sys-firewall")
        self.assertTrue(inventory.qubes["sys-vpn"].is_vpn)
        self.assertEqual(inventory.qubes["work"].ip, "10.137.0.30")
        self.assertFalse(inventory.qubes["work"].running)

    def test_agent_calls_are_parsed(self):
        backend = self.make(answers={("sys-vpn", "vpn.Status"):
                                     b"state=connected\nprotocol=wireguard\nbogus=1\n"})
        answer = backend.status("sys-vpn")
        self.assertEqual(answer.get("state"), "connected")
        self.assertEqual(answer.dropped, 1)

    def test_names_are_checked_before_calling(self):
        backend = self.make()
        with self.assertRaises(BackendError):
            backend.status("@adminvm")
        with self.assertRaises(BackendError):
            backend.connect("sys-vpn", "se1+vpn.Disconnect")
        self.assertEqual(self.qrexec.calls, [])

    def test_connect_error_is_explained(self):
        backend = self.make(answers={("sys-vpn", "vpn.Connect"):
                                     b"result=error\nerror=unknown-profile\n"})
        with self.assertRaises(BackendError) as ctx:
            backend.connect("sys-vpn", "se9")
        self.assertEqual(str(ctx.exception), "no such profile in the VPN qube")
        self.assertEqual(self.qrexec.calls, [("sys-vpn", "vpn.Connect", "se9")])

    def test_refused_answer(self):
        backend = self.make(answers={("sys-vpn", "vpn.Stats"): b"\xff" * 10})
        with self.assertRaises(BackendError) as ctx:
            backend.stats("sys-vpn")
        self.assertIn("refused", str(ctx.exception))

    def test_set_netvm_by_admin_api(self):
        backend = self.make()
        backend.set_netvm("work", "sys-vpn")
        backend.set_netvm("work", None)
        self.assertEqual(self.vms[2].calls, [("netvm", "sys-vpn"), ("netvm", None)])

    def test_set_netvm_by_dom0_service(self):
        backend = self.make("service", {("work", "vpn.SetNetvm"): b"result=ok\n"})
        backend.set_netvm("work", "sys-vpn")
        backend.set_netvm("work", None)
        self.assertEqual(self.qrexec.calls, [("work", "vpn.SetNetvm", "sys-vpn"),
                                             ("work", "vpn.SetNetvm", "none")])
        self.assertEqual(self.vms[2].calls, [])
        self.qrexec.answers[("work", "vpn.SetNetvm")] = b"result=error\nerror=not-allowed\n"
        with self.assertRaises(BackendError) as ctx:
            backend.set_netvm("work", "sys-vpn")
        self.assertIn("not-allowed", str(ctx.exception))

    def test_start_and_errors(self):
        backend = self.make()
        backend.start("work")
        self.assertEqual(self.vms[2].calls, ["start"])
        with self.assertRaises(BackendError):
            backend.shutdown("sys-vpn")
        with self.assertRaises(BackendError):
            backend.start("nope")

    def test_bad_method(self):
        with self.assertRaises(ValueError):
            self.make("sudo")


class MockBackendTest(unittest.TestCase):
    def setUp(self):
        self.backend = MockBackend(delay=0)

    def test_kinds(self):
        self.assertTrue(create_backend("mock").is_demo)
        with self.assertRaises(ValueError):
            create_backend("nope")

    def test_connect_cycle(self):
        clock = [0.0]
        backend = MockBackend(delay=0, clock=lambda: clock[0])
        answer = backend.connect("sys-vpn-secure", "work-gateway-tcp")
        self.assertEqual(answer.get("state"), "connecting")
        clock[0] += 5
        self.assertEqual(backend.status("sys-vpn-secure").get("state"), "connected")
        self.assertEqual(backend.disconnect("sys-vpn-secure").get("state"), "disconnected")

    def test_halted_qube_refuses(self):
        with self.assertRaises(BackendError):
            self.backend.status("sys-vpn-de")

    def test_profiles(self):
        answer = self.backend.profiles("sys-vpn")
        self.assertEqual(answer.get("active"), "se-got-wg-001")
        self.assertIn(protocol.Profile("ch-zrh-ovpn", "openvpn"), answer.profiles)

    def test_netvm_rules(self):
        with self.assertRaises(BackendError):
            self.backend.set_netvm("personal", "sys-vpn-de")  # halted net qube
        with self.assertRaises(BackendError):
            self.backend.shutdown("sys-vpn")  # has running clients
        self.backend.start("sys-vpn-de")
        self.backend.set_netvm("personal", "sys-vpn-de")
        self.assertEqual(self.backend.inventory().qubes["personal"].netvm, "sys-vpn-de")


if __name__ == "__main__":
    os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    unittest.main()
