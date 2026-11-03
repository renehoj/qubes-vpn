"""dom0's vpn.SetNetvm service, against a fake qubesadmin app."""

import importlib.machinery
import importlib.util
import io
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "dom0" / "vpn.SetNetvm"
loader = importlib.machinery.SourceFileLoader("vpn_setnetvm", str(SCRIPT))
spec = importlib.util.spec_from_loader("vpn_setnetvm", loader)
service = importlib.util.module_from_spec(spec)
loader.exec_module(service)
service.syslog.syslog = lambda *args: None


class VM:
    def __init__(self, name, klass="AppVM", tags=(), provides_network=False):
        self.name = name
        self.klass = klass
        self.tags = set(tags)
        self.provides_network = provides_network
        self.netvm = "sys-firewall"


class App:
    def __init__(self):
        self.domains = {vm.name: vm for vm in (
            VM("dom0", "AdminVM", {"vpn-client"}),
            VM("personal", tags={"vpn-client"}),
            VM("vault"),
            VM("sys-vpn", tags={"vpn"}, provides_network=True),
            VM("work-files"),
        )}


def call(client, argument, app=None, **extra):
    environ = {"QREXEC_REQUESTED_TARGET": client, "QREXEC_SERVICE_ARGUMENT": argument,
               "QREXEC_REMOTE_DOMAIN": "vpn-manager", **extra}
    out = io.StringIO()
    app = app or App()
    code = service.main(environ, app, out)
    return code, out.getvalue(), app


class SetNetvmTest(unittest.TestCase):
    def test_moves_a_client(self):
        code, text, app = call("personal", "sys-vpn")
        self.assertEqual((code, text), (0, "result=ok\n"))
        self.assertIs(app.domains["personal"].netvm, app.domains["sys-vpn"])

    def test_none(self):
        _code, _text, app = call("personal", "none")
        self.assertIsNone(app.domains["personal"].netvm)

    def test_refusals(self):
        for client, argument, code in (
                ("vault", "sys-vpn", "not-a-client"),
                ("dom0", "sys-vpn", "not-a-client"),
                ("nope", "sys-vpn", "no-such-qube"),
                ("personal", "work-files", "not-a-netvm"),
                ("personal", "ghost", "no-such-netvm"),
                ("personal", "sys-vpn;x", "bad-argument"),
                ("", "sys-vpn", "bad-target"),
                ("@dispvm", "sys-vpn", "bad-target")):
            with self.subTest(client=client, argument=argument):
                status, text, app = call(client, argument)
                self.assertEqual((status, text), (1, f"result=error\nerror={code}\n"))
                if client in app.domains:
                    self.assertEqual(app.domains[client].netvm, "sys-firewall")

    def test_keyword_targets_are_refused(self):
        status, text, _app = call("personal", "sys-vpn", QREXEC_REQUESTED_TARGET_TYPE="keyword")
        self.assertEqual(status, 1)
        self.assertIn("bad-target", text)

    def test_qubesd_errors_are_not_echoed(self):
        app = App()

        class Angry(VM):
            def __setattr__(self, key, value):
                if key == "netvm" and hasattr(self, "netvm"):
                    raise RuntimeError("qubesd: secret details")
                super().__setattr__(key, value)

        app.domains["personal"] = Angry("personal", tags={"vpn-client"})
        status, text, _app = call("personal", "sys-vpn", app)
        self.assertEqual((status, text), (1, "result=error\nerror=qubesd-refused\n"))


if __name__ == "__main__":
    sys.exit(unittest.main())
