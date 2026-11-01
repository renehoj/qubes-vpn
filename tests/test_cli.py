"""The headless commands, against the demo data."""

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qubes_vpn import cli  # noqa: E402


def run(*argv):
    out = io.StringIO()
    code = cli.main(["--mock", *argv], out=out)
    return code, out.getvalue()


class CliTest(unittest.TestCase):
    def test_tree(self):
        code, text = run()
        self.assertEqual(code, 0)
        lines = text.splitlines()
        self.assertEqual(lines[0], "2 of 3 tunnels up · 4 of 6 client qubes through a VPN")
        self.assertTrue(lines[1].startswith("Qube"))
        self.assertTrue(lines[2].startswith("sys-vpn "))
        self.assertTrue(lines[3].startswith("  sys-vpn-secure"))
        self.assertTrue(lines[4].startswith("    disp1234"))
        self.assertIn("Not through a VPN", text)

    def test_status(self):
        _code, text = run("status", "sys-vpn")
        self.assertIn("state=connected\n", text)
        self.assertIn("killswitch=on\n", text)

    def test_stats(self):
        _code, text = run("stats", "sys-vpn")
        self.assertIn("vif=10.137.0.31 rx=", text)

    def test_profiles(self):
        _code, text = run("profiles", "sys-vpn-secure")
        self.assertIn("profile=work-gateway (OpenVPN)", text)

    def test_connect_and_disconnect(self):
        code, text = run("connect", "sys-vpn", "nl-ams-wg-002")
        self.assertEqual(code, 0)
        self.assertIn("result=ok", text)
        code, text = run("disconnect", "sys-vpn")
        self.assertIn("state=disconnected", text)

    def test_errors(self):
        self.assertEqual(run("connect", "sys-vpn", "nope")[0], 1)
        self.assertEqual(run("status", "sys-vpn-de")[0], 1)
        self.assertEqual(run("status", "@adminvm")[0], 1)

    def test_move(self):
        code, text = run("move", "personal", "none")
        self.assertEqual((code, text), (0, "personal: net qube none\n"))


if __name__ == "__main__":
    unittest.main()
