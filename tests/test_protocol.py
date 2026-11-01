"""The parser and validator for what VPN qubes answer: nothing unchecked gets through."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qubes_vpn import protocol  # noqa: E402


def lines(*items):
    return "".join(f"{item}\n" for item in items).encode("ascii")


class StatusTest(unittest.TestCase):
    def test_a_good_answer(self):
        answer = protocol.parse_status(lines(
            "protocol=wireguard", "state=connected", "profile=se-got-wg-001",
            "interface=vpn-wg", "endpoint=185.65.134.2:51820", "tunnel_ip=10.64.12.7",
            "since=1700000000", "dns=10.64.0.1", "handshake_age=42", "killswitch=on"))
        self.assertEqual(answer.dropped, 0)
        self.assertEqual(answer.get("handshake_age"), 42)
        self.assertEqual(answer.get("endpoint"), "185.65.134.2:51820")

    def test_bad_values_are_dropped_not_cleaned(self):
        answer = protocol.parse_status(lines(
            "state=pwned", "protocol=ipsec", "handshake_age=-1", "handshake_age=4.2",
            "since=99999999999999999999999", "profile=../../x", "tunnel_ip=10.0.0.999",
            "endpoint=<b>evil</b>:1", "killswitch=maybe", "interface=a b"))
        self.assertEqual(answer.values, {})
        self.assertEqual(answer.dropped, 10)

    def test_unknown_keys_and_junk_lines(self):
        answer = protocol.parse_status(lines(
            "state=connected", "rm_rf=yes", "no equals sign", "=empty", "State=connected",
            "profile=" + "a" * 300))
        self.assertEqual(answer.values, {"state": "connected"})
        self.assertEqual(answer.dropped, 5)

    def test_first_value_wins(self):
        answer = protocol.parse_status(lines("state=connected", "state=error"))
        self.assertEqual(answer.get("state"), "connected")

    def test_crlf(self):
        self.assertEqual(protocol.parse_status(b"state=connected\r\n").get("state"), "connected")

    def test_endpoints(self):
        good = ("1.2.3.4:51820", "[2001:db8::1]:1194", "vpn.example.com:443",
                "vpn.example.com", "2001:db8::1")
        bad = ("1.2.3.4:0", "1.2.3.4:70000", "host:port", "[nope]:1", "-x.example.com",
               "a" * 300, "[2001:db8::1]x")
        for text in good:
            self.assertEqual(protocol._endpoint(text), text, text)
        for text in bad:
            self.assertIsNone(protocol._endpoint(text), text)


class WholeAnswerTest(unittest.TestCase):
    def test_too_long(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_status(b"x" * (protocol.MAX_OUTPUT + 1))

    def test_too_many_lines(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_status(b"state=connected\n" * (protocol.MAX_LINES + 1))

    def test_not_ascii(self):
        with self.assertRaises(protocol.ProtocolError):
            protocol.parse_status("profile=é\n".encode())

    def test_empty(self):
        self.assertEqual(protocol.parse_status(b"").values, {})


class StatsTest(unittest.TestCase):
    def test_counters_and_vifs(self):
        answer = protocol.parse_stats(lines(
            "protocol=wireguard", "state=connected", "rx_bytes=1834291022",
            "tx_bytes=98234110", "latency_ms=23.4", "vif=10.137.0.15:52311021:4422109",
            "vif=10.137.0.16:1:2"))
        self.assertEqual(answer.get("rx_bytes"), 1834291022)
        self.assertEqual(answer.get("latency_ms"), 23.4)
        self.assertEqual(answer.vifs, [protocol.Vif("10.137.0.15", 52311021, 4422109),
                                       protocol.Vif("10.137.0.16", 1, 2)])

    def test_bad_vifs(self):
        answer = protocol.parse_stats(lines(
            "vif=10.137.0.15:1", "vif=evil:1:2", "vif=10.137.0.15:-1:2",
            "vif=2001:db8::1:1:2", "latency_ms=1e9"))
        self.assertEqual(answer.vifs, [])
        self.assertEqual(answer.dropped, 5)

    def test_vif_limit(self):
        data = b"".join(f"vif=10.137.{i // 256}.{i % 256}:1:2\n".encode()
                        for i in range(protocol.MAX_VIFS + 10))
        answer = protocol.parse_stats(data)
        self.assertEqual(len(answer.vifs), protocol.MAX_VIFS)
        self.assertEqual(answer.dropped, 10)


class ProfilesTest(unittest.TestCase):
    def test_profiles(self):
        answer = protocol.parse_profiles(lines(
            "profile=se1:wireguard", "profile=de1:openvpn", "profile=x:ipsec",
            "profile=bad name:openvpn", "active=se1"))
        self.assertEqual(answer.profiles, [protocol.Profile("se1", "wireguard"),
                                           protocol.Profile("de1", "openvpn")])
        self.assertEqual(answer.get("active"), "se1")
        self.assertEqual(answer.dropped, 2)


class NamesTest(unittest.TestCase):
    def test_qube_names(self):
        for name in ("sys-vpn", "vpn.manager", "a"):
            self.assertTrue(protocol.valid_qube_name(name))
        for name in ("", "-x", "1abc", "a b", "@adminvm", "x" * 32, "a+b"):
            self.assertFalse(protocol.valid_qube_name(name), name)

    def test_error_text_never_echoes_unknown_codes(self):
        self.assertIn("kill switch", protocol.error_text("killswitch-failed"))
        self.assertEqual(protocol.error_text("made-up"), "the VPN qube reported an error")
        self.assertEqual(protocol.error_text(None), "")


if __name__ == "__main__":
    unittest.main()
