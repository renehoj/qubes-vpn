"""The agent in a fake VPN qube: services, both protocols, kill switch, stats."""

import io
import json
import os
import sys
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentfakes import WG_PROFILE, FakeManagement, FakeQube  # noqa: E402
from qubes_vpn_agent import killswitch, openvpn, output, profiles, service, stats, wireguard  # noqa: E402,E501


class OutputTest(unittest.TestCase):
    def test_values_cannot_break_lines(self):
        text = output.render([("profile", "a\nstate=connected"), ("n", 3), ("x", None)])
        self.assertEqual(text, "profile=a_state_connected\nn=3\n")

    def test_bad_key_is_a_bug(self):
        with self.assertRaises(ValueError):
            output.render([("Bad Key", 1)])

    def test_long_value_is_cut(self):
        self.assertEqual(len(output.clean("a" * 1000)), output.MAX_VALUE)


class ProfilesTest(unittest.TestCase):
    def setUp(self):
        self.qube = FakeQube()
        self.addCleanup(self.qube.cleanup)

    def test_names(self):
        for name in ("se1", "mullvad-se-got-wg-001", "a.b_c"):
            self.assertTrue(profiles.valid_name(name), name)
        for name in ("", "-x", "../etc", "a/b", "a b", "x" * 33, "x.", "é"):
            self.assertFalse(profiles.valid_name(name), name)

    def test_listing(self):
        self.qube.profile("wireguard", "se1")
        self.qube.profile("openvpn", "de1")
        self.qube.profile("openvpn", "bad name")
        Path(self.qube.paths.openvpn_dir, "notes.txt").write_text("x")
        os.symlink("/etc/passwd", os.path.join(self.qube.paths.wireguard_dir, "link.conf"))
        found = profiles.list_profiles(self.qube.paths.wireguard_dir, self.qube.paths.openvpn_dir)
        self.assertEqual([(p.name, p.protocol) for p in found],
                         [("de1", "openvpn"), ("se1", "wireguard")])

    def test_find(self):
        self.qube.profile("wireguard", "se1")
        self.qube.profile("wireguard", "dup")
        self.qube.profile("openvpn", "dup")
        dirs = (self.qube.paths.wireguard_dir, self.qube.paths.openvpn_dir)
        self.assertEqual(profiles.find_profile("se1", *dirs).protocol, "wireguard")
        for name, code in (("nope", "unknown-profile"), ("dup", "ambiguous-profile"),
                           ("../x", "bad-argument")):
            with self.assertRaises(profiles.ProfileError) as ctx:
                profiles.find_profile(name, *dirs)
            self.assertEqual(ctx.exception.code, code)


class WireGuardTest(unittest.TestCase):
    def test_prepare_config(self):
        config, dns = wireguard.prepare_config(WG_PROFILE)
        self.assertEqual(dns, ["10.64.0.1"])
        self.assertNotIn("DNS", config)
        self.assertIn("Address = 10.64.12.7/32\n", config)
        self.assertIn("AllowedIPs = 0.0.0.0/0\n", config)
        self.assertIn("Endpoint = 185.65.134.2:51820", config)
        self.assertNotIn("fc00", config)

    def test_parse_dump(self):
        peers = wireguard.parse_dump(
            "k\tp\t1\toff\nx\t(none)\t1.2.3.4:51820\t0.0.0.0/0\t100\t5\t6\toff\nshort\n")
        self.assertEqual(peers, [wireguard.Peer("1.2.3.4:51820", 100, 5, 6)])

    def test_states(self):
        from qubes_vpn_agent.system import Result
        dump = lambda hs: Result(0, f"k\tp\t1\toff\nx\t(none)\te:1\t0.0.0.0/0\t{hs}\t1\t2\toff\n")
        addr = Result(1)
        self.assertEqual(wireguard.probe(dump(990), addr, 900, 1000)["state"], "connected")
        self.assertEqual(wireguard.probe(dump(990), addr, 900, 1000)["handshake_age"], 10)
        self.assertEqual(wireguard.probe(dump(100), addr, 0, 1000)["state"], "stale")
        self.assertEqual(wireguard.probe(dump(0), addr, 990, 1000)["state"], "connecting")
        self.assertEqual(wireguard.probe(dump(0), addr, 0, 1000)["state"], "stale")
        self.assertEqual(wireguard.probe(Result(1), addr, 0, 1000), {})


class OpenVpnTest(unittest.TestCase):
    def test_parse_state(self):
        state = openvpn.parse_state(["1700000000,CONNECTED,SUCCESS,10.8.0.6,198.51.100.7,1194,,"])
        self.assertEqual(state, {"name": "CONNECTED", "local_ip": "10.8.0.6",
                                 "remote_ip": "198.51.100.7", "remote_port": "1194"})

    def test_parse_status(self):
        counts = openvpn.parse_status(["OpenVPN STATISTICS", "Updated,2026-10-31 12:00:00",
                                       "TCP/UDP read bytes,4242", "TUN/TAP write bytes,x"])
        self.assertEqual(counts, {"TCP/UDP read bytes": 4242})

    def test_pushed_dns(self):
        env = {"foreign_option_2": "dhcp-option DNS 10.8.0.2",
               "foreign_option_1": "dhcp-option DNS 10.8.0.1",
               "foreign_option_3": "dhcp-option DOMAIN example.com",
               "foreign_option_4": "dhcp-option DNS fd00::1",
               "dns_server_1_address_1": "10.8.0.1",
               "dns_server_1_address_2": "10.9.9.9"}
        self.assertEqual(openvpn.pushed_dns(env), ["10.8.0.1", "10.8.0.2", "10.9.9.9"])

    def test_management_socket(self):
        qube = FakeQube()
        self.addCleanup(qube.cleanup)
        mgmt = FakeManagement(qube.paths.mgmt_socket, {
            "state": ">LOG:1,I,noise\r\n1700000000,CONNECTED,SUCCESS,10.8.0.6,198.51.100.7,"
                     "1194,,\r\nEND\r\n",
            "status": "OpenVPN STATISTICS\r\nTCP/UDP read bytes,500\r\n"
                      "TCP/UDP write bytes,600\r\nEND\r\n",
        })
        self.addCleanup(mgmt.close)
        info = openvpn.probe(openvpn.Management(qube.paths.mgmt_socket))
        self.assertEqual(info["state"], "connected")
        self.assertEqual(info["endpoint"], "198.51.100.7:1194")
        self.assertEqual(info["link_rx_bytes"], 500)

    def test_no_socket(self):
        self.assertEqual(openvpn.probe(openvpn.Management("/nonexistent/sock")), {})

    def test_asks_for_credentials(self):
        self.assertTrue(openvpn.asks_for_credentials("client\nauth-user-pass\nremote x 1194\n"))
        self.assertTrue(openvpn.asks_for_credentials("  auth-user-pass   # proton\n"))
        for text in ("client\n", "auth-user-pass pass.txt\n", "# auth-user-pass\n",
                     "; auth-user-pass\n", "<auth-user-pass>\nu\np\n</auth-user-pass>\n"):
            with self.subTest(text=text):
                self.assertFalse(openvpn.asks_for_credentials(text))

    def test_credentials_format(self):
        self.assertTrue(openvpn.valid_credentials("user+pmp\nsecret\n"))
        for text in ("", "user\n", "\nsecret\n", "user\n\n"):
            self.assertFalse(openvpn.valid_credentials(text))
        self.assertEqual(openvpn.format_credentials("u", "p w"), "u\np w\n")
        for user, password in (("", "p"), ("u", ""), ("u", "p\nx"), ("u\r", "p")):
            with self.assertRaises(ValueError):
                openvpn.format_credentials(user, password)


class KillSwitchTest(unittest.TestCase):
    def test_without_dns_no_dnat(self):
        text = killswitch.render([])
        self.assertIn('oifname { "vpn-wg", "vpn-tun" } accept', text)
        self.assertIn('iifname "vif*" counter drop', text)
        self.assertIn("meta nfproto ipv6", text)
        self.assertNotIn("dnat ip to", text)
        self.assertTrue(text.startswith("table inet qubes-vpn {}\ndelete table inet qubes-vpn\n"))

    def test_dns(self):
        text = killswitch.render(["10.64.0.1"])
        self.assertIn("ip daddr 10.139.1.1 meta l4proto { tcp, udp } th dport 53 "
                      "counter dnat ip to 10.64.0.1", text)
        self.assertIn("ip daddr 10.139.1.2 meta l4proto { tcp, udp } th dport 53 "
                      "counter dnat ip to 10.64.0.1", text)
        two = killswitch.render(["10.64.0.1", "10.64.0.2"])
        self.assertIn("10.139.1.2 meta l4proto { tcp, udp } th dport 53 counter dnat ip to "
                      "10.64.0.2", two)

    def test_refuses_garbage_dns(self):
        with self.assertRaises(ValueError):
            killswitch.render(["1.2.3.4; flush ruleset"])


class StatsTest(unittest.TestCase):
    def test_vif_addresses(self):
        text = ("Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n"
                "vif12.0\t0F00890A\t00000000\t0005\t0\t0\t32\tFFFFFFFF\n"
                "eth0\t00000000\t0100890A\t0003\t0\t0\t0\t00000000\n"
                "vif13.0\t0000890A\t00000000\t0001\t0\t0\t0\t00FFFFFF\n")
        self.assertEqual(stats.vif_addresses(text), {"vif12.0": "10.137.0.15"})

    def test_parse_ping(self):
        self.assertEqual(stats.parse_ping("64 bytes from 10.64.0.1: icmp_seq=1 ttl=64 "
                                          "time=23.4 ms"), 23.4)
        self.assertIsNone(stats.parse_ping("1 packets transmitted, 0 received"))


class RunnerTest(unittest.TestCase):
    def test_finds_sbin_without_path(self):
        # As OpenVPN runs the up/down script: no PATH at all.
        from qubes_vpn_agent.system import Runner
        with mock.patch.dict(os.environ, {}, clear=True):
            result = Runner().run(["env"])
        self.assertIn("PATH=/usr/sbin:", result.stdout)


class AgentTest(unittest.TestCase):
    def setUp(self):
        self.qube = FakeQube()
        self.addCleanup(self.qube.cleanup)
        self.runner = self.qube.runner

    def run_service(self, *argv, environ=None):
        out = io.StringIO()
        code = service.main(list(argv), agent=self.qube.agent, out=out, environ=environ or {})
        return code, dict(line.split("=", 1) for line in out.getvalue().splitlines()
                          if not line.startswith("vif=")), out.getvalue()

    def test_disconnected(self):
        code, values, _ = self.run_service("status")
        self.assertEqual(code, 0)
        self.assertEqual(values, {"state": "disconnected", "killswitch": "off"})

    def test_list_profiles(self):
        self.qube.profile("wireguard", "se1")
        self.qube.profile("openvpn", "de1")
        _code, _values, text = self.run_service("list-profiles")
        self.assertEqual(text, "profile=de1:openvpn\nprofile=se1:wireguard\n")

    def test_connect_wireguard(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        self.qube.wg_up(handshake=self.qube.now - 42)
        code, values, _ = self.run_service("connect", environ={"QREXEC_SERVICE_ARGUMENT": "se1"})
        self.assertEqual(code, 0)
        self.assertEqual(values["result"], "ok")
        self.assertEqual(values["state"], "connected")
        self.assertEqual(values["protocol"], "wireguard")
        self.assertEqual(values["handshake_age"], "42")
        self.assertEqual(values["endpoint"], "185.65.134.2:51820")
        self.assertEqual(values["tunnel_ip"], "10.64.12.7")
        self.assertEqual(values["dns"], "10.64.0.1")
        self.assertEqual(values["killswitch"], "on")
        # Kill switch with the VPN's DNS before the tunnel starts.
        nft = self.runner.calls.index(["nft", "-f", "-"])
        start = self.runner.calls.index(["systemctl", "start", "qubes-vpn-wireguard.service"])
        self.assertLess(nft, start)
        self.assertIn("dnat ip to 10.64.0.1", self.runner.inputs[-1])
        conf = Path(self.qube.paths.wg_conf)
        self.assertNotIn("DNS", conf.read_text())
        self.assertEqual(conf.stat().st_mode & 0o777, 0o600)

    def test_connect_argument_from_argv(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        code, values, _ = self.run_service("connect", "se1")
        self.assertEqual((code, values["result"]), (0, "ok"))

    def test_connect_refuses_bad_names(self):
        for name in ("", "../../etc/shadow", "se1;reboot", "x" * 40):
            code, values, _ = self.run_service("connect", environ={"QREXEC_SERVICE_ARGUMENT": name})
            self.assertEqual((code, values), (1, {"result": "error", "error": "bad-argument"}))
        self.assertEqual(self.runner.calls, [])

    def test_connect_unknown(self):
        _code, values, _ = self.run_service("connect", "nope")
        self.assertEqual(values["error"], "unknown-profile")

    def test_no_tunnel_without_kill_switch(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        self.runner.set(["nft", "-f", "-"], 1)
        with self.assertLogs("qubes-vpn-agent", "ERROR"):
            _code, values, _ = self.run_service("connect", "se1")
        self.assertEqual(values["error"], "killswitch-failed")
        self.assertNotIn(["systemctl", "start", "qubes-vpn-wireguard.service"], self.runner.calls)

    def test_start_failure(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        self.runner.set(["systemctl", "start", "qubes-vpn-wireguard.service"], 1)
        _code, values, _ = self.run_service("connect", "se1")
        self.assertEqual(values["error"], "start-failed")
        self.assertFalse(os.path.exists(self.qube.paths.active))
        self.assertNotIn("dnat ip to", self.runner.inputs[-1])

    def test_connect_openvpn(self):
        path = self.qube.profile("openvpn", "de1")
        self.runner.set(["systemctl", "is-active", "qubes-vpn-openvpn.service"], 3, "activating\n")
        _code, values, _ = self.run_service("connect", "de1")
        self.assertEqual(values["state"], "connecting")
        self.assertIn(["systemctl", "start", "--no-block", "qubes-vpn-openvpn.service"],
                      self.runner.calls)
        env = Path(self.qube.paths.openvpn_env).read_text()
        self.assertIn(f"PROFILE={path}\n", env)
        # The server pushes DNS: the up script DNATs to it.
        self.run_service("openvpn-event", environ={
            "script_type": "up", "foreign_option_1": "dhcp-option DNS 10.8.0.1"})
        self.assertIn("dnat ip to 10.8.0.1", self.runner.inputs[-1])
        self.assertEqual(json.loads(Path(self.qube.paths.active).read_text())["dns"],
                         ["10.8.0.1"])
        self.run_service("openvpn-event", environ={"script_type": "down"})
        self.assertNotIn("dnat ip to", self.runner.inputs[-1])

    def openvpn_env(self):
        return Path(self.qube.paths.openvpn_env).read_text()

    def test_openvpn_without_credentials(self):
        self.qube.profile("openvpn", "de1")
        self.run_service("connect", "de1")
        self.assertIn("AUTH_ARGS=\n", self.openvpn_env())

    def test_openvpn_refuses_to_prompt(self):
        self.qube.profile("openvpn", "nl-free-1", "client\nauth-user-pass\n")
        code, values, _ = self.run_service("connect", "nl-free-1")
        self.assertEqual((code, values), (1, {"result": "error", "error": "no-credentials"}))
        self.assertFalse(any(call[:2] == ["systemctl", "start"] for call in self.runner.calls))
        self.assertFalse(os.path.exists(self.qube.paths.active))

    def test_openvpn_credentials(self):
        self.qube.profile("openvpn", "nl-free-1", "client\nauth-user-pass\n")
        self.qube.profile("openvpn", "se-free-2", "client\nauth-user-pass\n")
        directory = self.qube.paths.openvpn_dir
        default = os.path.join(directory, "default.auth")
        own = os.path.join(directory, "se-free-2.auth")
        Path(default).write_text("user+pmp\nsecret\n")
        Path(own).write_text("other\nsecret2\n")
        _code, values, _ = self.run_service("connect", "nl-free-1")
        self.assertEqual(values["result"], "ok")
        self.assertIn(f"AUTH_ARGS=--auth-user-pass {default}\n", self.openvpn_env())
        self.run_service("connect", "se-free-2")
        self.assertIn(f"AUTH_ARGS=--auth-user-pass {own}\n", self.openvpn_env())
        # The .auth files are not profiles.
        _code, _values, text = self.run_service("list-profiles")
        self.assertNotIn("default", text)

    def test_openvpn_bad_credentials_file(self):
        self.qube.profile("openvpn", "de1")
        Path(self.qube.paths.openvpn_dir, "default.auth").write_text("only-a-user\n")
        _code, values, _ = self.run_service("connect", "de1")
        self.assertEqual(values["error"], "bad-credentials")

    def test_credentials_command(self):
        answers = {"Username: ": "user+pmp", "Password: ": "s3cret pass"}
        asked = []

        def ask(prompt, secret):
            asked.append((prompt, secret))
            return answers[prompt]

        for argv, name in ((["credentials"], "default"), (["credentials", "se1"], "se1")):
            out = io.StringIO()
            code = service.main(argv, agent=self.qube.agent, out=out, environ={}, ask=ask)
            self.assertEqual((code, out.getvalue()), (0, "result=ok\n"))
            path = Path(self.qube.paths.openvpn_dir, f"{name}.auth")
            self.assertEqual(path.read_text(), "user+pmp\ns3cret pass\n")
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(asked[:2], [("Username: ", False), ("Password: ", True)])

    def test_credentials_command_refusals(self):
        for argv, answer, code in ((["credentials", "../x"], "u", "bad-argument"),
                                   (["credentials"], "", "bad-credentials")):
            out = io.StringIO()
            service.main(argv, agent=self.qube.agent, out=out, environ={},
                         ask=lambda _prompt, _secret, a=answer: a)
            self.assertEqual(out.getvalue(), f"result=error\nerror={code}\n")
        self.assertEqual(os.listdir(self.qube.paths.openvpn_dir), [])

    def test_openvpn_connected_via_management(self):
        self.qube.profile("openvpn", "de1")
        mgmt = FakeManagement(self.qube.paths.mgmt_socket, {
            "state": "1700000000,CONNECTED,SUCCESS,10.8.0.6,198.51.100.7,1194,,\r\nEND\r\n",
            "status": "TCP/UDP read bytes,1\r\nTCP/UDP write bytes,2\r\nEND\r\n",
        })
        self.addCleanup(mgmt.close)
        _code, values, _ = self.run_service("connect", "de1")
        self.assertEqual(values["state"], "connected")
        self.assertEqual(values["tunnel_ip"], "10.8.0.6")

    def test_connect_stops_the_other_tunnel_first(self):
        self.qube.profile("openvpn", "de1")
        self.run_service("connect", "de1")
        stops = [c for c in self.runner.calls if c[:2] == ["systemctl", "stop"]]
        self.assertEqual({c[2] for c in stops},
                         {"qubes-vpn-wireguard.service", "qubes-vpn-openvpn.service"})

    def test_disconnect(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        self.run_service("connect", "se1")
        _code, values, _ = self.run_service("disconnect")
        self.assertEqual(values, {"result": "ok", "state": "disconnected", "killswitch": "on"})
        self.assertFalse(os.path.exists(self.qube.paths.wg_conf))
        self.assertNotIn("dnat ip to", self.runner.inputs[-1])

    def test_tunnel_gone_is_reported(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        self.run_service("connect", "se1")
        self.runner.set(["systemctl", "is-active", "qubes-vpn-wireguard.service"], 3, "failed\n")
        _code, values, _ = self.run_service("status")
        self.assertEqual((values["state"], values["error"]), ("error", "tunnel-failed"))

    def test_stats(self):
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        self.qube.wg_up(handshake=self.qube.now - 5)
        self.qube.interface("vpn-wg", rx=1000, tx=200, rx_packets=10, tx_packets=4)
        self.qube.interface("vif12.0", rx=52311021, tx=4422109)
        self.qube.routes([("vif12.0", "0F00890A", "FFFFFFFF")])
        self.runner.set(["ping", "-n", "-c", "1", "-W", "1", "-I", "vpn-wg", "10.64.0.1"], 0,
                        "64 bytes from 10.64.0.1: icmp_seq=1 ttl=64 time=23.4 ms\n")
        self.run_service("connect", "se1")
        self.qube.now += 60
        _code, values, text = self.run_service("stats")
        self.assertEqual(values["rx_bytes"], "1000")
        self.assertEqual(values["tx_packets"], "4")
        self.assertEqual(values["uptime"], "60")
        self.assertEqual(values["handshake_age"], "65")
        self.assertEqual(values["latency_ms"], "23.4")
        self.assertIn("vif=10.137.0.15:52311021:4422109\n", text)
        # Cached: no second ping within LATENCY_TTL.
        self.run_service("stats")
        self.assertEqual(sum(c[0] == "ping" for c in self.runner.calls), 1)

    def test_autoconnect(self):
        _code, values, _ = self.run_service("autoconnect")
        self.assertEqual(values["state"], "disconnected")
        self.qube.profile("wireguard", "se1", WG_PROFILE)
        Path(self.qube.paths.agent_conf).write_text("# boot\nautoconnect = se1\n")
        _code, values, _ = self.run_service("autoconnect")
        self.assertEqual(values["profile"], "se1")

    def test_unknown_command(self):
        self.assertEqual(service.main(["reboot"], agent=self.qube.agent, out=io.StringIO()), 2)

    def test_internal_errors_stay_in_the_qube(self):
        def boom():
            raise RuntimeError("secret detail /rw/config/vpn/key")
        self.qube.agent.status = boom
        out = io.StringIO()
        with self.assertLogs("qubes-vpn-agent", "ERROR"):
            service.main(["status"], agent=self.qube.agent, out=out)
        self.assertEqual(out.getvalue(), "result=error\nerror=internal\n")


if __name__ == "__main__":
    unittest.main()
