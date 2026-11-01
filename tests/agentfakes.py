"""A fake VPN qube for the agent tests: files under a temporary root, and a
command table instead of systemctl, wg, ip, nft and ping."""

import os
import socket
import sys
import tempfile
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "agent"))

from qubes_vpn_agent.agent import Agent  # noqa: E402
from qubes_vpn_agent.system import Paths, Result  # noqa: E402

WG_PROFILE = """\
[Interface]
PrivateKey = cGxhY2Vob2xkZXIgcHJpdmF0ZSBrZXkgZm9yIHRlc3Q=
Address = 10.64.12.7/32, fc00:bbbb:bbbb:bb01::c:b06/128
DNS = 10.64.0.1, fc00::1, example.internal

[Peer]
PublicKey = cGxhY2Vob2xkZXIgcHVibGljIGtleSBmb3IgdGVzdHM=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 185.65.134.2:51820
"""

WG_DUMP = ("privkey\tpubkey\t51820\toff\n"
           "peerkey\t(none)\t185.65.134.2:51820\t0.0.0.0/0\t{hs}\t1834291022\t98234110\toff\n")


class FakeRunner:
    """Answers commands from a table; records every call."""

    def __init__(self):
        self.calls = []
        self.inputs = []
        self.table = {}
        self.nft_table = False

    def set(self, argv, returncode=0, stdout=""):
        self.table[tuple(argv)] = Result(returncode, stdout)

    def run(self, argv, timeout=15.0, input_text=None):
        self.calls.append(list(argv))
        if argv[:2] == ["nft", "-f"]:
            self.inputs.append(input_text)
            result = self.table.get(tuple(argv), Result(0))
            self.nft_table = self.nft_table or result.ok
            return result
        if argv[:3] == ["nft", "list", "table"]:
            return Result(0 if self.nft_table else 1)
        return self.table.get(tuple(argv), Result(0 if argv[0] == "systemctl" else 1))


class FakeQube:
    def __init__(self, now=1_700_000_000.0):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = self._tmp.name
        self.paths = Paths.under(self.root)
        self.runner = FakeRunner()
        self.now = now
        self.agent = Agent(self.paths, self.runner, clock=lambda: self.now)
        os.makedirs(self.paths.wireguard_dir)
        os.makedirs(self.paths.openvpn_dir)
        os.makedirs(self.paths.sys_net)
        os.makedirs(os.path.dirname(self.paths.proc_route))

    def cleanup(self):
        self._tmp.cleanup()

    def profile(self, protocol, name, text="client\n"):
        directory = self.paths.wireguard_dir if protocol == "wireguard" else self.paths.openvpn_dir
        ext = ".conf" if protocol == "wireguard" else ".ovpn"
        path = os.path.join(directory, name + ext)
        Path(path).write_text(text)
        return path

    def interface(self, name, rx=0, tx=0, rx_packets=0, tx_packets=0):
        directory = Path(self.paths.sys_net, name, "statistics")
        directory.mkdir(parents=True, exist_ok=True)
        for key, value in (("rx_bytes", rx), ("tx_bytes", tx),
                           ("rx_packets", rx_packets), ("tx_packets", tx_packets)):
            (directory / key).write_text(f"{value}\n")

    def routes(self, rows):
        """rows: (interface, little-endian hex destination, mask)."""
        lines = ["Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT"]
        for interface, dest, mask in rows:
            lines.append(f"{interface}\t{dest}\t00000000\t0005\t0\t0\t32\t{mask}\t0\t0\t0")
        Path(self.paths.proc_route).write_text("\n".join(lines) + "\n")

    def wg_up(self, handshake):
        self.runner.set(["wg", "show", "vpn-wg", "dump"], 0, WG_DUMP.format(hs=int(handshake)))
        self.runner.set(["ip", "-4", "-o", "addr", "show", "dev", "vpn-wg"], 0,
                        "7: vpn-wg    inet 10.64.12.7/32 scope global vpn-wg\\ "
                        "valid_lft forever preferred_lft forever\n")


class FakeManagement:
    """An OpenVPN management socket on a unix socket, answering canned replies."""

    def __init__(self, path, replies):
        self.path = path
        self.replies = replies
        self.commands = []
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(path)
        self.server.listen(4)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while True:
            try:
                conn, _addr = self.server.accept()
            except OSError:
                return
            with conn:
                conn.sendall(b">INFO:OpenVPN Management Interface Version 5 -- type 'help'\r\n")
                data = b""
                while not data.endswith(b"\n"):
                    chunk = conn.recv(1024)
                    if not chunk:
                        break
                    data += chunk
                command = data.decode().strip()
                self.commands.append(command)
                conn.sendall(self.replies.get(command, "ERROR: unknown command\r\n").encode())

    def close(self):
        self.server.close()
