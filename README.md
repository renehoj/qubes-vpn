<img width="889" height="636" alt="qubes-vpn" src="https://github.com/user-attachments/assets/c901ff80-0160-47d0-94ab-9383092d8c46" />

# qubes-vpn

A VPN manager for Qubes OS: several VPN qubes at once, WireGuard and OpenVPN,
in qubes-firewall's window. Nothing of it runs in dom0, which only holds the
qrexec policy (and, if you want it, one small whitelisted service).

```console
$ qubes-vpn --tray          # in the vpn-manager qube, autostarted
$ qubes-vpn                 # the window on its own
$ qubes-vpn-cli             # headless: the same overview as text
```

Installation, step by step: [docs/install.md](docs/install.md).

## The three parts

| Part | Runs in | What it is |
|---|---|---|
| **Agent** (`agent/`) | every VPN qube (tag `vpn`, `provides_network=True`) | qrexec services `vpn.*`, one interface over WireGuard (wg-quick) and OpenVPN (management socket), the kill switch and DNS rules |
| **Manager** (`qubes_vpn/`) | the `vpn-manager` qube (no net qube) | the tray icon and window; calls the agents over qrexec and qubesd over the Admin API (`qubesadmin`) |
| **Policy** (`policy/`) | dom0, `/etc/qubes/policy.d/` | who may call what; optionally `dom0/vpn.SetNetvm` |

## What the window shows

A tree: each VPN qube with what goes through it, VPN qubes behind it first
(VPN over VPN), then client qubes (tag `vpn-client`); last, the client qubes
that use no VPN. A qube behind a VPN qube without the `vpn-client` tag is not
on the list the policy gives the manager: it shows up under its VPN qube by
address only, as *not listed*, until you tag it.

| Column | |
|---|---|
| Qube | |
| State | VPN qube: connected, connecting…, no handshake (WireGuard, none for 180 s), disconnected, error, halted, no answer; client: running or halted |
| Profile | the profile the VPN qube is connected to, and its protocol |
| ↓ ↑ | download and upload speed, from the counters two polls apart |
| Details | latency through the tunnel, handshake age, uptime, endpoint; *kill switch off!* or the error, first. A client's address, or its net qube. The whole text is the row's tooltip |

Under the tree, the selected qube's traffic over the last six minutes (↓ in
red, ↑ in grey), the route its traffic takes (`disp1234 → sys-vpn-secure →
sys-vpn → sys-firewall`) and the byte totals. The subtitle counts tunnels up
and client qubes through a VPN.

The window polls every 3 seconds (2–5, `config.ini`): `vpn.Status` and
`vpn.Stats` of every running VPN qube, in parallel; halted ones are never
asked. The qube list (who runs, net qubes, addresses) is re-read every 15
seconds and after every action. Hidden behind the tray, it asks only
`vpn.Status`.

## Actions

| Button | |
|---|---|
| **Connect…** | the VPN qube's profiles (`vpn.ListProfiles`); **Connect** sends `vpn.Connect+<profile>`. The active and last used profile are marked |
| **Disconnect** | `vpn.Disconnect`. With running qubes behind it, asks first: the kill switch leaves them without network |
| **Start**, **Shut down** | the VPN qube (`admin.vm.Start`, `admin.vm.Shutdown`). Shut down refuses while qubes behind it run |
| **Move…** | a client qube's net qube: the VPN qubes (not ones that would make a loop), the other net qubes in use (`sys-firewall`), or none. Asks first when the qube would leave the VPNs, lose its network, or go to a VPN qube that is not connected; starts a halted VPN qube first |

Enter does the selected row's main thing: start a halted VPN qube, list a
running one's profiles, move a client qube. Errors stay in the footer, in red,
until the page changes.

The tray icon shows whether every running tunnel is up, something needs a
look (connecting, no handshake, error, kill switch off) or nothing is
connected; its tooltip lists the VPN qubes. Left click shows the window; the
menu connects (to the last profile) or disconnects each running VPN qube.

## Keys

| key | in the overview |
|---|---|
| Up / Down | select a qube |
| Enter (or double-click) | start / connect… / move… |
| Alt + underlined letter | Connect, Disconnect, Start, Shut down, Move, Close, Refresh |
| Ctrl+R, F5 | refresh now |
| Escape | close (hide, with the tray) |

| key | on the profile, move and confirm pages |
|---|---|
| Enter, Ctrl+Enter | connect / move / go ahead |
| Escape, Alt+B | back to the overview |

The confirm page starts with the focus on **Back**: Enter twice does not go
past a warning.

## The agent

| qrexec service | output |
|---|---|
| `vpn.ListProfiles` | `profile=<name>:<protocol>` per profile, `active=<name>` |
| `vpn.Connect+<profile>` | `result=ok` and the status, or `result=error`, `error=<code>` |
| `vpn.Disconnect` | the same |
| `vpn.Status` | `protocol`, `state`, `profile`, `interface`, `endpoint`, `tunnel_ip`, `since`, `dns`, `handshake_age`, `killswitch`, `error` |
| `vpn.Stats` | `rx_bytes`, `tx_bytes`, `rx_packets`, `tx_packets` (tunnel interface), `link_rx_bytes`, `link_tx_bytes`, `handshake_age`, `uptime`, `latency_ms`, and `vif=<address>:<rx>:<tx>` per downstream qube |

Output is `key=value` lines, for example:

    protocol=wireguard
    state=connected
    handshake_age=42
    rx_bytes=1834291022
    tx_bytes=98234110
    vif=10.137.0.15:52311021:4422109

`vif` counters are the VPN qube's view: `rx` is what that qube sent. The
manager maps the address to a qube with the Admin API's `ip` property.

Profiles live in the VPN qube, in `/rw/config/vpn/wireguard/<name>.conf` and
`/rw/config/vpn/openvpn/<name>.ovpn`; the name is the argument of
`vpn.Connect` and must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,31}`. OpenVPN
usernames and passwords live beside the profiles, in `openvpn/<name>.auth` or
`openvpn/default.auth` for all of them (`vpn-agent credentials [<profile>]`
writes them). Keys and passwords never leave the VPN qube.

- **WireGuard**: the agent copies the profile to `/run/qubes-vpn/vpn-wg.conf`
  without `DNS =` lines and IPv6 addresses, and starts
  `qubes-vpn-wireguard.service` (`wg-quick up`): interface `vpn-wg`. Status
  reads `wg show vpn-wg dump`; a handshake older than 180 s is *stale*.
- **OpenVPN**: `qubes-vpn-openvpn.service` runs the profile with
  `--dev vpn-tun`, `--management /run/openvpn/mgmt.sock unix`, the agent
  as up/down script and, when there is a credentials file,
  `--auth-user-pass <file>`; pushed IPv6 is filtered. Status asks the management
  socket `state` and `status`.
- **Kill switch** (`inet qubes-vpn`, an nftables table of its own beside
  Qubes'): from the `vif*` interfaces, IPv4 leaves only through `vpn-wg` or
  `vpn-tun`, everything else is dropped; IPv6 from downstream is dropped.
  It is loaded at boot and before every connect; a connect is refused if
  nft fails.
- **DNS**: 10.139.1.1 and 10.139.1.2 from downstream qubes are DNATed to the
  VPN's DNS servers (the profile's `DNS =`, or what the OpenVPN server
  pushed), ahead of Qubes' own DNAT. Without VPN DNS servers, Qubes' DNAT
  points them at the uplink and the kill switch drops them: no leak.
- **Persistence**: the code and units are in the template
  (`agent/install.sh --template`), or in `/usr/local` and `/rw/config`
  (`--appvm`); profiles in `/rw/config/vpn`; run-time state in
  `/run/qubes-vpn`. See [docs/install.md](docs/install.md#persistence).

## Security

- Everything a VPN qube says is untrusted (`protocol.py`): at most 16 KiB and
  400 lines, ASCII only, known keys only, every value checked against its
  type (numbers as numbers in range, states from a fixed list, addresses
  parsed, names by the profile pattern). A bad value is dropped, never
  "cleaned"; the window says how many lines it dropped. Error codes are only
  shown through a fixed table. The qrexec call itself is killed after 20
  seconds or 16 KiB.
- A VPN qube cannot move another qube's numbers: a `vif` address counts only
  for a qube whose net qube that VPN qube is.
- The agent checks `vpn.Connect`'s argument against the pattern and the
  profiles that exist, and reads nothing else from the caller.
- No keys or passwords in the manager or dom0: the manager knows profile
  names, nothing more.
- Known weakness: `admin.vm.property.Set +netvm` cannot be limited by value.
  The optional dom0 service `vpn.SetNetvm+<netvm>` puts the value in the
  argument, so the policy names the allowed net qubes
  ([docs/install.md](docs/install.md#optional-vpnsetnetvm-in-dom0)).

## Architecture

| Module | Responsibility |
|---|---|
| `protocol.py` | the agents' output: limits, schemas, validation, error texts |
| `model.py` | inventory, status, speeds and history, the poll (`Monitor`), the tree, texts and warnings |
| `backend/base.py` | `Backend` interface; checks names before and parses answers after every agent call |
| `backend/qrexec.py` | `qrexec-client-vm`, bounded in time and size |
| `backend/qubesadmin_backend.py` | the real thing: `qubesadmin` and qrexec |
| `backend/mock.py` | demo qubes and simulated agents (their answers go through the parser) |
| `settings.py` | `config.ini`, the last profile per VPN qube |
| `window.py` | `VpnWindow`, the graph, the poller; with `tray.py` and `frontend.py` the only modules importing `gi` |
| `tray.py` | the tray icon |
| `frontend.py` | `qubes-vpn [--tray]` |
| `cli.py` | headless use: the tree, status, stats, profiles, connect, disconnect, move |
| `vpn.css` | qubes-firewall's chrome, plus the tree and the graph |
| `agent/qubes_vpn_agent/` | the agent: `service` (commands), `agent` (both protocols), `wireguard`, `openvpn`, `killswitch`, `stats`, `profiles`, `output`, `system` |
| `dom0/vpn.SetNetvm` | the optional dom0 service |

Like qubes-firewall, the core (protocol, model, backends, cli, agent) does
not import `gi`, and imports `qubesadmin` only in the qubesadmin backend, so
it runs and is tested on any Linux box.

## Running

```console
$ bin/qubes-vpn --mock                  # from a checkout, demo data
$ bin/qubes-vpn --mock --tray
$ bin/qubes-vpn-cli --mock
$ bin/qubes-vpn-cli status sys-vpn      # in vpn-manager: one agent, validated
```

Anywhere without `qubesadmin`, `--backend auto` falls back to demo data.

Tests use the standard library only, with qrexec, qubesadmin, systemd, wg,
nft and the OpenVPN management socket faked; the window tests are skipped
without GTK 3 and a display (`xvfb-run sh run-tests.sh` runs them headless):

```console
$ ./run-tests.sh
```
