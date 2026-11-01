# Installing qubes-vpn

For Qubes OS 4.2 or later, Debian 13 templates, WireGuard and OpenVPN run
directly (wg-quick, openvpn) under systemd, without NetworkManager.

The names below are examples: `debian-13-minimal` (template),
`debian-13-vpn` (a clone for the VPN qubes), `sys-vpn` (a VPN qube),
`vpn-manager` (the manager), `personal` (a client qube), `dev` (the qube that
has this checkout).

Commands marked **dom0** run in a dom0 terminal; the others in the qube
named.

## 1. A template for the VPN qubes

**dom0:**

```bash
qvm-clone debian-13-minimal debian-13-vpn
```

In `debian-13-vpn` (as root: `qvm-run -u root debian-13-vpn xterm`):

```bash
apt install qubes-core-agent-networking wireguard-tools openvpn nftables iputils-ping python3
```

Copy the agent into the template. In `dev`:

```bash
qvm-copy-to-vm debian-13-vpn ~/src/qubes-vpn/agent
```

In `debian-13-vpn`:

```bash
sudo ~/QubesIncoming/dev/agent/install.sh --template
```

This puts the agent in `/usr/lib/qubes-vpn-agent`, the qrexec services in
`/etc/qubes-rpc/vpn.*` and the systemd units in `/etc/systemd/system`, and
enables `qubes-vpn-killswitch.service` and `qubes-vpn-autoconnect.service`.
Those two run only in qubes where the `vpn-agent` qvm-service is on (step 2);
the services answer only where the policy sends calls (`@tag:vpn`). Shut the
template down.

## 2. A VPN qube

**dom0:**

```bash
qvm-create --class AppVM --template debian-13-vpn --label blue sys-vpn
qvm-prefs sys-vpn provides_network true
qvm-prefs sys-vpn netvm sys-firewall
qvm-tags sys-vpn add vpn
qvm-service sys-vpn vpn-agent on
```

In `sys-vpn`, the profiles (copy them in with `qvm-copy`):

```bash
sudo install -d -m 0700 /rw/config/vpn /rw/config/vpn/wireguard /rw/config/vpn/openvpn
sudo install -m 0600 ~/QubesIncoming/*/se-got-wg-001.conf /rw/config/vpn/wireguard/
sudo install -m 0600 ~/QubesIncoming/*/work-gateway.ovpn /rw/config/vpn/openvpn/
```

An OpenVPN profile's certificates go beside it, in `/rw/config/vpn/openvpn`
(OpenVPN runs from that directory). Do not use `user`/`group` in an OpenVPN
profile: the down script needs root to put the DNS rules back.

### OpenVPN username and password

Profiles from providers such as ProtonVPN have a bare `auth-user-pass` line
and no credentials. Store them in the VPN qube:

```bash
sudo /usr/lib/qubes-vpn-agent/vpn-agent credentials
```

(`/usr/local/lib/…` after `install.sh --appvm`.) It asks for the username and
password and writes `/rw/config/vpn/openvpn/default.auth` (root only, 0600),
which every OpenVPN profile in that qube uses. For one profile only, name it:
`vpn-agent credentials work-gateway` writes `work-gateway.auth`, which wins
over `default.auth`. Run it again to change them.

The file is OpenVPN's own format, so you may also write it yourself: the
username on line 1, the password on line 2, mode 0600. The agent passes it
with `--auth-user-pass`, overriding the profile's own line; a profile that
asks for credentials when none are stored is refused (`no-credentials`)
instead of failing over and over.

For ProtonVPN, use the **OpenVPN / IKEv2 username and password** from
account.protonvpn.com (Account → OpenVPN / IKEv2), not your Proton login. The
username may carry suffixes such as `+pmp`.

Optional, `/rw/config/vpn/agent.conf`:

```ini
# Connect at boot.
autoconnect = se-got-wg-001
# What the latency is measured against (default: the VPN's DNS, else 1.1.1.1).
ping_target = 10.64.0.1
```

Restart `sys-vpn` and check the kill switch:

```bash
sudo nft list table inet qubes-vpn
```

More VPN qubes are made the same way. For VPN over VPN, give one VPN qube
another as net qube (`qvm-prefs sys-vpn-secure netvm sys-vpn`).

## 3. The vpn-manager qube

**dom0** (any GUI template with the packages below; the qube needs no
network):

```bash
qvm-create --class AppVM --template debian-13-xfce --label gray vpn-manager
qvm-prefs vpn-manager netvm ''
```

In its template:

```bash
sudo apt install python3-qubesadmin python3-gi python3-gi-cairo gir1.2-gtk-3.0
```

In `dev`:

```bash
qvm-copy-to-vm vpn-manager ~/src/qubes-vpn
```

In `vpn-manager`:

```bash
~/QubesIncoming/dev/qubes-vpn/packaging/install-manager.sh
```

This copies the manager to `~/.local/share/qubes-vpn` and starts the tray at
login (`~/.config/autostart/qubes-vpn.desktop`). The home directory keeps
both; the template is not changed.

To start `vpn-manager` with the desktop, **dom0:**

```bash
qvm-prefs vpn-manager autostart true
```

Optional, `~/.config/qubes-vpn/config.ini`:

```ini
[manager]
poll_interval = 3
netvm_method = admin
```

## 4. Client qubes

**dom0**, for each qube the manager may move between net qubes:

```bash
qvm-tags personal add vpn-client
```

Disposables: tag the disposable template (`qvm-tags browser-untrusted-dvm add
vpn-client`). Qubes copies a template's tags to each new disposable, so the
ones started from then on are listed; one that was already running is not,
and shows under its VPN qube by address only, as *not listed*. Restart it, or
tag it too (`qvm-tags disp1234 add vpn-client`). Moving the disposable
template changes the net qube of disposables started later, not of running
ones.

## 5. The policy

**dom0:**

```bash
qvm-run --pass-io dev 'cat ~/src/qubes-vpn/policy/30-qubes-vpn.policy' | sudo tee /etc/qubes/policy.d/30-qubes-vpn.policy
```

If the qube is not called `vpn-manager`, change the source column. The file
explains every line. When Qubes has `qubes-policy-lint`, check it with:

```bash
sudo qubes-policy-lint /etc/qubes/policy.d/30-qubes-vpn.policy
```

The agent's services run as root (`user=root`) and never start a halted VPN
qube (`autostart=no`).

## 6. Check it from vpn-manager

```bash
qrexec-client-vm sys-vpn vpn.Status
qrexec-client-vm sys-vpn vpn.ListProfiles
qubes-vpn-cli
qubes-vpn-cli connect sys-vpn se-got-wg-001
qubes-vpn-cli stats sys-vpn
qubes-vpn-cli move personal sys-vpn
```

`Request refused` means the policy did not allow the call: check the tags,
the source name and the policy file.

Leak test, in `personal` behind `sys-vpn`:

```bash
curl -s https://am.i.mullvad.net/ip
```

Then disconnect `sys-vpn` and repeat: it must fail, DNS included
(`getent hosts example.com`).

## Optional: vpn.SetNetvm in dom0

`admin.vm.property.Set +netvm` lets the policy say which qubes the manager
may move, but not where to: it could give a `vpn-client` qube any net qube,
`sys-net` included. The optional dom0 service moves the new net qube into
the call's argument, where the policy can name each allowed one.

**dom0:**

```bash
qvm-run --pass-io dev 'cat ~/src/qubes-vpn/dom0/vpn.SetNetvm' | sudo tee /etc/qubes-rpc/vpn.SetNetvm > /dev/null
sudo chmod 0755 /etc/qubes-rpc/vpn.SetNetvm
qvm-run --pass-io dev 'cat ~/src/qubes-vpn/policy/31-qubes-vpn-setnetvm.policy' | sudo tee /etc/qubes/policy.d/31-qubes-vpn-setnetvm.policy
```

Read the service before installing it: it is the only qubes-vpn code that
runs in dom0 (60 lines, qubesadmin only). Edit `31-qubes-vpn-setnetvm.policy`
to list your net qubes, delete the `admin.vm.property.Set` line from
`30-qubes-vpn.policy`, and set `netvm_method = service` in vpn-manager's
`config.ini`.

## Persistence

An AppVM's root filesystem is reset at every start; only `/rw` (with `/home`
and `/usr/local`) survives.

| What | Where | Why there |
|---|---|---|
| agent code, qrexec services, systemd units | the template (`install.sh --template`) | present from the first moment of boot, so the kill switch is up before anything can be forwarded |
| … or, without changing the template | `/usr/local/lib/qubes-vpn-agent`, `/usr/local/etc/qubes-rpc`, units in `/rw/config/vpn/systemd` copied to `/run/systemd/system` by `/rw/config/rc.local` (`install.sh --appvm`) | one qube only; the kill switch comes up later in the boot, when `rc.local` runs |
| profiles, keys, OpenVPN credentials (`*.auth`), `agent.conf` | `/rw/config/vpn` in the VPN qube (root only) | per qube, never in the template, never in the manager |
| the active connection, the wg-quick copy | `/run/qubes-vpn` | meant to vanish at shutdown |
| manager code | `~/.local/share/qubes-vpn` in vpn-manager | the home directory survives; the template only needs the dependencies |
| manager settings, last profiles | `~/.config/qubes-vpn`, `~/.local/state/qubes-vpn` | |

`bind-dirs` is not needed: nothing the agent changes under `/etc` has to
survive a restart.

## Removing

**dom0:** `sudo rm /etc/qubes/policy.d/30-qubes-vpn.policy` (and
`31-…`, `/etc/qubes-rpc/vpn.SetNetvm`). In the template: `sudo systemctl
disable qubes-vpn-killswitch qubes-vpn-autoconnect` and remove
`/usr/lib/qubes-vpn-agent`, `/etc/qubes-rpc/vpn.*`,
`/etc/systemd/system/qubes-vpn-*.service`.
