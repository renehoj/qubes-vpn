#!/bin/sh
# Install the VPN agent (the qrexec services vpn.*) for a VPN qube.
#
#   sudo ./install.sh --template   in the VPN qubes' template (recommended):
#                                  /usr/lib/qubes-vpn-agent, /etc/qubes-rpc,
#                                  /etc/systemd/system. Every qube based on the
#                                  template has the services; the boot units run
#                                  only where `qvm-service <qube> vpn-agent on`.
#   sudo ./install.sh --appvm      in one AppVM, without touching the template:
#                                  /usr/local (kept in /rw/usrlocal), units in
#                                  /rw/config/vpn/systemd, started from
#                                  /rw/config/rc.local at every boot. The kill
#                                  switch then comes up later in the boot.
#
# Either way, profiles and keys live in the VPN qube's /rw/config/vpn, which
# survives restarts and is never in the template.
set -eu

usage() {
    sed -n '2,16s/^# \{0,1\}//p' "$0"
}

mode=template
case "${1:-}" in
    ""|--template) ;;
    --appvm) mode=appvm ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "install.sh: run as root (sudo)" >&2
    exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)
if [ "$mode" = template ]; then
    libdir=/usr/lib/qubes-vpn-agent
    rpcdir=/etc/qubes-rpc
    unitdir=/etc/systemd/system
else
    libdir=/usr/local/lib/qubes-vpn-agent
    rpcdir=/usr/local/etc/qubes-rpc
    unitdir=/rw/config/vpn/systemd
fi
agent=$libdir/vpn-agent

install -d -m 0755 "$libdir/qubes_vpn_agent" "$rpcdir"
install -m 0644 "$here"/qubes_vpn_agent/*.py "$libdir/qubes_vpn_agent/"
sed "s|@LIBDIR@|$libdir|g" "$here/vpn-agent.in" > "$agent"
chmod 0755 "$agent"

for service in "$here"/qubes-rpc/vpn.*; do
    target="$rpcdir/$(basename "$service")"
    sed "s|@AGENT@|$agent|g" "$service" > "$target"
    chmod 0755 "$target"
done

install -d -m 0755 "$unitdir"
for unit in "$here"/systemd/*.service; do
    target="$unitdir/$(basename "$unit")"
    if [ "$mode" = appvm ]; then
        # Installed in this qube only: no qvm-service switch to wait for.
        sed -e "s|@AGENT@|$agent|g" -e '/^ConditionPathExists=/d' "$unit" > "$target"
    else
        sed "s|@AGENT@|$agent|g" "$unit" > "$target"
    fi
    chmod 0644 "$target"
done

if [ "$mode" = template ]; then
    systemctl daemon-reload
    systemctl enable qubes-vpn-killswitch.service qubes-vpn-autoconnect.service
else
    install -d -m 0700 /rw/config/vpn /rw/config/vpn/wireguard /rw/config/vpn/openvpn
    rclocal=/rw/config/rc.local
    marker="# qubes-vpn-agent"
    if ! grep -qF "$marker" "$rclocal" 2>/dev/null; then
        [ -e "$rclocal" ] || printf '#!/bin/sh\n' > "$rclocal"
        cat >> "$rclocal" <<RC

$marker
cp $unitdir/*.service /run/systemd/system/
systemctl daemon-reload
systemctl start qubes-vpn-killswitch.service qubes-vpn-autoconnect.service
RC
    fi
    chmod 0755 "$rclocal"
    cp "$unitdir"/*.service /run/systemd/system/
    systemctl daemon-reload
    systemctl start qubes-vpn-killswitch.service
fi

missing=""
for tool in wg wg-quick openvpn nft ping; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
if [ -n "$missing" ]; then
    echo "install.sh: not found:$missing" >&2
    echo "  Debian: apt install wireguard-tools openvpn nftables iputils-ping" >&2
    echo "  Fedora: dnf install wireguard-tools openvpn nftables iputils" >&2
fi
echo "Installed the VPN agent ($mode) in $libdir."
