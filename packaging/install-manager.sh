#!/bin/sh
# Install the VPN manager for the user, in the vpn-manager qube.
#
# Copies this checkout to ~/.local/share/qubes-vpn (the home directory
# survives restarts; the template is not touched) and starts the tray at
# login: ~/.config/autostart/qubes-vpn.desktop.
#
# The template needs the dependencies (Debian 13):
#   sudo apt install python3-qubesadmin python3-gi python3-gi-cairo gir1.2-gtk-3.0
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
dest=${XDG_DATA_HOME:-$HOME/.local/share}/qubes-vpn
autostart=${XDG_CONFIG_HOME:-$HOME/.config}/autostart

if [ "$here" != "$dest" ]; then
    rm -rf "$dest"
    mkdir -p "$dest"
    cp -r "$here/bin" "$here/qubes_vpn" "$dest/"
fi
mkdir -p "$autostart" "$HOME/.local/bin"
sed "s|^Exec=.*|Exec=$dest/bin/qubes-vpn --tray|" "$here/packaging/qubes-vpn.desktop" \
    > "$autostart/qubes-vpn.desktop"
ln -sf "$dest/bin/qubes-vpn" "$HOME/.local/bin/qubes-vpn"
ln -sf "$dest/bin/qubes-vpn-cli" "$HOME/.local/bin/qubes-vpn-cli"

for module in qubesadmin gi; do
    python3 -c "import $module" 2>/dev/null || echo "install-manager.sh: python3 cannot import $module; see the apt line in this script" >&2
done
echo "Installed in $dest; the tray starts at the next login (or run: qubes-vpn --tray)."
