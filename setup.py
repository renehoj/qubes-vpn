#!/usr/bin/env python3
"""Packaging for the qubes-vpn manager (the agent installs with agent/install.sh)."""

import setuptools

setuptools.setup(
    name="qubes_vpn",
    version="0.1.0",
    description="VPN manager for Qubes OS, in qubes-systemlist's look",
    packages=["qubes_vpn", "qubes_vpn.backend"],
    python_requires=">=3.9",
    # Without these the window raises FileNotFoundError when it opens, only on
    # a real install.
    package_data={"qubes_vpn": ["vpn.css", "fallback-theme.css"]},
    entry_points={
        "gui_scripts": [
            "qubes-vpn = qubes_vpn.frontend:main",
        ],
        "console_scripts": [
            "qubes-vpn-cli = qubes_vpn.cli:main",
        ],
    },
)
