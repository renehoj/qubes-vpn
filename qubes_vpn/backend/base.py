"""Backend interface shared by the qubesadmin and demo implementations.

Same split as qubes-firewall: the window only talks to a :class:`Backend`, and
everything crossing that boundary is plain data (an
:class:`~qubes_vpn.model.Inventory`, a validated
:class:`~qubes_vpn.protocol.Answer`), never qubesadmin objects or raw agent
output.

The ``vpn.*`` services go through :meth:`Backend._call`, which returns the raw
bytes; the base class checks every name before the call and parses every
answer after it, so no implementation can skip either.
"""

from __future__ import annotations

import abc

from .. import protocol
from ..model import Inventory
from ..protocol import Answer


class BackendError(Exception):
    """An operation failed; the message is meant to be shown to the user."""


class Backend(abc.ABC):
    """Talking to qubesd and to the agents in the VPN qubes.

    Every method may block (qrexec calls), so the window calls them from
    worker threads. Implementations must be thread-safe.
    """

    #: Shown in the window when it is not the real system.
    name = "backend"
    #: True when nothing this backend does touches a real system.
    is_demo = False

    # -- qubesd ----------------------------------------------------------
    @abc.abstractmethod
    def inventory(self) -> Inventory:
        """The qubes tagged ``vpn`` or ``vpn-client``."""

    @abc.abstractmethod
    def start(self, name: str) -> None:
        """Start a qube (admin.vm.Start); returns once it runs."""

    @abc.abstractmethod
    def shutdown(self, name: str) -> None:
        """Shut a qube down (admin.vm.Shutdown)."""

    @abc.abstractmethod
    def _set_netvm(self, client: str, netvm: str | None) -> None:
        """Make ``netvm`` (None: none) the net qube of ``client``."""

    def set_netvm(self, client: str, netvm: str | None) -> None:
        _check_qube(client)
        if netvm is not None:
            _check_qube(netvm)
        self._set_netvm(client, netvm)

    # -- the agents ------------------------------------------------------
    @abc.abstractmethod
    def _call(self, target: str, service: str, argument: str | None = None,
              stdin: bytes | None = None) -> bytes:
        """Run qrexec service ``service[+argument]`` in ``target``, with
        ``stdin`` as its input (None: none); its stdout."""

    def _ask(self, target: str, service: str, parse, argument: str | None = None,
             stdin: bytes | None = None) -> Answer:
        _check_qube(target)
        data = self._call(target, service, argument, stdin)
        try:
            return parse(data)
        except protocol.ProtocolError as exc:
            raise BackendError(f"{target} sent an answer that was refused: {exc}") from exc

    def status(self, vpn: str) -> Answer:
        return self._ask(vpn, "vpn.Status", protocol.parse_status)

    def stats(self, vpn: str) -> Answer:
        return self._ask(vpn, "vpn.Stats", protocol.parse_stats)

    def profiles(self, vpn: str) -> Answer:
        return self._ask(vpn, "vpn.ListProfiles", protocol.parse_profiles)

    def connect(self, vpn: str, profile: str) -> Answer:
        if not protocol.valid_profile_name(profile):
            raise BackendError("That is not a valid profile name.")
        return _checked(self._ask(vpn, "vpn.Connect", protocol.parse_status, profile))

    def disconnect(self, vpn: str) -> Answer:
        return _checked(self._ask(vpn, "vpn.Disconnect", protocol.parse_status))

    # -- settings (vpn.Configure+<key>, the value on stdin) ---------------
    def _configure(self, vpn: str, key: str, value: str) -> Answer:
        """Answers as :meth:`profiles` does, with the new settings."""
        if key not in protocol.CONFIG_KEYS:
            raise BackendError(f"Unknown setting: {key}")
        return _checked(self._ask(vpn, "vpn.Configure", protocol.parse_profiles, key,
                                  f"{value}\n".encode("utf-8")))

    def set_autoconnect(self, vpn: str, profile: str | None) -> Answer:
        """The profile ``vpn`` connects to at boot; None: none."""
        if profile is not None and not protocol.valid_profile_name(profile):
            raise BackendError("That is not a valid profile name.")
        return self._configure(vpn, "autoconnect", profile or "")

    def set_ping_target(self, vpn: str, address: str | None) -> Answer:
        """What the latency is measured against; None: the agent's default."""
        if address is not None and not protocol.valid_ipv4(address):
            raise BackendError("The latency target must be an IPv4 address.")
        return self._configure(vpn, "ping_target", address or "")

    def set_credentials(self, vpn: str, profile: str | None, username: str,
                        password: str) -> Answer:
        """Store the OpenVPN username and password in ``vpn``, for ``profile``
        or (None) for every OpenVPN profile without its own. Both empty:
        remove them."""
        name = profile or protocol.DEFAULT_CREDENTIALS
        if not protocol.valid_profile_name(name):
            raise BackendError("That is not a valid profile name.")
        if bool(username) != bool(password):
            raise BackendError("Give both a username and a password.")
        for text in (username, password):
            if len(text) > protocol.MAX_SECRET or any(c in text for c in "\r\n\0"):
                raise BackendError("The username and password must each be one line "
                                   f"of at most {protocol.MAX_SECRET} characters.")
        return self._configure(vpn, "credentials", f"{name}\n{username}\n{password}")


def _check_qube(name: str) -> None:
    if not protocol.valid_qube_name(name):
        raise BackendError("That is not a valid qube name.")


def _checked(answer: Answer) -> Answer:
    if answer.get("result") != "ok":
        raise BackendError(protocol.error_text(answer.error) or "The VPN qube refused.")
    return answer
