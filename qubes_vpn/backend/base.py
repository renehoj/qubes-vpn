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
    def _call(self, target: str, service: str, argument: str | None = None) -> bytes:
        """Run qrexec service ``service[+argument]`` in ``target``; its stdout."""

    def _ask(self, target: str, service: str, parse, argument: str | None = None) -> Answer:
        _check_qube(target)
        data = self._call(target, service, argument)
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


def _check_qube(name: str) -> None:
    if not protocol.valid_qube_name(name):
        raise BackendError("That is not a valid qube name.")


def _checked(answer: Answer) -> Answer:
    if answer.get("result") != "ok":
        raise BackendError(protocol.error_text(answer.error) or "The VPN qube refused.")
    return answer
