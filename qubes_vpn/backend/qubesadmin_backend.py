"""Backend for the vpn-manager qube: qubesadmin for qubesd, qrexec for the agents.

Admin API calls (see ``policy/30-qubes-vpn.policy`` for what each needs):

* the qube list: ``admin.vm.List``, filtered by qubesd to the qubes the
  policy lets this qube list (tags ``vpn`` and ``vpn-client``), then
  ``admin.vm.tag.Get +vpn`` / ``+vpn-client``, ``admin.vm.CurrentState`` and
  ``admin.vm.property.Get +netvm`` / ``+ip`` per qube;
* ``admin.vm.Start`` and ``admin.vm.Shutdown`` on VPN qubes;
* the dom0 service ``vpn.SetNetvm+<net qube>`` on client qubes (see
  ``dom0/vpn.SetNetvm``), whose policy says which net qubes are allowed, or,
  with ``netvm_method = admin``, ``admin.vm.property.Set +netvm``, which it
  cannot.

A qube the policy hides, or whose properties it refuses, is left out of the
list rather than failing the whole poll.
"""

from __future__ import annotations

import logging

import qubesadmin
import qubesadmin.exc

from .. import protocol
from ..model import Inventory, Qube
from .base import Backend, BackendError
from .qrexec import QrexecClient

logger = logging.getLogger("qubes-vpn")

VPN_TAG = "vpn"
CLIENT_TAG = "vpn-client"
METHODS = ("admin", "service")


class QubesAdminBackend(Backend):
    """The real thing."""

    name = "qubesd"

    def __init__(self, app=None, qrexec: QrexecClient | None = None,
                 netvm_method: str = "service"):
        if netvm_method not in METHODS:
            raise ValueError(f"netvm_method must be one of {METHODS}")
        self.app = app if app is not None else qubesadmin.Qubes()
        self.qrexec = qrexec or QrexecClient()
        self.netvm_method = netvm_method

    def _vm(self, name: str):
        try:
            return self.app.domains[name]
        except KeyError:
            raise BackendError(f"No such qube: {name}") from None

    def inventory(self) -> Inventory:
        qubes = {}
        try:
            domains = list(self.app.domains)
        except qubesadmin.exc.QubesException as exc:
            raise BackendError(f"Could not list the qubes: {exc}") from exc
        for vm in domains:
            name = str(vm.name)
            if name == "dom0" or not protocol.valid_qube_name(name):
                continue
            try:
                is_vpn = VPN_TAG in vm.tags
                is_client = CLIENT_TAG in vm.tags
                if not (is_vpn or is_client):
                    continue
                running = vm.is_running()
                netvm = vm.netvm
            except qubesadmin.exc.QubesException as exc:
                logger.info("Leaving out %s: %s", name, exc)
                continue
            qubes[name] = Qube(name, is_vpn, is_client, bool(running),
                               str(netvm) if netvm is not None else None, self._ip(vm))
        return Inventory(qubes)

    @staticmethod
    def _ip(vm) -> str | None:
        try:
            ip = vm.ip
        except (qubesadmin.exc.QubesException, AttributeError):
            return None
        return str(ip) if ip else None

    def start(self, name: str) -> None:
        try:
            self._vm(name).start()
        except qubesadmin.exc.QubesException as exc:
            raise BackendError(f"Could not start {name}: {exc}") from exc

    def shutdown(self, name: str) -> None:
        try:
            self._vm(name).shutdown()
        except qubesadmin.exc.QubesException as exc:
            raise BackendError(f"Could not shut down {name}: {exc}") from exc

    def _set_netvm(self, client: str, netvm: str | None) -> None:
        if self.netvm_method == "service":
            # Policy: vpn.SetNetvm +<netvm> vpn-manager @tag:vpn-client allow target=dom0
            data = self.qrexec.call(client, "vpn.SetNetvm", netvm or "none")
            answer = protocol.parse_setnetvm(data)
            if answer.get("result") != "ok":
                raise BackendError(f"dom0 refused to move {client} "
                                   f"({answer.error or 'no reason given'}).")
            return
        try:
            self._vm(client).netvm = netvm
        except qubesadmin.exc.QubesException as exc:
            raise BackendError(f"Could not change the net qube of {client}: {exc}") from exc

    def _call(self, target: str, service: str, argument: str | None = None) -> bytes:
        return self.qrexec.call(target, service, argument)
