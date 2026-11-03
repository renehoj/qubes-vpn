"""Backends providing access to the qubes and their VPN agents."""

from .base import Backend, BackendError  # noqa: F401

KINDS = ("auto", "qubesadmin", "mock")


def qubesadmin_available() -> bool:
    try:
        import qubesadmin  # noqa: F401  pylint: disable=import-outside-toplevel
    except ImportError:
        return False
    return True


def create_backend(kind: str = "auto", netvm_method: str = "service") -> Backend:
    """Create a backend: ``qubesadmin``, ``mock`` or ``auto``.

    ``auto`` uses qubesadmin when it is installed (the vpn-manager qube) and
    demo data otherwise, so the window can be developed on any Linux box.
    """
    if kind == "auto":
        kind = "qubesadmin" if qubesadmin_available() else "mock"
    if kind == "qubesadmin":
        # pylint: disable=import-outside-toplevel
        from .qubesadmin_backend import QubesAdminBackend
        return QubesAdminBackend(netvm_method=netvm_method)
    if kind == "mock":
        from .mock import MockBackend  # pylint: disable=import-outside-toplevel
        return MockBackend()
    raise ValueError(f"Unknown backend: {kind}")
