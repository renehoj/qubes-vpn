"""Calling a qrexec service from the vpn-manager qube: ``qrexec-client-vm``.

The answer comes from a qube that may be compromised, so the call is bounded
both ways: it is killed after ``timeout`` seconds, and once it has sent more
than ``max_bytes`` (``protocol.MAX_OUTPUT``) it is killed and refused, rather
than read into memory. Its stdin is empty; the services read nothing.
"""

from __future__ import annotations

import os
import select
import subprocess
import time

from .. import protocol
from .base import BackendError

TIMEOUT = 20.0
MAX_STDERR = 4096


class QrexecError(BackendError):
    pass


class QrexecClient:
    def __init__(self, command: tuple[str, ...] = ("qrexec-client-vm",),
                 timeout: float = TIMEOUT, max_bytes: int = protocol.MAX_OUTPUT):
        self.command = command
        self.timeout = timeout
        self.max_bytes = max_bytes

    def call(self, target: str, service: str, argument: str | None = None) -> bytes:
        name = f"{service}+{argument}" if argument else service
        argv = [*self.command, "--", target, name]
        try:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE)
        except OSError as exc:
            raise QrexecError(f"Could not run {self.command[0]}: {exc}") from exc
        try:
            stdout, stderr = self._read(proc, f"{name} in {target}")
            returncode = proc.wait(timeout=1)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        if not stdout and returncode != 0:
            # "Request refused" and friends: the policy said no, or the qube
            # is not there. stderr is local (qrexec-client-vm's own), but
            # keep it short and printable anyway.
            detail = stderr.decode("ascii", "replace").strip().splitlines()
            reason = "".join(c for c in (detail[-1] if detail else "") if c.isprintable())[:120]
            raise QrexecError(f"{name} in {target} failed (exit {returncode})"
                              + (f": {reason}" if reason else ""))
        return stdout

    def _read(self, proc: subprocess.Popen, what: str) -> tuple[bytes, bytes]:
        deadline = time.monotonic() + self.timeout
        out, err = bytearray(), bytearray()
        streams = {proc.stdout.fileno(): out, proc.stderr.fileno(): err}
        while streams:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise QrexecError(f"{what} did not answer within {self.timeout:.0f} s")
            ready, _w, _x = select.select(list(streams), [], [], remaining)
            for fd in ready:
                chunk = os.read(fd, 65536)
                if not chunk:
                    del streams[fd]
                    continue
                buffer = streams[fd]
                buffer += chunk
                if buffer is out and len(out) > self.max_bytes:
                    raise QrexecError(f"{what} sent more than {self.max_bytes} bytes")
                if buffer is err and len(err) > MAX_STDERR:
                    del err[MAX_STDERR:]
        return bytes(out), bytes(err)
