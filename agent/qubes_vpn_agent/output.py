"""The agent's output: ``key=value`` lines, ASCII only.

The manager treats all of it as untrusted and validates it again; the agent
keeps its side tidy anyway. Keys are fixed identifiers, and every value is cut
down to the characters the format can carry, so nothing a profile file, the
kernel or OpenVPN reports can split a line, start a new key or grow without
bound.
"""

from __future__ import annotations

import re
from typing import Iterable

Pairs = list[tuple[str, object]]

_KEY = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
_UNSAFE = re.compile(r"[^A-Za-z0-9_.:/@+\-\[\],]")
MAX_VALUE = 128


def clean(value: object) -> str:
    """``value`` as one safe token: unsafe characters become ``_``."""
    if isinstance(value, bool):
        value = int(value)
    if isinstance(value, float):
        value = f"{value:.1f}"
    return _UNSAFE.sub("_", str(value))[:MAX_VALUE]


def render(pairs: Iterable[tuple[str, object]]) -> str:
    lines = []
    for key, value in pairs:
        if not _KEY.match(key):
            raise ValueError(f"bad output key: {key!r}")
        if value is None:
            continue
        lines.append(f"{key}={clean(value)}")
    return "".join(f"{line}\n" for line in lines)
