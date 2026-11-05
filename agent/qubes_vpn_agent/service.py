"""``vpn-agent <command>``: what the qrexec services and systemd run.

=====================  =============================  ============================
qrexec service         command                        output
=====================  =============================  ============================
``vpn.ListProfiles``   ``list-profiles``              ``profile=<name>:<protocol>``,
                                                      settings
``vpn.Connect+<p>``    ``connect <p>``                ``result=``, then Status
``vpn.Configure+<k>``  ``configure <k>``              ``result=``, then ListProfiles
``vpn.Disconnect``     ``disconnect``                 ``result=``, then Status
``vpn.Status``         ``status``                     state, protocol, profile, …
``vpn.Stats``          ``stats``                      counters, ``vif=`` lines
(systemd, at boot)     ``killswitch``                 ``result=``
(systemd, at boot)     ``autoconnect``                as Connect, if agent.conf says
(OpenVPN up/down)      ``openvpn-event``              ``result=``
(by hand, in the qube) ``credentials [<profile>]``    ``result=``
=====================  =============================  ============================

The profile name of ``vpn.Connect+<p>`` comes from ``QREXEC_SERVICE_ARGUMENT``
(qrexec also passes it as ``$1``) and is checked against the profile pattern
and the profiles that exist; nothing else is read from the caller, not even
stdin. A failure prints ``result=error`` and ``error=<code>``.

``vpn.Configure+<key>`` is the one service that reads stdin: the new value of
``key`` (see ``Agent.configure``), at most ``MAX_CONFIG_INPUT`` bytes. The key
is the qrexec argument, so the policy can allow each one on its own.

``credentials`` asks for an OpenVPN username and password on the terminal and
writes them to ``/rw/config/vpn/openvpn/<profile>.auth``, or ``default.auth``
for every OpenVPN profile. ``vpn.Configure+credentials`` does the same from
the manager.

Everything runs as root (the policy's ``user=root``): the tunnels, nft and
``/rw/config/vpn`` need it.
"""

from __future__ import annotations

import getpass
import logging
import os
import sys

from .agent import MAX_CONFIG_INPUT, Agent, AgentError
from .output import render

COMMANDS = ("list-profiles", "connect", "disconnect", "status", "stats",
            "killswitch", "autoconnect", "openvpn-event", "credentials", "configure")

logger = logging.getLogger("qubes-vpn-agent")


def _ask(prompt: str, secret: bool) -> str:
    if secret:
        return getpass.getpass(prompt)
    print(prompt, end="", file=sys.stderr, flush=True)
    return sys.stdin.readline().rstrip("\n")


def _read_stdin() -> bytes:
    # One byte more than allowed, so the agent can tell "too long" apart.
    return sys.stdin.buffer.read(MAX_CONFIG_INPUT + 1)


def main(argv: list[str] | None = None, *, agent: Agent | None = None, out=None,
         environ: dict[str, str] | None = None, ask=_ask, stdin=_read_stdin) -> int:
    argv = sys.argv[1:] if argv is None else argv
    out = out or sys.stdout
    environ = dict(os.environ) if environ is None else environ
    if not argv or argv[0] not in COMMANDS:
        print(f"usage: vpn-agent {{{'|'.join(COMMANDS)}}}", file=sys.stderr)
        return 2
    command = argv[0]
    if agent is None:
        if os.geteuid() != 0:
            out.write(render([("result", "error"), ("error", "not-root")]))
            return 1
        agent = Agent()
    try:
        if command == "list-profiles":
            pairs = agent.list_profiles()
        elif command == "connect":
            name = environ.get("QREXEC_SERVICE_ARGUMENT") or (argv[1] if len(argv) > 1 else "")
            pairs = agent.connect(name)
        elif command == "disconnect":
            pairs = agent.disconnect()
        elif command == "status":
            pairs = agent.status()
        elif command == "stats":
            pairs = agent.stats()
        elif command == "killswitch":
            pairs = agent.apply_killswitch()
        elif command == "autoconnect":
            pairs = agent.autoconnect()
        elif command == "configure":
            key = environ.get("QREXEC_SERVICE_ARGUMENT") or (argv[1] if len(argv) > 1 else "")
            pairs = agent.configure(key, stdin())
        elif command == "credentials":
            profile = argv[1] if len(argv) > 1 else None
            pairs = agent.set_credentials(profile, ask("Username: ", False),
                                          ask("Password: ", True))
        else:
            pairs = agent.openvpn_event(environ)
    except AgentError as exc:
        out.write(render([("result", "error"), ("error", exc.code)]))
        return 1
    except Exception:  # pylint: disable=broad-except
        # The details go to this qube's journal (qrexec's stderr), not the caller.
        logger.exception("vpn-agent %s failed", command)
        out.write(render([("result", "error"), ("error", "internal")]))
        return 1
    out.write(render(pairs))
    return 0


if __name__ == "__main__":
    sys.exit(main())
