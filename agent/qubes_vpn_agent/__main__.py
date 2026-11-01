"""``python3 -m qubes_vpn_agent <command>`` (see ``service``)."""

import sys

from .service import main

sys.exit(main())
