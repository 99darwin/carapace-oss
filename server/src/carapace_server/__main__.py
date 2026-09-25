"""Container entrypoint: ``python -m carapace_server``.

Serves the API on ``$PORT`` (Cloud Run sets it) on all interfaces. The image
has no shell to expand ``$PORT`` in a command line, so it is read here.

uvicorn's own ``X-Forwarded-*`` handling is off: it trusts by peer address,
which behind Cloud Run is never ``127.0.0.1``, and ``FORWARDED_ALLOW_IPS=*``
would make it take the leftmost, client-supplied entry. The app trusts a
configured number of proxy hops instead (``CARAPACE_TRUSTED_PROXY_HOPS``,
see ``proxy.py``), so there is exactly one place that reads the header.
"""

from __future__ import annotations

import os
import re
import sys
from collections.abc import Mapping

import uvicorn

APP_FACTORY = "carapace_server.app:create_app"
DEFAULT_PORT = 8080
MIN_PORT = 1
MAX_PORT = 65535
PORT_PATTERN = re.compile(r"[0-9]{1,5}")
# The container is the network boundary; Cloud Run routes to this port.
LISTEN_HOST = "0.0.0.0"  # noqa: S104


class PortError(ValueError):
    """Raised when ``PORT`` is not a usable TCP port number."""


def listen_port(environ: Mapping[str, str]) -> int:
    """Return the port from ``PORT``, or the default when it is unset."""
    raw = environ.get("PORT")
    if raw is None or raw == "":
        return DEFAULT_PORT
    if not PORT_PATTERN.fullmatch(raw):
        raise PortError(f"PORT must be a decimal port number, got {raw!r}")
    port = int(raw)
    if not MIN_PORT <= port <= MAX_PORT:
        raise PortError(f"PORT must be in {MIN_PORT}-{MAX_PORT}, got {port}")
    return port


def main() -> None:
    try:
        port = listen_port(os.environ)
    except PortError as exc:
        sys.exit(f"carapace-server: {exc}")
    uvicorn.run(
        APP_FACTORY,
        factory=True,
        host=LISTEN_HOST,
        port=port,
        server_header=False,
        proxy_headers=False,
    )


if __name__ == "__main__":
    main()
