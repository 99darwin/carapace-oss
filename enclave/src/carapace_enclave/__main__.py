"""Production entrypoint: ``python -m carapace_enclave``.

Runs only inside Confidential Space. Without the launcher socket there is
no attestation, so it exits instead of falling back to anything.
"""

from __future__ import annotations

import asyncio
import logging
import os
import stat
import sys

from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.kms import CloudKmsDecrypter
from carapace_enclave.attestation.token import (
    LAUNCHER_SOCKET,
    LauncherClient,
    TokenSource,
)
from carapace_enclave.clock import TrustedClock
from carapace_enclave.runtime import EnclaveConfig, boot, configure_logging, serve

logger = logging.getLogger("carapace_enclave")


class NoLauncherError(Exception):
    """Not running under the Confidential Space launcher."""


def require_launcher_socket(path: str = LAUNCHER_SOCKET) -> None:
    try:
        mode = os.stat(path).st_mode
    except OSError:
        raise NoLauncherError(f"no TEE launcher socket at {path}") from None
    if not stat.S_ISSOCK(mode):
        raise NoLauncherError(f"{path} is not a socket")


async def main() -> None:
    config = EnclaveConfig.from_env(os.environ)
    require_launcher_socket()
    clock = TrustedClock()
    identity = BootIdentity.generate()
    tokens = TokenSource(LauncherClient(), clock, nonce=identity.boot_id)
    decrypter = CloudKmsDecrypter(
        key_version=config.kms_key_name,
        wif_audience=config.wif_audience,
        tokens=tokens,
    )
    services = await boot(
        control_plane_url=config.control_plane_url,
        identity=identity,
        tokens=tokens,
        clock=clock,
        decrypter=decrypter,
    )
    await serve(services)


def run() -> int:
    configure_logging()
    try:
        asyncio.run(main())
    except Exception as exc:
        # No traceback or chained context, and a message only from our own
        # errors, whose messages are written never to carry secret data.
        own = type(exc).__module__.startswith(("carapace_enclave", "carapace_crypto"))
        detail = f": {exc}" if own else ""
        logger.critical("enclave failed: %s%s", type(exc).__name__, detail)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(run())
