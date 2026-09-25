"""Boot sequence and serving, shared by the production and dev entrypoints.

Boot order, each step fatal on failure:

1. Generate the boot identity (TLS key, receipt key, boot id = nonce).
2. Fetch an attestation token for the control plane (proves the launcher
   works and floors the clock).
3. Fetch the KMS public key and prove by round trip that KMS decrypts with
   its private half, so the enclave never publishes a key it cannot use.
4. Register the boot with the control plane.
5. Serve HTTPS with the boot TLS key.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx
import uvicorn

from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.kms import (
    DekDecrypter,
    KmsError,
    validate_key_version_name,
    verify_round_trip,
)
from carapace_enclave.attestation.token import (
    AttestationError,
    TokenSource,
    validate_audiences,
)
from carapace_enclave.broker import Broker
from carapace_enclave.clock import TrustedClock
from carapace_enclave.egress import EgressExecutor
from carapace_enclave.receipts import ReceiptLog
from carapace_enclave.server import EnclaveServices, create_app
from carapace_enclave.server_client import ControlPlaneClient
from carapace_enclave.tls import server_ssl_context

logger = logging.getLogger(__name__)

# Unprivileged on purpose: the image runs as UID 65532 with no ambient
# capabilities, so it cannot bind below 1024. Must equal INGRESS_PORT in
# infra/pulumi/components/enclave_vm.py and the EXPOSE in enclave/Dockerfile,
# which is what makes the Confidential Space launcher open the port.
ENCLAVE_PORT = 8443
# The VM's only interface carries its public address (see infra): the API is
# meant to be reachable, and authorization is the API key, not the network.
LISTEN_HOST = "0.0.0.0"  # noqa: S104
# Every connection may buffer MAX_AGENT_BODY_BYTES before the key is checked,
# so the number of simultaneous connections bounds the memory anyone can
# make the enclave hold. Beyond this uvicorn answers 503 without reading.
MAX_CONCURRENT_CONNECTIONS = 256


class ConfigurationError(Exception):
    """The launch environment is missing or has an unsafe value."""


@dataclass(frozen=True, slots=True)
class EnclaveConfig:
    """The only three values the launch policy lets the operator set."""

    control_plane_url: str
    kms_key_name: str
    wif_audience: str

    @classmethod
    def from_env(
        cls, environ: Mapping[str, str], *, require_https: bool = True
    ) -> EnclaveConfig:
        values = {}
        for name in ("CONTROL_PLANE_URL", "KMS_KEY_NAME", "WIF_AUDIENCE"):
            value = environ.get(name, "").strip()
            if not value:
                raise ConfigurationError(f"{name} is required")
            values[name] = value
        config = cls(
            control_plane_url=values["CONTROL_PLANE_URL"],
            kms_key_name=values["KMS_KEY_NAME"],
            wif_audience=values["WIF_AUDIENCE"],
        )
        config.validate(require_https=require_https)
        return config

    def validate(self, *, require_https: bool = True) -> None:
        parts = urlsplit(self.control_plane_url)
        if require_https and parts.scheme != "https":
            raise ConfigurationError("CONTROL_PLANE_URL must be https")
        if parts.query or parts.fragment or parts.username or parts.password:
            raise ConfigurationError("CONTROL_PLANE_URL must be a plain base URL")
        try:
            validate_audiences(
                control_plane_url=self.control_plane_url,
                wif_audience=self.wif_audience,
            )
            validate_key_version_name(self.kms_key_name)
        except (AttestationError, KmsError) as exc:
            raise ConfigurationError(str(exc)) from None


async def boot(
    *,
    control_plane_url: str,
    identity: BootIdentity,
    tokens: TokenSource,
    clock: TrustedClock,
    decrypter: DekDecrypter,
    executor: EgressExecutor | None = None,
    control_plane_transport: httpx.AsyncBaseTransport | None = None,
) -> EnclaveServices:
    """Steps 2-4 of the boot sequence. Raises on any failure."""
    await asyncio.to_thread(tokens.get, control_plane_url)
    kms_public_key_pem = await asyncio.to_thread(decrypter.public_key_pem)
    await asyncio.to_thread(verify_round_trip, decrypter, kms_public_key_pem)
    client = ControlPlaneClient(
        base_url=control_plane_url,
        tokens=tokens,
        identity=identity,
        clock=clock,
        transport=control_plane_transport,
    )
    await client.register_boot()
    receipts = ReceiptLog(identity=identity, client=client)
    broker = Broker(
        client=client,
        decrypter=decrypter,
        executor=executor or EgressExecutor(),
        receipts=receipts,
        clock=clock,
    )
    logger.info("boot %s registered", identity.boot_id)
    return EnclaveServices(
        identity=identity,
        tokens=tokens,
        broker=broker,
        receipts=receipts,
        kms_public_key_pem=kms_public_key_pem,
        kms_key_version=decrypter.key_version,
    )


async def serve(
    services: EnclaveServices, *, host: str = LISTEN_HOST, port: int = ENCLAVE_PORT
) -> None:
    """Serve the enclave API over TLS with the boot key until stopped."""
    context = server_ssl_context(services.identity)

    def ssl_factory(_config: uvicorn.Config, _default: object) -> ssl.SSLContext:
        return context

    config = uvicorn.Config(
        create_app(services),
        host=host,
        port=port,
        ssl_context_factory=ssl_factory,
        http="h11",
        loop="asyncio",
        lifespan="on",
        access_log=False,
        server_header=False,
        proxy_headers=False,
        limit_concurrency=MAX_CONCURRENT_CONNECTIONS,
        log_config=None,
    )
    await uvicorn.Server(config).serve()


def configure_logging() -> None:
    """INFO for the enclave; libraries that can log request details at
    DEBUG (httpx, httpcore, google-auth) are held at WARNING."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    for name in ("httpx", "httpcore", "google", "urllib3"):
        logging.getLogger(name).setLevel(logging.WARNING)
