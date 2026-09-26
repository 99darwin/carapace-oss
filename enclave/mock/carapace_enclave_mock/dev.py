"""DEV ONLY: run the enclave locally against a dev-mode server.

    PYTHONPATH=enclave/mock uv run python -m carapace_enclave_mock.dev \\
        --launcher-key dev-launcher.pem [--kms-key dev-kms.pem]

``--launcher-key`` is an RSA private key PEM for the fake launcher (for
example ``openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048``).
The script prints the public half; start the server with it::

    CARAPACE_MODE=dev CARAPACE_ATTESTATION_ISSUER=mock://local \\
    CARAPACE_MOCK_ATTESTATION_PUBLIC_KEY_PEM="$(cat launcher.pub.pem)" \\
    CARAPACE_ALLOWED_IMAGE_DIGESTS=sha256:000...000

``--kms-key`` (RSA-4096) keeps the fake KMS key across restarts, so that
envelopes sealed to it stay openable; without it a new key is generated.
Neither key protects anything real: a prod server refuses ``mock://local``.
"""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from carapace_enclave.attestation.identity import BootIdentity
from carapace_enclave.attestation.token import LauncherClient, TokenSource
from carapace_enclave.clock import TrustedClock
from carapace_enclave.runtime import EnclaveConfig, boot, configure_logging, serve
from carapace_enclave_mock.kms import MOCK_KMS_KEY_VERSION, LocalRsaDecrypter
from carapace_enclave_mock.launcher import MOCK_IMAGE_DIGEST, MockLauncher

DEV_CONTROL_PLANE_URL = "http://localhost:8000"
DEV_WIF_AUDIENCE = (
    "//iam.googleapis.com/projects/0/locations/global"
    "/workloadIdentityPools/mock/providers/mock"
)
DEV_PORT = 8443
DEV_HOST = "127.0.0.1"


def _load_rsa(path: Path) -> rsa.RSAPrivateKey:
    key = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise SystemExit(f"{path} is not an RSA private key")
    return key


async def main(args: argparse.Namespace) -> None:
    config = EnclaveConfig(
        control_plane_url=args.control_plane_url,
        kms_key_name=MOCK_KMS_KEY_VERSION,
        wif_audience=DEV_WIF_AUDIENCE,
    )
    config.validate(require_https=False)
    launcher = MockLauncher(
        signing_key=_load_rsa(args.launcher_key),
        env={
            "CONTROL_PLANE_URL": config.control_plane_url,
            "KMS_KEY_NAME": config.kms_key_name,
            "WIF_AUDIENCE": config.wif_audience,
        },
    )
    decrypter = (
        LocalRsaDecrypter(_load_rsa(args.kms_key))
        if args.kms_key
        else LocalRsaDecrypter.generate()
    )
    print("mock launcher public key (CARAPACE_MOCK_ATTESTATION_PUBLIC_KEY_PEM):")
    print(launcher.public_pem)
    print(f"mock image digest (CARAPACE_ALLOWED_IMAGE_DIGESTS): {MOCK_IMAGE_DIGEST}")
    print(
        f"carapace verify: --project-id {launcher.project_id} "
        f"--service-account {launcher.service_account} "
        f"--kms-key {config.kms_key_name}"
    )
    clock = TrustedClock()
    identity = BootIdentity.generate()
    tokens = TokenSource(
        LauncherClient(transport=launcher.transport()), clock, nonce=identity.boot_id
    )
    services = await boot(
        control_plane_url=config.control_plane_url,
        identity=identity,
        tokens=tokens,
        clock=clock,
        decrypter=decrypter,
    )
    print(f"enclave boot {identity.boot_id} on https://{DEV_HOST}:{args.port}")
    await serve(services, host=DEV_HOST, port=args.port)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--launcher-key", type=Path, required=True)
    parser.add_argument("--kms-key", type=Path)
    parser.add_argument("--control-plane-url", default=DEV_CONTROL_PLANE_URL)
    parser.add_argument("--port", type=int, default=DEV_PORT)
    return parser.parse_args()


if __name__ == "__main__":
    configure_logging()
    asyncio.run(main(parse_args()))
