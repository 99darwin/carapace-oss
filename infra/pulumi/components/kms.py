"""Cloud KMS: the single HSM-backed asymmetric key that wraps every secret."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass

import pulumi
import pulumi_gcp as gcp

KEY_PURPOSE = "ASYMMETRIC_DECRYPT"
KEY_ALGORITHM = "RSA_DECRYPT_OAEP_4096_SHA256"
KEY_PROTECTION_LEVEL = "HSM"
DECRYPTER_ROLE = "roles/cloudkms.cryptoKeyDecrypter"
PUBLIC_KEY_VIEWER_ROLE = "roles/cloudkms.publicKeyViewer"
# KMS creates version 1 of an asymmetric key automatically. Asymmetric keys
# have no automatic rotation, so version 1 stays in use until an operator
# rotates the key by hand.
INITIAL_KEY_VERSION = 1


@dataclass(frozen=True)
class KmsKey:
    key_ring: gcp.kms.KeyRing
    crypto_key: gcp.kms.CryptoKey
    key_name: pulumi.Output[str]
    key_version_name: pulumi.Output[str]


def create_kms_key(
    *,
    prefix: str,
    location: str,
    protect: bool,
    depends_on: Sequence[pulumi.Resource] = (),
) -> KmsKey:
    """Create the key ring and the ASYMMETRIC_DECRYPT HSM key."""
    opts = pulumi.ResourceOptions(protect=protect, depends_on=list(depends_on))
    key_ring = gcp.kms.KeyRing(
        f"{prefix}-keyring",
        name=f"{prefix}-keyring",
        location=location,
        opts=opts,
    )
    crypto_key = gcp.kms.CryptoKey(
        f"{prefix}-secrets-key",
        name=f"{prefix}-secrets",
        key_ring=key_ring.id,
        purpose=KEY_PURPOSE,
        version_template={
            "algorithm": KEY_ALGORITHM,
            "protection_level": KEY_PROTECTION_LEVEL,
        },
        opts=opts,
    )
    key_version_name = crypto_key.id.apply(
        lambda key_id: f"{key_id}/cryptoKeyVersions/{INITIAL_KEY_VERSION}"
    )
    return KmsKey(
        key_ring=key_ring,
        crypto_key=crypto_key,
        key_name=crypto_key.id,
        key_version_name=key_version_name,
    )


def build_key_policy(
    decrypter_members: Sequence[str], public_key_viewers: Sequence[str]
) -> str:
    """Return the complete IAM policy JSON for the key.

    The policy is authoritative: any binding not listed here (for example a
    decrypter grant added by hand) is removed on the next ``pulumi up``.
    """
    if not decrypter_members:
        raise ValueError("at least one decrypter member is required")
    for member in decrypter_members:
        if not member.startswith("principalSet://"):
            raise ValueError(f"decrypter must be a WIF principalSet: {member!r}")
    bindings = [
        {"role": DECRYPTER_ROLE, "members": sorted(decrypter_members)},
        {"role": PUBLIC_KEY_VIEWER_ROLE, "members": sorted(public_key_viewers)},
    ]
    return json.dumps({"bindings": bindings}, sort_keys=True)


def bind_key_policy(
    *,
    prefix: str,
    kms_key: KmsKey,
    decrypter_members: pulumi.Input[Sequence[str]],
    public_key_viewers: pulumi.Input[Sequence[str]],
) -> gcp.kms.CryptoKeyIAMPolicy:
    """Attach the authoritative IAM policy to the key."""
    policy_data = pulumi.Output.all(decrypter_members, public_key_viewers).apply(
        lambda args: build_key_policy(args[0], args[1])
    )
    return gcp.kms.CryptoKeyIAMPolicy(
        f"{prefix}-secrets-key-policy",
        crypto_key_id=kms_key.crypto_key.id,
        policy_data=policy_data,
    )
