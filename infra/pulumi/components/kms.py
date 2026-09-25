"""Cloud KMS: the single HSM-backed asymmetric key that wraps every secret."""

from __future__ import annotations

import json
import re
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
PUBLIC_MEMBERS = frozenset({"allUsers", "allAuthenticatedUsers"})
# One identity per member: a service account, user or group email, or a WIF
# principalSet in a workload identity pool.
EMAIL_MEMBER = re.compile(r"(?:serviceAccount|user|group):[^@\s:/]+@[^@\s:/]+\.[a-z]+")
PRINCIPAL_SET_MEMBER = re.compile(r"principalSet://iam\.googleapis\.com/projects/\S+")
EMPTY_POLICY = json.dumps({"bindings": []})
PEM_PUBLIC_KEY_HEADER = "-----BEGIN PUBLIC KEY-----"
KMS_SERVICE = "cloudkms.googleapis.com"
# Cryptographic operations such as AsymmetricDecrypt are DATA_READ entries.
KMS_DATA_ACCESS_LOG_TYPE = "DATA_READ"


@dataclass(frozen=True)
class KmsKey:
    key_ring: gcp.kms.KeyRing
    crypto_key: gcp.kms.CryptoKey
    key_name: pulumi.Output[str]
    key_version_name: pulumi.Output[str]
    key_ring_policy: gcp.kms.KeyRingIAMPolicy


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
    # Ring-level grants are inherited by the key, so the ring's own policy is
    # pinned to empty; every key-level grant lives in ``bind_key_policy``.
    key_ring_policy = gcp.kms.KeyRingIAMPolicy(
        f"{prefix}-keyring-policy",
        key_ring_id=key_ring.id,
        policy_data=EMPTY_POLICY,
    )
    key_version_name = crypto_key.id.apply(
        lambda key_id: f"{key_id}/cryptoKeyVersions/{INITIAL_KEY_VERSION}"
    )
    return KmsKey(
        key_ring=key_ring,
        crypto_key=crypto_key,
        key_name=crypto_key.id,
        key_version_name=key_version_name,
        key_ring_policy=key_ring_policy,
    )


class KmsPublicKeyError(ValueError):
    """The key version KMS reported is not the one the stack deploys."""


def select_public_key_pem(
    *,
    name: str,
    algorithm: str,
    public_keys: Sequence[object],
    expected_name: str,
) -> str:
    """Return the PEM of the key version the enclave is configured with.

    ``expected_name`` is the version name handed to the enclave, which it
    reports back to clients. The server advertises the PEM under that same
    name, so a data source that resolved any other version (or no public key
    yet) fails the deployment rather than shipping a mismatched pair.
    """
    if name != expected_name:
        raise KmsPublicKeyError(
            f"KMS returned key version {name!r}, expected {expected_name!r}"
        )
    if algorithm != KEY_ALGORITHM:
        raise KmsPublicKeyError(f"KMS key version algorithm is {algorithm!r}")
    if len(public_keys) != 1:
        raise KmsPublicKeyError(
            "KMS key version has no public key yet; re-run once it is ENABLED"
        )
    pem = getattr(public_keys[0], "pem", None)
    if not isinstance(pem, str) or not pem.startswith(PEM_PUBLIC_KEY_HEADER):
        raise KmsPublicKeyError("KMS public key is not a PEM public key")
    return pem


def read_public_key_pem(kms_key: KmsKey) -> pulumi.Output[str]:
    """Read the public half of the key version the enclave decrypts with.

    The public key is not secret; the server serves it at
    ``/v1/kms/public-key`` so ``carapace verify`` can compare it with the key
    the attested enclave reports.
    """
    version = gcp.kms.get_kms_crypto_key_version_output(
        crypto_key=kms_key.crypto_key.id, version=INITIAL_KEY_VERSION
    )
    return pulumi.Output.all(version, kms_key.key_version_name).apply(
        lambda args: select_public_key_pem(
            name=args[0].name,
            algorithm=args[0].algorithm,
            public_keys=args[0].public_keys or [],
            expected_name=args[1],
        )
    )


def validate_viewer_member(member: str) -> str:
    """Refuse public principals and anything that is not a single identity.

    ``allUsers`` and ``allAuthenticatedUsers`` would publish the key's
    metadata to the internet; a ``domain:`` or malformed member is refused
    for the same reason: every viewer must name one principal.
    """
    if not isinstance(member, str):
        raise ValueError(f"public key viewer must be a string: {member!r}")
    if member in PUBLIC_MEMBERS:
        raise ValueError(f"public key viewer must not be public: {member!r}")
    if not (PRINCIPAL_SET_MEMBER.fullmatch(member) or EMAIL_MEMBER.fullmatch(member)):
        raise ValueError(f"malformed public key viewer: {member!r}")
    return member


def build_key_policy(
    decrypter_members: Sequence[str], public_key_viewers: Sequence[str]
) -> str:
    """Return the complete IAM policy JSON for the key.

    The policy is authoritative: any binding not listed here (for example a
    decrypter grant added by hand) is removed on the next ``pulumi up``.

    Every decrypter is also a public key viewer. The enclave's boot self-test
    calls ``GetPublicKey`` with the same federated credentials it decrypts
    with, so the attested ``principalSet`` needs both roles; granting them
    together keeps the two bindings from drifting apart. ``public_key_viewers``
    names any further read-only viewers (the server).
    """
    if not decrypter_members:
        raise ValueError("at least one decrypter member is required")
    for member in decrypter_members:
        if not PRINCIPAL_SET_MEMBER.fullmatch(member):
            raise ValueError(f"decrypter must be a WIF principalSet: {member!r}")
    for member in public_key_viewers:
        validate_viewer_member(member)
    viewers = set(decrypter_members) | set(public_key_viewers)
    bindings = [
        {"role": DECRYPTER_ROLE, "members": sorted(decrypter_members)},
        {"role": PUBLIC_KEY_VIEWER_ROLE, "members": sorted(viewers)},
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


def enable_kms_data_access_logs(
    *, prefix: str, project: str, depends_on: Sequence[pulumi.Resource] = ()
) -> gcp.projects.IAMAuditConfig:
    """Log every KMS data-plane call, including each ``AsymmetricDecrypt``.

    Data Access logs are off by default, so without this a decrypt leaves no
    trace. The resource is authoritative for Cloud KMS's audit config in the
    project: an exemption added by hand is removed on the next ``pulumi up``.
    """
    return gcp.projects.IAMAuditConfig(
        f"{prefix}-kms-data-access-logs",
        project=project,
        service=KMS_SERVICE,
        audit_log_configs=[{"log_type": KMS_DATA_ACCESS_LOG_TYPE}],
        opts=pulumi.ResourceOptions(depends_on=list(depends_on)),
    )
