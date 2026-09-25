"""Regenerate ``envelope_v1.json``.

The RSA test key is reused from the existing file when present so that
regenerating does not churn every vector. RSA-OAEP is randomized, so
``wrapped`` changes on each run; everything else is deterministic given the
fixed DEK and nonce.

Usage: ``uv run python packages/crypto/tests/vectors/generate_envelope_v1.py``
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_crypto.canonical import canonical_json
from carapace_crypto.envelope import _seal

VECTORS_PATH = Path(__file__).with_name("envelope_v1.json")
RSA_BITS = 4096

GITHUB_POLICY: dict[str, Any] = {
    "v": 1,
    "hosts": [{"match": "exact", "value": "api.github.com"}],
    "schemes": ["https"],
    "methods": ["GET", "POST"],
    "ports": [443],
    "inject": {
        "kind": "header",
        "name": "Authorization",
        "template": "Bearer {secret}",
    },
    "limits": {
        "req_bytes": 1048576,
        "resp_bytes": 5242880,
        "rpm": 60,
        "timeout_s": 30,
    },
}

UNICODE_POLICY: dict[str, Any] = {
    "v": 1,
    "hosts": [{"match": "suffix", "value": ".example.com"}],
    "note": 'café ☃ \U0001f511 "quoted" back\\slash \n\t\u0001',
    "inject": {"kind": "query", "name": "api_key", "template": "{secret}"},
    "é": True,
    "Z": None,
    "a": [],
}

ENVELOPE_CASES: list[dict[str, Any]] = [
    {
        "name": "github-header",
        "secret_id": "5b0c7c2e-2f7b-4c55-9d1e-7d1f3f0a9b11",
        "owner_id": "0e6f0d0c-8f5c-4d8e-a3b8-0c1f2d3e4f50",
        "policy": GITHUB_POLICY,
        "plaintext": b"ghp_testvectorNOTAREALTOKEN0000000000",
        "dek": bytes(range(32)),
        "nonce": bytes(range(100, 112)),
        "kms_key_version": "1",
    },
    {
        "name": "unicode-policy-binary-secret",
        "secret_id": "sec_ü",
        "owner_id": "owner-2",
        "policy": UNICODE_POLICY,
        "plaintext": bytes(range(256)),
        "dek": bytes([0xA5] * 32),
        "nonce": bytes([0x5A] * 12),
        "kms_key_version": None,
    },
]

# Negative vectors: each patches the "github-header" envelope's serialized
# form (JSON merge patch semantics, one level deep) and names the outcome an
# implementation must produce. "reject_malformed" must fail before any
# unwrap; "reject_authentication" fails at AES-GCM.
TAMPER_CASES: list[dict[str, Any]] = [
    {
        "name": "policy-widened-hosts",
        "patch": {
            "policy": {
                **GITHUB_POLICY,
                "hosts": [
                    *GITHUB_POLICY["hosts"],
                    {"match": "suffix", "value": ".attacker.test"},
                ],
            }
        },
        "outcome": "reject_authentication",
    },
    {
        "name": "policy-widened-limits",
        "patch": {
            "policy": {
                **GITHUB_POLICY,
                "limits": {**GITHUB_POLICY["limits"], "resp_bytes": 10**9},
            }
        },
        "outcome": "reject_authentication",
    },
    {
        "name": "policy-widened-methods",
        "patch": {"policy": {**GITHUB_POLICY, "methods": ["GET", "POST", "DELETE"]}},
        "outcome": "reject_authentication",
    },
    {
        "name": "relabeled-owner",
        "patch": {"owner_id": "9d3b1c5e-1e5c-4c3a-9a34-a2b8c7d6e5f4"},
        "expected_owner_id": "9d3b1c5e-1e5c-4c3a-9a34-a2b8c7d6e5f4",
        "outcome": "reject_authentication",
    },
    {
        "name": "relabeled-secret",
        "patch": {"secret_id": "7c1e9a2b-3d4f-4a5b-8c6d-0e1f2a3b4c5d"},
        "expected_secret_id": "7c1e9a2b-3d4f-4a5b-8c6d-0e1f2a3b4c5d",
        "outcome": "reject_authentication",
    },
    {"name": "truncated-ct", "truncate_ct": 1, "outcome": "reject_authentication"},
    {"name": "flipped-ct-first-byte", "flip_ct": 0, "outcome": "reject_authentication"},
    {"name": "flipped-ct-tag", "flip_ct": -1, "outcome": "reject_authentication"},
    {"name": "flipped-nonce", "flip_nonce": 0, "outcome": "reject_authentication"},
    {"name": "version-2", "patch": {"v": 2}, "outcome": "reject_malformed"},
    {"name": "version-bool", "patch": {"v": True}, "outcome": "reject_malformed"},
    {"name": "ct-tag-only", "ct_bytes": b"\x00" * 16, "outcome": "reject_malformed"},
    {
        "name": "policy-float",
        "patch": {"policy": {**GITHUB_POLICY, "limits": {"timeout_s": 30.0}}},
        "outcome": "reject_malformed",
    },
]

CANONICAL_CASES: list[dict[str, Any]] = [
    {"name": "sorted-keys", "value": {"b": 1, "a": 2, "A": 3}},
    {"name": "nested", "value": {"z": {"y": [3, {"b": None, "a": False}]}}},
    {"name": "unicode-order", "value": {"é": 1, "z": 2, "\U0001f511": 3}},
    {
        # RFC 8785 §3.2.3: sorted by UTF-16 code units, so U+1F600 (a
        # surrogate pair) sorts between U+20AC and U+FB33.
        "name": "utf16-key-order",
        "value": {
            "\u20ac": 0,
            "\r": 1,
            "\ufb33": 2,
            "1": 3,
            "\U0001f600": 4,
            "\u0080": 5,
            "\u00f6": 6,
            "\uff61": 7,
        },
    },
    {"name": "escapes", "value": {"s": '"\\/\b\f\n\r\t\u0000\u001f\u007f'}},
    {"name": "safe-integers", "value": {"max": 2**53 - 1, "min": -(2**53 - 1)}},
    {"name": "empty", "value": {}},
]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _load_or_create_key() -> rsa.RSAPrivateKey:
    if VECTORS_PATH.exists():
        pem = json.loads(VECTORS_PATH.read_text())["rsa_private_key_pkcs8_pem"]
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
        if isinstance(key, rsa.RSAPrivateKey) and key.key_size == RSA_BITS:
            return key
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def _envelope_vector(case: dict[str, Any], public_pem: bytes) -> dict[str, Any]:
    pool = case["dek"] + case["nonce"]

    def fixed_random(size: int) -> bytes:
        nonlocal pool
        chunk, pool = pool[:size], pool[size:]
        return chunk

    envelope = _seal(
        public_pem,
        case["secret_id"],
        case["owner_id"],
        case["policy"],
        case["plaintext"],
        kms_key_version=case["kms_key_version"],
        random_bytes=fixed_random,
    )
    aad_input = canonical_json(
        {
            "v": 1,
            "secret_id": case["secret_id"],
            "owner_id": case["owner_id"],
            "policy": case["policy"],
        }
    )
    return {
        "name": case["name"],
        "secret_id": case["secret_id"],
        "owner_id": case["owner_id"],
        "policy": case["policy"],
        "plaintext_b64": _b64(case["plaintext"]),
        "dek_hex": case["dek"].hex(),
        "nonce_hex": case["nonce"].hex(),
        "aad_input_b64": _b64(aad_input),
        "aad_hex": hashlib.sha256(aad_input).hexdigest(),
        "ct_b64": _b64(envelope.ct),
        "envelope": envelope.to_dict(),
    }


def _flip(data: bytes, index: int) -> bytes:
    index %= len(data)
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def _tamper_vector(case: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    envelope = dict(base["envelope"])
    envelope.update(case.get("patch", {}))
    ct = base64.b64decode(envelope["ct"])
    if "truncate_ct" in case:
        ct = ct[: -case["truncate_ct"]]
    if "flip_ct" in case:
        ct = _flip(ct, case["flip_ct"])
    if "ct_bytes" in case:
        ct = case["ct_bytes"]
    envelope["ct"] = _b64(ct)
    if "flip_nonce" in case:
        nonce = base64.b64decode(envelope["nonce"])
        envelope["nonce"] = _b64(_flip(nonce, case["flip_nonce"]))
    return {
        "name": case["name"],
        "base": base["name"],
        "expected_secret_id": case.get("expected_secret_id", base["secret_id"]),
        "expected_owner_id": case.get("expected_owner_id", base["owner_id"]),
        "envelope": envelope,
        "outcome": case["outcome"],
    }


def main() -> None:
    private_key = _load_or_create_key()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    envelopes = [_envelope_vector(c, public_pem) for c in ENVELOPE_CASES]
    document = {
        "description": (
            "Carapace envelope v1 test vectors. The RSA key is a PUBLIC TEST "
            "KEY; never use it for real data. RSA-OAEP output is randomized, "
            "so implementations must check that decrypting 'wrapped' yields "
            "'dek_hex' and that AES-256-GCM with dek/nonce/aad yields 'ct_b64'. "
            "Every 'tamper' entry must be rejected with the named outcome: "
            "'reject_malformed' before any unwrap, 'reject_authentication' at "
            "AES-GCM after a successful unwrap."
        ),
        "algorithms": {
            "aead": "AES-256-GCM, 12-byte nonce, 16-byte tag appended to ct",
            "wrap": "RSA-OAEP, SHA-256, MGF1-SHA-256, empty label",
            "aad": "sha256(canonical_json({v, secret_id, owner_id, policy}))",
            "binary_encoding": "RFC 4648 base64 with padding",
        },
        "rsa_public_key_pem": public_pem.decode("ascii"),
        "rsa_private_key_pkcs8_pem": private_pem.decode("ascii"),
        "envelopes": envelopes,
        "tamper": [_tamper_vector(c, envelopes[0]) for c in TAMPER_CASES],
        "canonical_json": [
            {
                "name": case["name"],
                "value": case["value"],
                "canonical_b64": _b64(canonical_json(case["value"])),
            }
            for case in CANONICAL_CASES
        ],
    }
    VECTORS_PATH.write_text(
        json.dumps(document, indent=2, ensure_ascii=True, sort_keys=False) + "\n"
    )


if __name__ == "__main__":
    main()
