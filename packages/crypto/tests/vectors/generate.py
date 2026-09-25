"""Regenerate ``envelope_v1.json`` and ``grant_v1.json``.

The RSA test key is reused from the existing file when present so that
regenerating does not churn every vector. RSA-OAEP is randomized, so
``wrapped`` (and therefore each envelope signature) changes on every run;
everything else is deterministic given the fixed owner seeds, DEKs and nonces.

Usage: ``uv run python packages/crypto/tests/vectors/generate.py``
"""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from carapace_crypto.apikey import ApiKey
from carapace_crypto.canonical import canonical_json
from carapace_crypto.envelope import ENVELOPE_CONTEXT, Envelope, _seal
from carapace_crypto.grant import (
    CLOCK_SKEW_SECONDS,
    DEFAULT_GRANT_TTL_SECONDS,
    GRANT_CONTEXT,
    MAX_GRANT_TTL_SECONDS,
    Grant,
    create_grant,
)
from carapace_crypto.ownerkey import OwnerKey, signing_input
from carapace_crypto.signing import KeyPair

VECTORS_DIR = Path(__file__).parent
ENVELOPE_PATH = VECTORS_DIR / "envelope_v1.json"
GRANT_PATH = VECTORS_DIR / "grant_v1.json"
RSA_BITS = 4096

# Public test seeds. Never use them for anything else.
OWNER = OwnerKey.from_seed(bytes(range(0x10, 0x30)))
ATTACKER = OwnerKey.from_seed(bytes(range(0xD0, 0xF0)))
NOW = 1_800_000_000
DAY = 86_400

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
        "version": 1_800_000_000,
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
        "version": 7,
    },
]
BASE = ENVELOPE_CASES[0]
OTHER_OWNER_ID = "9d3b1c5e-1e5c-4c3a-9a34-a2b8c7d6e5f4"
OTHER_SECRET_ID = "7c1e9a2b-3d4f-4a5b-8c6d-0e1f2a3b4c5d"
WIDENED_POLICY = {
    **GITHUB_POLICY,
    "hosts": [*GITHUB_POLICY["hosts"], {"match": "suffix", "value": ".evil.test"}],
}

# Negative envelope vectors, each derived from the "github-header" envelope.
# Keys: "patch" (top-level field overrides), "flip_<field>" (xor one bit at
# that byte index), "truncate_<field>", "seal_as"/"owner_pk" (another owner),
# "resign" (+ optional "context") re-signs after the edit, "duplicate_key"
# emits raw JSON text. The default outcome is "reject_signature".
TAMPER_CASES: list[dict[str, Any]] = [
    {"name": "policy-widened", "patch": {"policy": WIDENED_POLICY}},
    {
        "name": "policy-widened-limits",
        "patch": {
            "policy": {
                **GITHUB_POLICY,
                "limits": {**GITHUB_POLICY["limits"], "resp_bytes": 10**9},
            }
        },
    },
    {"name": "relabeled-owner", "patch": {"owner_id": OTHER_OWNER_ID}},
    {
        "name": "relabeled-secret",
        "patch": {"secret_id": OTHER_SECRET_ID},
        "expected_secret_id": OTHER_SECRET_ID,
    },
    {"name": "version-bumped", "patch": {"version": 1_900_000_000}},
    {"name": "kms-key-version-edited", "patch": {"kms_key_version": "2"}},
    {"name": "flipped-ct-first-byte", "flip_ct": 0},
    {"name": "flipped-ct-tag", "flip_ct": -1},
    {"name": "flipped-nonce", "flip_nonce": 0},
    {"name": "flipped-wrapped", "flip_wrapped": 7},
    {"name": "flipped-sig", "flip_sig": 0},
    {"name": "owner-pk-swapped", "owner_pk": ATTACKER},
    {"name": "substituted-by-other-owner", "seal_as": ATTACKER},
    {"name": "signed-under-grant-context", "resign": OWNER, "context": GRANT_CONTEXT},
    {"name": "signed-without-context", "resign": OWNER, "context": b""},
    {
        "name": "version-rollback",
        "min_version": BASE["version"] + 1,
        "outcome": "reject_stale",
    },
    # Re-signed by the legitimate owner after the edit: only the AEAD binding
    # catches these, which shows the AAD is still required.
    {
        "name": "resigned-policy-widened",
        "patch": {"policy": WIDENED_POLICY},
        "resign": OWNER,
        "outcome": "reject_authentication",
    },
    {
        "name": "resigned-relabeled-secret",
        "patch": {"secret_id": OTHER_SECRET_ID},
        "expected_secret_id": OTHER_SECRET_ID,
        "resign": OWNER,
        "outcome": "reject_authentication",
    },
    {
        "name": "resigned-truncated-ct",
        "truncate_ct": 1,
        "resign": OWNER,
        "outcome": "reject_authentication",
    },
    {"name": "version-2", "patch": {"v": 2}, "outcome": "reject_malformed"},
    {"name": "version-bool", "patch": {"v": True}, "outcome": "reject_malformed"},
    {"name": "version-zero", "patch": {"version": 0}, "outcome": "reject_malformed"},
    {
        "name": "version-bool-field",
        "patch": {"version": True},
        "outcome": "reject_malformed",
    },
    {"name": "sig-missing", "patch": {"sig": None}, "outcome": "reject_malformed"},
    {"name": "sig-truncated", "truncate_sig": 1, "outcome": "reject_malformed"},
    {"name": "sig-unpadded-base64", "unpad_sig": True, "outcome": "reject_malformed"},
    {
        "name": "owner-pk-short",
        "patch": {"owner_pk": base64.b64encode(b"\x01" * 31).decode()},
        "outcome": "reject_malformed",
    },
    {"name": "ct-tag-only", "ct_bytes": b"\x00" * 16, "outcome": "reject_malformed"},
    {
        "name": "policy-float",
        "patch": {"policy": {**GITHUB_POLICY, "limits": {"timeout_s": 30.0}}},
        "outcome": "reject_malformed",
    },
    {"name": "duplicate-json-key", "duplicate_key": "policy"},
]

API_KEY_CASES: list[dict[str, Any]] = [
    {"name": "owner-key-1", "owner": OWNER, "random": bytes(range(0x40, 0x60))},
    {"name": "owner-key-2", "owner": OWNER, "random": bytes([0x77] * 32)},
    {"name": "attacker-key", "owner": ATTACKER, "random": bytes([0x99] * 32)},
]

GRANT_SECRETS = {case["secret_id"]: case["version"] for case in ENVELOPE_CASES}
GRANT_EXP = NOW + DEFAULT_GRANT_TTL_SECONDS

# Negative grant vectors, derived from the single accepted grant. Keys as for
# envelopes plus "api_key" (which key the agent presents), "now" and
# "secret_id" (what is requested). The default outcome is "reject_signature".
GRANT_TAMPER_CASES: list[dict[str, Any]] = [
    {
        "name": "presented-with-other-key",
        "api_key": "owner-key-2",
        "outcome": "reject_key_mismatch",
    },
    {
        "name": "presented-with-attacker-key",
        "api_key": "attacker-key",
        "outcome": "reject_key_mismatch",
    },
    {"name": "key-bind-edited", "bind_of": "owner-key-2"},
    {"name": "secrets-widened", "patch": {"secrets": {**GRANT_SECRETS, "x": 1}}},
    {
        "name": "floor-lowered",
        "patch": {"secrets": {**GRANT_SECRETS, BASE["secret_id"]: 1}},
    },
    {"name": "exp-extended", "patch": {"exp": GRANT_EXP + 10 * DAY}},
    {"name": "flipped-sig", "flip_sig": 0},
    {"name": "signed-by-attacker", "resign": ATTACKER},
    {
        "name": "owner-pk-swapped-and-resigned",
        "resign": ATTACKER,
        "owner_pk": ATTACKER,
        "outcome": "reject_key_mismatch",
    },
    {
        "name": "signed-under-envelope-context",
        "resign": OWNER,
        "context": ENVELOPE_CONTEXT,
    },
    {
        "name": "resigned-for-other-key",
        "bind_of": "owner-key-2",
        "resign": OWNER,
        "outcome": "reject_key_mismatch",
    },
    {"name": "expired", "now": GRANT_EXP, "outcome": "reject_expired"},
    {
        "name": "not-yet-valid",
        "now": NOW - CLOCK_SKEW_SECONDS - 1,
        "outcome": "reject_expired",
    },
    {"name": "within-skew", "now": NOW - CLOCK_SKEW_SECONDS, "outcome": "accept"},
    {"name": "last-valid-second", "now": GRANT_EXP - 1, "outcome": "accept"},
    {
        "name": "secret-not-covered",
        "secret_id": OTHER_SECRET_ID,
        "outcome": "reject_scope",
    },
    {
        "name": "ttl-over-cap",
        "patch": {"exp": NOW + MAX_GRANT_TTL_SECONDS + 1},
        "resign": OWNER,
        "outcome": "reject_malformed",
    },
    {
        "name": "floor-bool",
        "patch": {"secrets": {BASE["secret_id"]: True}},
        "resign": OWNER,
        "outcome": "reject_malformed",
    },
    {"name": "version-2", "patch": {"v": 2}, "outcome": "reject_malformed"},
    {"name": "duplicate-json-key", "duplicate_key": "secrets"},
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
            "€": 0,
            "\r": 1,
            "דּ": 2,
            "1": 3,
            "\U0001f600": 4,
            "\u0080": 5,
            "ö": 6,
            "｡": 7,
        },
    },
    {"name": "escapes", "value": {"s": '"\\/\b\f\n\r\t\u0000\u001f\u007f'}},
    {"name": "safe-integers", "value": {"max": 2**53 - 1, "min": -(2**53 - 1)}},
    {"name": "empty", "value": {}},
]


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text)


def _load_or_create_key() -> rsa.RSAPrivateKey:
    if ENVELOPE_PATH.exists():
        pem = json.loads(ENVELOPE_PATH.read_text())["rsa_private_key_pkcs8_pem"]
        key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
        if isinstance(key, rsa.RSAPrivateKey) and key.key_size == RSA_BITS:
            return key
    return rsa.generate_private_key(public_exponent=65537, key_size=RSA_BITS)


def _owner_vector(owner: OwnerKey) -> dict[str, str]:
    return {
        "seed_hex": owner.seed.hex(),
        "public_key_hex": owner.public_key.hex(),
        "fingerprint_hex": owner.fingerprint.hex(),
    }


def _seal_case(case: dict[str, Any], public_pem: bytes, owner: OwnerKey) -> Envelope:
    pool = case["dek"] + case["nonce"]

    def fixed_random(size: int) -> bytes:
        nonlocal pool
        chunk, pool = pool[:size], pool[size:]
        return chunk

    return _seal(
        public_pem,
        case["secret_id"],
        case["owner_id"],
        case["policy"],
        case["plaintext"],
        owner_key=owner,
        version=case["version"],
        kms_key_version=case["kms_key_version"],
        random_bytes=fixed_random,
    )


def _envelope_vector(case: dict[str, Any], public_pem: bytes) -> dict[str, Any]:
    envelope = _seal_case(case, public_pem, OWNER)
    aad_input = canonical_json(envelope.header())
    return {
        "name": case["name"],
        "secret_id": case["secret_id"],
        "owner_id": case["owner_id"],
        "policy": case["policy"],
        "version": case["version"],
        "plaintext_b64": _b64(case["plaintext"]),
        "dek_hex": case["dek"].hex(),
        "nonce_hex": case["nonce"].hex(),
        "aad_input_b64": _b64(aad_input),
        "aad_hex": hashlib.sha256(aad_input).hexdigest(),
        "ct_b64": _b64(envelope.ct),
        "signing_input_b64": _b64(
            signing_input(ENVELOPE_CONTEXT, envelope.signed_body())
        ),
        "envelope": envelope.to_dict(),
    }


def _flip(data: bytes, index: int) -> bytes:
    index %= len(data)
    return data[:index] + bytes([data[index] ^ 0x01]) + data[index + 1 :]


def _with_duplicate_key(wire: dict[str, Any], key: str) -> str:
    """JSON text repeating ``key``: a benign value first, the real one last."""
    text = json.dumps(wire, ensure_ascii=True)
    return "{" + json.dumps(key) + ":{}," + text[1:]


def _resign(wire: dict[str, Any], signer: OwnerKey, context: bytes) -> dict[str, Any]:
    """Sign the wire body as-is, so even malformed bodies can carry a valid sig."""
    body = {name: value for name, value in wire.items() if name != "sig"}
    if context:
        sig = signer.sign_object(context, body)
    else:
        sig = KeyPair.from_private_bytes(signer.seed).sign(canonical_json(body))
    return {**wire, "sig": _b64(sig)}


def _apply_binary_edits(wire: dict[str, Any], case: dict[str, Any]) -> None:
    for field in ("ct", "nonce", "wrapped", "sig"):
        if f"flip_{field}" in case:
            wire[field] = _b64(_flip(_unb64(wire[field]), case[f"flip_{field}"]))
        if f"truncate_{field}" in case:
            wire[field] = _b64(_unb64(wire[field])[: -case[f"truncate_{field}"]])


def _tamper_vector(
    case: dict[str, Any], base: dict[str, Any], public_pem: bytes
) -> dict[str, Any]:
    wire = dict(base["envelope"])
    if "seal_as" in case:
        wire = _seal_case(BASE, public_pem, case["seal_as"]).to_dict()
    wire.update(case.get("patch", {}))
    if "owner_pk" in case:
        wire["owner_pk"] = _b64(case["owner_pk"].public_key)
    if "ct_bytes" in case:
        wire["ct"] = _b64(case["ct_bytes"])
    # Edits that a re-signing owner would sign over come first; the signature
    # itself is damaged last.
    truncate_sig = case.pop("truncate_sig", None)
    _apply_binary_edits(wire, case)
    if "resign" in case:
        wire = _resign(wire, case["resign"], case.get("context", ENVELOPE_CONTEXT))
    if truncate_sig is not None:
        wire["sig"] = _b64(_unb64(wire["sig"])[:-truncate_sig])
    if case.get("unpad_sig"):
        wire["sig"] = wire["sig"].rstrip("=")
    vector = {
        "name": case["name"],
        "base": base["name"],
        "expected_secret_id": case.get("expected_secret_id", base["secret_id"]),
        "expected_owner_pk_hex": OWNER.public_key.hex(),
        "min_version": case.get("min_version", 1),
        "outcome": case.get("outcome", "reject_signature"),
    }
    if "duplicate_key" in case:
        vector["envelope_json"] = _with_duplicate_key(wire, case["duplicate_key"])
        vector["outcome"] = "reject_malformed"
    else:
        vector["envelope"] = wire
    return vector


def _api_key(case: dict[str, Any]) -> ApiKey:
    owner: OwnerKey = case["owner"]
    return ApiKey.parse(f"cpk_{owner.fingerprint.hex()}_{case['random'].hex()}")


def _api_key_vector(case: dict[str, Any]) -> dict[str, Any]:
    key = _api_key(case)
    return {
        "name": case["name"],
        "raw": key.raw,
        "fingerprint_hex": key.fingerprint.hex(),
        "lookup_hash_hex": key.lookup_hash.hex(),
        "bind_hash_hex": key.bind_hash.hex(),
    }


def _grant_tamper_vector(
    case: dict[str, Any], base: Grant, keys: dict[str, ApiKey]
) -> dict[str, Any]:
    wire = base.to_dict()
    wire.update(case.get("patch", {}))
    if "bind_of" in case:
        wire["key_bind"] = _b64(keys[case["bind_of"]].bind_hash)
    if "owner_pk" in case:
        wire["owner_pk"] = _b64(case["owner_pk"].public_key)
    _apply_binary_edits(wire, case)
    if "resign" in case:
        wire = _resign(wire, case["resign"], case.get("context", GRANT_CONTEXT))
    vector = {
        "name": case["name"],
        "api_key": case.get("api_key", "owner-key-1"),
        "now": case.get("now", NOW),
        "secret_id": case.get("secret_id", BASE["secret_id"]),
        "outcome": case.get("outcome", "reject_signature"),
    }
    if "duplicate_key" in case:
        vector["grant_json"] = _with_duplicate_key(wire, case["duplicate_key"])
        vector["outcome"] = "reject_malformed"
    else:
        vector["grant"] = wire
    return vector


def _write(path: Path, document: dict[str, Any]) -> None:
    path.write_text(json.dumps(document, indent=2, ensure_ascii=True) + "\n")


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
    _write(
        ENVELOPE_PATH,
        {
            "description": (
                "Carapace envelope v1 test vectors. The RSA key and the owner "
                "seeds are PUBLIC TEST KEYS; never use them for real data. "
                "RSA-OAEP output is randomized, so implementations must check "
                "that decrypting 'wrapped' yields 'dek_hex', that AES-256-GCM "
                "with dek/nonce/aad yields 'ct_b64', and that 'sig' verifies "
                "over 'signing_input_b64' under the owner public key. Every "
                "'tamper' entry must be rejected with the named outcome, "
                "checked in this order: 'reject_malformed' at parse, "
                "'reject_signature' at the identity/owner-signature check, "
                "'reject_stale' at the version floor ('min_version'), all "
                "before any unwrap; 'reject_authentication' at AES-GCM after "
                "a successful unwrap. Entries with 'envelope_json' are raw "
                "JSON text the parser must reject (duplicate keys)."
            ),
            "algorithms": {
                "aead": "AES-256-GCM, 12-byte nonce, 16-byte tag appended to ct",
                "wrap": "RSA-OAEP, SHA-256, MGF1-SHA-256, empty label",
                "aad": (
                    "sha256(canonical_json({v, secret_id, owner_id, owner_pk, "
                    "version, policy}))"
                ),
                "signature": (
                    "Ed25519 over 'carapace-envelope-v1' || 0x0A || "
                    "canonical_json(envelope without sig)"
                ),
                "fingerprint": (
                    "sha256('carapace-owner-fp-v1' || 0x0A || public_key)[:16]"
                ),
                "binary_encoding": "RFC 4648 base64 with padding, canonical",
            },
            "rsa_public_key_pem": public_pem.decode("ascii"),
            "rsa_private_key_pkcs8_pem": private_pem.decode("ascii"),
            "owner": _owner_vector(OWNER),
            "attacker": _owner_vector(ATTACKER),
            "envelopes": envelopes,
            "tamper": [
                _tamper_vector(dict(c), envelopes[0], public_pem) for c in TAMPER_CASES
            ],
            "canonical_json": [
                {
                    "name": case["name"],
                    "value": case["value"],
                    "canonical_b64": _b64(canonical_json(case["value"])),
                }
                for case in CANONICAL_CASES
            ],
        },
    )

    keys = {c["name"]: _api_key(c) for c in API_KEY_CASES}
    grant = create_grant(OWNER, keys["owner-key-1"], GRANT_SECRETS, now=NOW)
    _write(
        GRANT_PATH,
        {
            "description": (
                "Carapace API key and grant v1 test vectors. Owner seeds are "
                "PUBLIC TEST KEYS. 'api_keys' give the hashes an implementation "
                "must derive from each raw key. Every 'tamper' entry names the "
                "api key presented, the verification time 'now', the "
                "'secret_id' requested, and the outcome: 'reject_malformed' at "
                "parse, 'reject_key_mismatch' when the owner fingerprint or "
                "key binding does not match the presented key, "
                "'reject_signature', 'reject_expired' (outside "
                "[iat - clock_skew_seconds, exp)), 'reject_scope' when "
                "'secret_id' is not covered, or 'accept'."
            ),
            "algorithms": {
                "api_key": "'cpk_' || hex(fingerprint) || '_' || hex(random(32))",
                "lookup_hash": "sha256('carapace-key-lookup-v1' || 0x0A || key)",
                "bind_hash": "sha256('carapace-key-bind-v1' || 0x0A || key)",
                "signature": (
                    "Ed25519 over 'carapace-grant-v1' || 0x0A || "
                    "canonical_json(grant without sig)"
                ),
                "max_ttl_seconds": MAX_GRANT_TTL_SECONDS,
                "clock_skew_seconds": CLOCK_SKEW_SECONDS,
            },
            "owner": _owner_vector(OWNER),
            "attacker": _owner_vector(ATTACKER),
            "api_keys": [_api_key_vector(c) for c in API_KEY_CASES],
            "grants": [
                {
                    "name": "owner-key-1-two-secrets",
                    "api_key": "owner-key-1",
                    "now": NOW,
                    "signing_input_b64": _b64(
                        signing_input(GRANT_CONTEXT, grant.signed_body())
                    ),
                    "grant": grant.to_dict(),
                }
            ],
            "tamper": [
                _grant_tamper_vector(dict(c), grant, keys) for c in GRANT_TAMPER_CASES
            ],
        },
    )


if __name__ == "__main__":
    main()
