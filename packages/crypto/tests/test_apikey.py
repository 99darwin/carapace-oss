"""Tests for client-minted API keys."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from carapace_crypto.apikey import KEY_LENGTH, ApiKey, ApiKeyError
from carapace_crypto.ownerkey import OwnerKey

VECTORS = json.loads((Path(__file__).parent / "vectors" / "grant_v1.json").read_text())
OWNER = OwnerKey.from_seed(bytes(range(32)))
OTHER = OwnerKey.from_seed(bytes(range(32, 64)))


class TestFormat:
    def test_generate_then_parse(self) -> None:
        key = ApiKey.generate(OWNER)
        assert len(key.raw) == KEY_LENGTH == 101
        assert key.raw.startswith("cpk_" + OWNER.fingerprint.hex() + "_")
        assert ApiKey.parse(key.raw) == key
        assert key.fingerprint == OWNER.fingerprint

    def test_generate_is_random(self) -> None:
        assert ApiKey.generate(OWNER).raw != ApiKey.generate(OWNER).raw

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "cpk_",
            "cpk_" + "0" * 32 + "_" + "0" * 63,
            "cpk_" + "0" * 32 + "_" + "0" * 65,
            "cpk_" + "0" * 31 + "_" + "0" * 65,
            "cpk_" + "0" * 32 + "-" + "0" * 64,
            "CPK_" + "0" * 32 + "_" + "0" * 64,
            "cpk_" + "A" * 32 + "_" + "0" * 64,
            "cpk_" + "0" * 32 + "_" + "g" * 64,
            "cpk_" + "0" * 32 + "_" + "0" * 63 + "\n",
            "cpk_" + "0" * 32 + "_" + "0" * 63 + " ",
            "xpk_" + "0" * 32 + "_" + "0" * 64,
        ],
    )
    def test_parse_rejects_malformed(self, raw: str) -> None:
        with pytest.raises(ApiKeyError):
            ApiKey.parse(raw)

    @pytest.mark.parametrize("raw", [None, 5, b"cpk_"])
    def test_parse_rejects_non_strings(self, raw: Any) -> None:
        with pytest.raises(ApiKeyError):
            ApiKey.parse(raw)

    def test_repr_redacts_key(self) -> None:
        key = ApiKey.generate(OWNER)
        assert key.raw[4:] not in repr(key)
        assert OWNER.fingerprint.hex() in repr(key)


class TestHashes:
    def test_lookup_and_bind_differ_and_are_domain_separated(self) -> None:
        key = ApiKey.generate(OWNER)
        raw = key.raw.encode("ascii")
        assert (
            key.lookup_hash
            == hashlib.sha256(b"carapace-key-lookup-v1\n" + raw).digest()
        )
        assert key.bind_hash == hashlib.sha256(b"carapace-key-bind-v1\n" + raw).digest()
        assert key.lookup_hash != key.bind_hash
        assert hashlib.sha256(raw).digest() not in (key.lookup_hash, key.bind_hash)

    def test_hashes_cover_fingerprint(self) -> None:
        random_part = ApiKey.generate(OWNER).raw.split("_")[2]
        ours = ApiKey.parse(f"cpk_{OWNER.fingerprint.hex()}_{random_part}")
        theirs = ApiKey.parse(f"cpk_{OTHER.fingerprint.hex()}_{random_part}")
        assert ours.lookup_hash != theirs.lookup_hash
        assert ours.bind_hash != theirs.bind_hash


class TestVectors:
    @pytest.mark.parametrize("vector", VECTORS["api_keys"], ids=lambda v: v["name"])
    def test_vector(self, vector: dict[str, Any]) -> None:
        key = ApiKey.parse(vector["raw"])
        assert key.fingerprint.hex() == vector["fingerprint_hex"]
        assert key.lookup_hash.hex() == vector["lookup_hash_hex"]
        assert key.bind_hash.hex() == vector["bind_hash_hex"]

    def test_vector_fingerprints_name_the_vector_owners(self) -> None:
        by_name = {v["name"]: v for v in VECTORS["api_keys"]}
        owner_fp = VECTORS["owner"]["fingerprint_hex"]
        assert by_name["owner-key-1"]["fingerprint_hex"] == owner_fp
        assert by_name["owner-key-2"]["fingerprint_hex"] == owner_fp
        assert (
            by_name["attacker-key"]["fingerprint_hex"]
            == VECTORS["attacker"]["fingerprint_hex"]
        )
