"""Tests for owner-signed grants."""

from __future__ import annotations

import base64
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from carapace_crypto.apikey import ApiKey
from carapace_crypto.canonical import canonical_json
from carapace_crypto.envelope import ENVELOPE_CONTEXT
from carapace_crypto.grant import (
    CLOCK_SKEW_SECONDS,
    DEFAULT_GRANT_TTL_SECONDS,
    GRANT_CONTEXT,
    MAX_GRANT_SECRETS,
    MAX_GRANT_TTL_SECONDS,
    MAX_SECRET_ID_LENGTH,
    Grant,
    GrantError,
    GrantExpiredError,
    GrantKeyMismatchError,
    GrantScopeError,
    GrantSignatureError,
    create_grant,
    verify_grant,
)
from carapace_crypto.hashing import tagged_sha256
from carapace_crypto.ownerkey import FINGERPRINT_TAG, OwnerKey, signing_input
from carapace_crypto.signing import KeyPair

VECTORS = json.loads((Path(__file__).parent / "vectors" / "grant_v1.json").read_text())
OWNER = OwnerKey.from_seed(bytes(range(32)))
ATTACKER = OwnerKey.from_seed(bytes(range(32, 64)))
KEY = ApiKey.generate(OWNER)
OTHER_KEY = ApiKey.generate(OWNER)
ATTACKER_KEY = ApiKey.generate(ATTACKER)
NOW = 1_800_000_000
SECRETS = {"secret-a": 5, "secret-b": 1}


def _grant(**overrides: Any) -> Grant:
    args: dict[str, Any] = {"now": NOW}
    args.update(overrides)
    return create_grant(OWNER, KEY, SECRETS, **args)


def _resigned(grant: Grant, signer: OwnerKey = OWNER) -> Grant:
    return dataclasses.replace(
        grant, sig=signer.sign_object(GRANT_CONTEXT, grant.signed_body())
    )


class TestRoundTrip:
    def test_create_then_verify(self) -> None:
        grant = _grant()
        verified = verify_grant(grant, KEY, now=NOW + 1000)
        assert verified.min_version_for("secret-a") == 5
        assert verified.owner_pk == OWNER.public_key
        assert verified.key_bind == KEY.bind_hash
        assert verified.exp - verified.iat == DEFAULT_GRANT_TTL_SECONDS

    def test_json_round_trip(self) -> None:
        grant = _grant()
        assert Grant.from_json(json.dumps(grant.to_dict())) == grant
        assert set(grant.to_dict()) == {
            "v",
            "owner_pk",
            "key_bind",
            "secrets",
            "iat",
            "exp",
            "sig",
        }

    def test_signing_input_is_context_newline_canonical_body(self) -> None:
        grant = _grant()
        expected = b"carapace-grant-v1\n" + canonical_json(grant.signed_body())
        assert signing_input(GRANT_CONTEXT, grant.signed_body()) == expected
        assert KeyPair.verify(OWNER.public_key, grant.sig, expected)

    def test_tombstone_verifies_but_covers_nothing(self) -> None:
        tombstone = create_grant(OWNER, KEY, {}, now=NOW)
        verify_grant(tombstone, KEY, now=NOW)
        with pytest.raises(GrantScopeError):
            tombstone.min_version_for("secret-a")

    def test_custom_ttl(self) -> None:
        grant = _grant(ttl_seconds=60)
        assert grant.exp == NOW + 60
        verify_grant(grant, KEY, now=NOW + 59)
        with pytest.raises(GrantExpiredError):
            verify_grant(grant, KEY, now=NOW + 60)

    def test_secrets_are_copied(self) -> None:
        secrets = dict(SECRETS)
        grant = create_grant(OWNER, KEY, secrets, now=NOW)
        secrets["injected"] = 1
        assert "injected" not in grant.secrets


class TestKeyBinding:
    def test_cannot_issue_for_key_naming_another_owner(self) -> None:
        with pytest.raises(GrantKeyMismatchError):
            create_grant(OWNER, ATTACKER_KEY, SECRETS, now=NOW)

    def test_grant_for_other_key_of_same_owner_is_rejected(self) -> None:
        with pytest.raises(GrantKeyMismatchError, match="different API key"):
            verify_grant(_grant(), OTHER_KEY, now=NOW)

    def test_presented_with_attacker_key_is_rejected(self) -> None:
        # The attacker's key names the attacker's fingerprint; the grant's
        # owner_pk does not match it, before any signature work.
        with pytest.raises(GrantKeyMismatchError, match="owner key"):
            verify_grant(_grant(), ATTACKER_KEY, now=NOW)

    def test_attacker_grant_for_attacker_key_cannot_use_victim_key(self) -> None:
        theirs = create_grant(ATTACKER, ATTACKER_KEY, SECRETS, now=NOW)
        with pytest.raises(GrantKeyMismatchError):
            verify_grant(theirs, KEY, now=NOW)

    def test_attacker_signature_over_owner_pk_is_rejected(self) -> None:
        forged = _resigned(_grant(), ATTACKER)
        with pytest.raises(GrantSignatureError):
            verify_grant(forged, KEY, now=NOW)

    def test_owner_pk_swapped_and_resigned_is_rejected(self) -> None:
        # Consistent under the attacker's key, but the API key names OWNER.
        edited = dataclasses.replace(_grant(), owner_pk=ATTACKER.public_key)
        with pytest.raises(GrantKeyMismatchError):
            verify_grant(_resigned(edited, ATTACKER), KEY, now=NOW)

    def test_key_bind_edited_and_resigned_is_rejected(self) -> None:
        edited = _resigned(dataclasses.replace(_grant(), key_bind=OTHER_KEY.bind_hash))
        with pytest.raises(GrantKeyMismatchError):
            verify_grant(edited, KEY, now=NOW)


class TestTampering:
    @pytest.mark.parametrize(
        "edit",
        [
            {"secrets": {**SECRETS, "secret-c": 1}},
            {"secrets": {**SECRETS, "secret-a": 1}},
            {"exp": NOW + DEFAULT_GRANT_TTL_SECONDS + 1},
            {"iat": NOW - 1},
            {"key_bind": OTHER_KEY.bind_hash},
        ],
        ids=["widen", "lower-floor", "extend", "backdate", "rebind"],
    )
    def test_edit_fails_signature(self, edit: dict[str, Any]) -> None:
        with pytest.raises(GrantSignatureError):
            verify_grant(dataclasses.replace(_grant(), **edit), KEY, now=NOW)

    def test_flipped_signature_fails(self) -> None:
        grant = _grant()
        flipped = bytes([grant.sig[0] ^ 1]) + grant.sig[1:]
        with pytest.raises(GrantSignatureError):
            verify_grant(dataclasses.replace(grant, sig=flipped), KEY, now=NOW)

    def test_signature_under_envelope_context_fails(self) -> None:
        grant = _grant()
        sig = OWNER.sign_object(ENVELOPE_CONTEXT, grant.signed_body())
        with pytest.raises(GrantSignatureError):
            verify_grant(dataclasses.replace(grant, sig=sig), KEY, now=NOW)

    def test_signature_without_context_fails(self) -> None:
        grant = _grant()
        sig = KeyPair.from_private_bytes(OWNER.seed).sign(
            canonical_json(grant.signed_body())
        )
        with pytest.raises(GrantSignatureError):
            verify_grant(dataclasses.replace(grant, sig=sig), KEY, now=NOW)


class TestLifetime:
    def test_expired(self) -> None:
        grant = _grant()
        with pytest.raises(GrantExpiredError, match="expired"):
            verify_grant(grant, KEY, now=grant.exp)

    def test_last_valid_second(self) -> None:
        grant = _grant()
        verify_grant(grant, KEY, now=grant.exp - 1)

    def test_not_yet_valid_beyond_skew(self) -> None:
        with pytest.raises(GrantExpiredError, match="not yet valid"):
            verify_grant(_grant(), KEY, now=NOW - CLOCK_SKEW_SECONDS - 1)

    def test_within_skew(self) -> None:
        verify_grant(_grant(), KEY, now=NOW - CLOCK_SKEW_SECONDS)

    @pytest.mark.parametrize("now", [float("nan"), True, "1", None, NOW + 0.5])
    def test_verify_rejects_non_integer_now(self, now: Any) -> None:
        with pytest.raises(GrantError):
            verify_grant(_grant(), KEY, now=now)

    def test_replacement_iat_is_strictly_above_previous(self) -> None:
        first = _grant()
        tombstone = create_grant(OWNER, KEY, {}, now=NOW, previous_iat=first.iat)
        assert tombstone.iat == first.iat + 1
        assert tombstone.exp == tombstone.iat + DEFAULT_GRANT_TTL_SECONDS
        verify_grant(tombstone, KEY, now=NOW)

    def test_replacement_keeps_now_when_already_later(self) -> None:
        later = create_grant(OWNER, KEY, {}, now=NOW + 60, previous_iat=NOW)
        assert later.iat == NOW + 60

    def test_replacement_rejects_bad_previous_iat(self) -> None:
        with pytest.raises(GrantError):
            _grant(previous_iat=True)

    def test_create_rejects_ttl_over_cap(self) -> None:
        with pytest.raises(GrantError, match="lifetime"):
            _grant(ttl_seconds=MAX_GRANT_TTL_SECONDS + 1)

    def test_create_accepts_ttl_at_cap(self) -> None:
        verify_grant(_grant(ttl_seconds=MAX_GRANT_TTL_SECONDS), KEY, now=NOW)

    @pytest.mark.parametrize("ttl", [0, -1])
    def test_create_rejects_non_positive_ttl(self, ttl: int) -> None:
        with pytest.raises(GrantError):
            _grant(ttl_seconds=ttl)

    def test_resigned_overlong_lifetime_is_rejected_at_parse(self) -> None:
        # Even a legitimately signed grant cannot exceed the cap.
        edited = dataclasses.replace(_grant(), exp=NOW + MAX_GRANT_TTL_SECONDS + 1)
        wire = _resigned(edited).to_dict()
        with pytest.raises(GrantError, match="lifetime"):
            Grant.from_dict(wire)
        with pytest.raises(GrantError):
            verify_grant(edited, KEY, now=NOW)


class TestScope:
    def test_min_version_for_covered_secret(self) -> None:
        assert _grant().min_version_for("secret-b") == 1

    def test_uncovered_secret(self) -> None:
        with pytest.raises(GrantScopeError):
            _grant().min_version_for("secret-c")


class TestParsing:
    @pytest.mark.parametrize(
        "mutation",
        [
            {"v": 2},
            {"v": True},
            {"v": "1"},
            {"owner_pk": base64.b64encode(b"x" * 31).decode()},
            {"key_bind": base64.b64encode(b"x" * 31).decode()},
            {"sig": base64.b64encode(b"x" * 65).decode()},
            {"sig": None},
            {"secrets": []},
            {"secrets": {"": 1}},
            {"secrets": {"x" * (MAX_SECRET_ID_LENGTH + 1): 1}},
            {"secrets": {"a": 0}},
            {"secrets": {"a": True}},
            {"secrets": {"a": "1"}},
            {"secrets": {"a": 2**53}},
            {"secrets": {f"s{i}": 1 for i in range(MAX_GRANT_SECRETS + 1)}},
            {"iat": 0},
            {"iat": True},
            {"iat": "1"},
            {"exp": NOW},
            {"exp": NOW - 1},
            {"exp": NOW + MAX_GRANT_TTL_SECONDS + 1},
        ],
    )
    def test_from_dict_rejects_malformed(self, mutation: dict[str, Any]) -> None:
        with pytest.raises(GrantError):
            Grant.from_dict({**_grant().to_dict(), **mutation})

    def test_from_dict_rejects_unknown_field(self) -> None:
        with pytest.raises(GrantError, match="missing or unknown"):
            Grant.from_dict({**_grant().to_dict(), "extra": 1})

    def test_from_dict_rejects_missing_field(self) -> None:
        wire = _grant().to_dict()
        del wire["exp"]
        with pytest.raises(GrantError, match="missing or unknown"):
            Grant.from_dict(wire)

    def test_from_dict_rejects_urlsafe_or_unpadded_base64(self) -> None:
        wire = _grant().to_dict()
        with pytest.raises(GrantError):
            Grant.from_dict({**wire, "sig": wire["sig"].rstrip("=")})
        urlsafe = base64.urlsafe_b64encode(b"\xfb" * 32).decode()
        with pytest.raises(GrantError):
            Grant.from_dict({**wire, "key_bind": urlsafe})

    def test_from_dict_accepts_max_secrets(self) -> None:
        secrets = {f"s{i}": 1 for i in range(MAX_GRANT_SECRETS)}
        grant = create_grant(OWNER, KEY, secrets, now=NOW)
        assert Grant.from_dict(grant.to_dict()) == grant

    def test_from_json_rejects_duplicate_keys(self) -> None:
        text = json.dumps(_grant().to_dict())
        with pytest.raises(GrantError, match="duplicate"):
            Grant.from_json('{"secrets":{},' + text[1:])

    @pytest.mark.parametrize("text", ["[]", "1", "{", ""])
    def test_from_json_rejects_non_objects(self, text: str) -> None:
        with pytest.raises(GrantError):
            Grant.from_json(text)


class TestVectors:
    @staticmethod
    def _keys() -> dict[str, ApiKey]:
        return {k["name"]: ApiKey.parse(k["raw"]) for k in VECTORS["api_keys"]}

    @pytest.mark.parametrize("vector", VECTORS["grants"], ids=lambda v: v["name"])
    def test_accepted_grant(self, vector: dict[str, Any]) -> None:
        owner_pk = bytes.fromhex(VECTORS["owner"]["public_key_hex"])
        key = self._keys()[vector["api_key"]]
        grant = Grant.from_dict(vector["grant"])
        signing_bytes = base64.b64decode(vector["signing_input_b64"])
        assert signing_input(GRANT_CONTEXT, grant.signed_body()) == signing_bytes
        assert signing_bytes.startswith(b"carapace-grant-v1\n")
        assert KeyPair.verify(owner_pk, grant.sig, signing_bytes)
        verified = verify_grant(grant, key, now=vector["now"])
        assert verified.secrets == vector["grant"]["secrets"]

    def test_accepted_grant_is_reproducible(self) -> None:
        owner = OwnerKey.from_seed(bytes.fromhex(VECTORS["owner"]["seed_hex"]))
        vector = VECTORS["grants"][0]
        grant = vector["grant"]
        rebuilt = create_grant(
            owner,
            self._keys()[vector["api_key"]],
            grant["secrets"],
            now=grant["iat"],
            ttl_seconds=grant["exp"] - grant["iat"],
        )
        assert rebuilt.to_dict() == grant

    @pytest.mark.parametrize("vector", VECTORS["tamper"], ids=lambda v: v["name"])
    def test_tamper_vector(self, vector: dict[str, Any]) -> None:
        key = self._keys()[vector["api_key"]]
        outcome = vector["outcome"]
        try:
            if "grant_json" in vector:
                grant = Grant.from_json(vector["grant_json"])
            else:
                grant = Grant.from_dict(vector["grant"])
        except GrantError as exc:
            assert outcome == "reject_malformed", f"unexpected parse failure: {exc}"
            assert type(exc) is GrantError
            return
        assert outcome != "reject_malformed", "malformed vector parsed"

        expected = {
            "reject_key_mismatch": GrantKeyMismatchError,
            "reject_signature": GrantSignatureError,
            "reject_expired": GrantExpiredError,
        }
        if outcome in expected:
            with pytest.raises(expected[outcome]):
                verify_grant(grant, key, now=vector["now"])
            return
        verified = verify_grant(grant, key, now=vector["now"])
        if outcome == "reject_scope":
            with pytest.raises(GrantScopeError):
                verified.min_version_for(vector["secret_id"])
        else:
            assert outcome == "accept"
            assert verified.min_version_for(vector["secret_id"]) >= 1

    def test_tamper_vectors_cover_required_cases(self) -> None:
        names = {v["name"] for v in VECTORS["tamper"]}
        required = {
            "presented-with-other-key",
            "presented-with-attacker-key",
            "signed-by-attacker",
            "signed-under-envelope-context",
            "secret-not-covered",
            "expired",
            "floor-lowered",
            "duplicate-json-key",
        }
        assert required <= names


class TestSeedlessForgery:
    """A small-order owner_pk would let anyone sign a grant without a seed."""

    IDENTITY_PK = (1).to_bytes(32, "little")
    UNIVERSAL_SIG = IDENTITY_PK + bytes(32)

    def _weak_key_and_body(self) -> tuple[ApiKey, dict[str, Any]]:
        fp = tagged_sha256(FINGERPRINT_TAG, self.IDENTITY_PK)[:16]
        key = ApiKey.parse(f"cpk_{fp.hex()}_{'ab' * 32}")
        body = {
            "v": 1,
            "owner_pk": base64.b64encode(self.IDENTITY_PK).decode(),
            "key_bind": base64.b64encode(key.bind_hash).decode(),
            "secrets": {"victim-secret": 1},
            "iat": NOW,
            "exp": NOW + DEFAULT_GRANT_TTL_SECONDS,
        }
        return key, body

    def test_universal_signature_really_verifies_at_the_primitive(self) -> None:
        _, body = self._weak_key_and_body()
        message = signing_input(GRANT_CONTEXT, body)
        assert KeyPair.verify(self.IDENTITY_PK, self.UNIVERSAL_SIG, message)

    def test_parser_rejects_small_order_owner_pk(self) -> None:
        _, body = self._weak_key_and_body()
        wire = {**body, "sig": base64.b64encode(self.UNIVERSAL_SIG).decode()}
        with pytest.raises(GrantError, match="small-order"):
            Grant.from_dict(wire)

    def test_verify_rejects_directly_constructed_weak_grant(self) -> None:
        key, _ = self._weak_key_and_body()
        grant = Grant(
            owner_pk=self.IDENTITY_PK,
            key_bind=key.bind_hash,
            secrets={"victim-secret": 1},
            iat=NOW,
            exp=NOW + DEFAULT_GRANT_TTL_SECONDS,
            sig=self.UNIVERSAL_SIG,
        )
        with pytest.raises(GrantKeyMismatchError, match="invalid"):
            verify_grant(grant, key, now=NOW)
