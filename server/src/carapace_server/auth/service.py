"""Account registration, login (password or passkey) and session rotation.

Security notes:
- Passwords: bcrypt over base64(sha256(password)), so long passwords keep
  their full entropy instead of being truncated at 72 bytes. Hashing runs in
  a worker thread to keep the event loop responsive.
- User enumeration: unknown accounts still pay for a bcrypt check, and
  passkey login options for unknown accounts return a deterministic decoy
  credential ID, so neither timing nor response shape reveals existence.
- Passkey registration verifies the full attestation response with
  py_webauthn; client-supplied public keys are never trusted directly.
- Refresh tokens are random, stored as SHA-256 hashes, single use. Reuse of
  a rotated token revokes its whole family (see :meth:`AuthService.refresh`).
- Passkey ceremonies require user verification, so possession of an
  authenticator alone (user presence) is not enough to sign in.
- Registration is closed unless ``allow_signup`` is set: only the first
  account registers, and only with the one-time setup token (compared as
  SHA-256 digests in constant time). The first account also inserts the
  single ``instance_claim`` row in its transaction, so of two concurrent
  first registrations the database lets exactly one commit.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

import bcrypt
import webauthn
from sqlalchemy import delete, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn.helpers import options_to_json_dict, parse_authentication_credential_json
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    UserVerificationRequirement,
)

from carapace_server.auth.models import (
    INSTANCE_CLAIM_ID,
    ChallengeType,
    InstanceClaim,
    RefreshToken,
    User,
    WebAuthnChallenge,
)
from carapace_server.auth.tokens import create_access_token
from carapace_server.config import Settings
from carapace_server.db import utcnow

logger = logging.getLogger(__name__)

CHALLENGE_TTL = timedelta(minutes=2)
CHALLENGE_TIMEOUT_MS = 120_000
REFRESH_TOKEN_BYTES = 32
USER_AGENT_MAX_LENGTH = 512
DECOY_CREDENTIAL_ID_BYTES = 32
# Stable 403 details; the CLI matches on them.
REGISTRATION_CLOSED = "Registration is closed"
SETUP_TOKEN_INVALID = "Invalid setup token"  # noqa: S105 - a message


class AuthError(Exception):
    """Generic authentication failure. Messages are safe to show clients."""


class RegistrationClosedError(AuthError):
    """An account exists and ``allow_signup`` is off."""


class SetupTokenError(AuthError):
    """The first registration lacked the right setup token."""


@dataclass(frozen=True)
class ClientInfo:
    user_agent: str | None
    ip_address: str | None


@dataclass(frozen=True)
class Session:
    user_id: uuid.UUID
    access_token: str
    refresh_token: str


def normalize_email(email: str) -> str:
    return email.strip().lower()


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _prehash(password: str) -> bytes:
    return base64.b64encode(hashlib.sha256(password.encode()).digest())


def _hash_password(password: str, rounds: int) -> bytes:
    return bcrypt.hashpw(_prehash(password), bcrypt.gensalt(rounds=rounds))


def _check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(_prehash(password), hashed)


@lru_cache
def dummy_password_hash(rounds: int) -> bytes:
    """A real bcrypt hash at the configured cost, for timing equalization."""
    return _hash_password(secrets.token_urlsafe(16), rounds)


class AuthService:
    def __init__(self, db: AsyncSession, settings: Settings) -> None:
        self.db = db
        self.settings = settings

    # -- lookups ------------------------------------------------------------

    async def _user_by_email(self, email: str) -> User | None:
        return await self.db.scalar(select(User).where(User.email == email))

    # -- registration gate --------------------------------------------------

    async def ensure_registration_open(self) -> None:
        """Raise unless signup is open or no account exists yet.

        A read, so it only fails early; :meth:`_add_user` is what makes the
        first registration atomic.
        """
        if self.settings.allow_signup:
            return
        if await self.db.scalar(select(User.id).limit(1)) is not None:
            raise RegistrationClosedError(REGISTRATION_CLOSED)

    def _setup_token_valid(self, setup_token: str | None) -> bool:
        expected = self.settings.setup_token_sha256
        if expected is None:
            # Local development only; prod fails closed without a token.
            return self.settings.mode == "dev"
        presented = hashlib.sha256((setup_token or "").encode()).hexdigest()
        return hmac.compare_digest(presented, expected) and bool(setup_token)

    async def _check_registration(self, setup_token: str | None) -> bool:
        """Raise unless this registration may proceed.

        Returns whether it is the first account, which must claim the
        server. With ``allow_signup`` no token is asked for and nothing is
        claimed.
        """
        await self.ensure_registration_open()
        if self.settings.allow_signup:
            return False
        if not self._setup_token_valid(setup_token):
            raise SetupTokenError(SETUP_TOKEN_INVALID)
        return True

    async def _add_user(self, user: User, *, claim: bool) -> None:
        """Insert ``user`` and, for the first account, the instance claim.

        Both inserts share the caller's transaction. A concurrent first
        registration that committed first makes the claim insert fail on
        its primary key, which closes registration for this one.
        """
        self.db.add(user)
        try:
            await self.db.flush()
            if claim:
                self.db.add(InstanceClaim(id=INSTANCE_CLAIM_ID, user_id=user.id))
                await self.db.flush()
        except IntegrityError:
            await self.db.rollback()
            if claim:
                raise RegistrationClosedError(REGISTRATION_CLOSED) from None
            raise AuthError("Registration failed") from None

    # -- password -----------------------------------------------------------

    async def register_with_password(
        self,
        email: str,
        password: str,
        display_name: str | None,
        client: ClientInfo,
        *,
        setup_token: str | None = None,
    ) -> Session:
        claim = await self._check_registration(setup_token)
        email = normalize_email(email)
        if await self._user_by_email(email) is not None:
            raise AuthError("Registration failed")
        password_hash = await asyncio.to_thread(
            _hash_password, password, self.settings.bcrypt_rounds
        )
        user = User(email=email, display_name=display_name, password_hash=password_hash)
        await self._add_user(user, claim=claim)
        return await self._start_session(user, client)

    async def login_with_password(
        self, email: str, password: str, client: ClientInfo
    ) -> Session:
        user = await self._user_by_email(normalize_email(email))
        stored = user.password_hash if user else None
        candidate = stored or dummy_password_hash(self.settings.bcrypt_rounds)
        ok = await asyncio.to_thread(_check_password, password, candidate)
        if user is None or stored is None or not ok:
            raise AuthError("Invalid credentials")
        return await self._start_session(user, client)

    # -- passkeys -----------------------------------------------------------

    async def registration_options(self, email: str) -> dict[str, Any]:
        await self.ensure_registration_open()
        email = normalize_email(email)
        if await self._user_by_email(email) is not None:
            raise AuthError("Unable to process request")
        challenge = await self._store_challenge(email, ChallengeType.REGISTER)
        options = webauthn.generate_registration_options(
            rp_id=self.settings.webauthn_rp_id,
            rp_name=self.settings.webauthn_rp_name,
            user_name=email,
            challenge=challenge,
            timeout=CHALLENGE_TIMEOUT_MS,
            authenticator_selection=AuthenticatorSelectionCriteria(
                user_verification=UserVerificationRequirement.REQUIRED
            ),
        )
        return options_to_json_dict(options)

    async def register_with_passkey(
        self,
        email: str,
        display_name: str | None,
        credential: dict[str, Any],
        client: ClientInfo,
        *,
        setup_token: str | None = None,
    ) -> Session:
        email = normalize_email(email)
        challenge = await self._consume_challenge(email, ChallengeType.REGISTER)
        claim = await self._check_registration(setup_token)
        if await self._user_by_email(email) is not None:
            raise AuthError("Registration failed")
        try:
            verified = webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=self.settings.webauthn_origin,
                require_user_verification=True,
            )
        except Exception as exc:
            logger.info("passkey registration rejected: %s", type(exc).__name__)
            raise AuthError("Registration failed") from exc
        user = User(
            email=email,
            display_name=display_name,
            passkey_credential_id=verified.credential_id,
            passkey_public_key=verified.credential_public_key,
            passkey_sign_count=verified.sign_count,
            passkey_transports=credential.get("response", {}).get("transports"),
        )
        await self._add_user(user, claim=claim)
        return await self._start_session(user, client)

    async def authentication_options(self, email: str) -> dict[str, Any]:
        email = normalize_email(email)
        user = await self._user_by_email(email)
        credential_id = (
            user.passkey_credential_id
            if user and user.passkey_credential_id
            else self._decoy_credential_id(email)
        )
        challenge = await self._store_challenge(email, ChallengeType.AUTHENTICATE)
        options = webauthn.generate_authentication_options(
            rp_id=self.settings.webauthn_rp_id,
            challenge=challenge,
            timeout=CHALLENGE_TIMEOUT_MS,
            allow_credentials=[PublicKeyCredentialDescriptor(id=credential_id)],
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        return options_to_json_dict(options)

    async def login_with_passkey(
        self, email: str, credential: dict[str, Any], client: ClientInfo
    ) -> Session:
        email = normalize_email(email)
        challenge = await self._consume_challenge(email, ChallengeType.AUTHENTICATE)
        user = await self._user_by_email(email)
        if user is None or user.passkey_public_key is None:
            raise AuthError("Invalid credentials")
        try:
            parsed = parse_authentication_credential_json(credential)
            if not hmac.compare_digest(parsed.raw_id, user.passkey_credential_id):
                raise AuthError("credential mismatch")
            verified = webauthn.verify_authentication_response(
                credential=parsed,
                expected_challenge=challenge,
                expected_rp_id=self.settings.webauthn_rp_id,
                expected_origin=self.settings.webauthn_origin,
                credential_public_key=user.passkey_public_key,
                credential_current_sign_count=user.passkey_sign_count,
                require_user_verification=True,
            )
        except Exception as exc:
            logger.info("passkey login rejected: %s", type(exc).__name__)
            raise AuthError("Invalid credentials") from exc
        user.passkey_sign_count = verified.new_sign_count
        return await self._start_session(user, client)

    def _decoy_credential_id(self, email: str) -> bytes:
        key = self.settings.jwt_key.encode()
        digest = hmac.new(key, b"passkey-decoy:" + email.encode(), hashlib.sha256)
        return digest.digest()[:DECOY_CREDENTIAL_ID_BYTES]

    async def _store_challenge(self, email: str, kind: ChallengeType) -> bytes:
        await self.db.execute(
            delete(WebAuthnChallenge).where(WebAuthnChallenge.email == email)
        )
        challenge = secrets.token_bytes(32)
        self.db.add(
            WebAuthnChallenge(
                email=email,
                challenge_type=kind,
                challenge=challenge,
                expires_at=utcnow() + CHALLENGE_TTL,
            )
        )
        await self.db.commit()
        return challenge

    async def _consume_challenge(self, email: str, kind: ChallengeType) -> bytes:
        """Fetch and delete the pending challenge (single use)."""
        record = await self.db.scalar(
            select(WebAuthnChallenge).where(
                WebAuthnChallenge.email == email,
                WebAuthnChallenge.challenge_type == kind,
            )
        )
        if record is None:
            raise AuthError("Invalid credentials")
        await self.db.delete(record)
        await self.db.commit()
        if record.expires_at <= utcnow():
            raise AuthError("Invalid credentials")
        return record.challenge

    # -- sessions -----------------------------------------------------------

    async def _start_session(self, user: User, client: ClientInfo) -> Session:
        user.last_login_at = utcnow()
        refresh = self._new_refresh_token(user.id, uuid.uuid4(), client)
        await self.db.commit()
        access = create_access_token(self.settings, user.id)
        return Session(user_id=user.id, access_token=access, refresh_token=refresh)

    def _new_refresh_token(
        self, user_id: uuid.UUID, family_id: uuid.UUID, client: ClientInfo
    ) -> str:
        token = secrets.token_urlsafe(REFRESH_TOKEN_BYTES)
        user_agent = client.user_agent
        self.db.add(
            RefreshToken(
                user_id=user_id,
                family_id=family_id,
                token_hash=hash_refresh_token(token),
                expires_at=utcnow() + timedelta(days=self.settings.refresh_token_days),
                user_agent=user_agent[:USER_AGENT_MAX_LENGTH] if user_agent else None,
                ip_address=client.ip_address,
            )
        )
        return token

    async def refresh(self, refresh_token: str, client: ClientInfo) -> Session:
        """Rotate: the presented token is revoked and a new pair issued.

        The revoke is a conditional UPDATE so two concurrent refreshes with
        the same token cannot both succeed. A token that was already rotated
        (revoked but not yet expired) is evidence that it leaked, because the
        legitimate client only ever holds the newest token in its family; the
        whole family is revoked so neither party keeps the session.
        """
        now = utcnow()
        token_hash = hash_refresh_token(refresh_token)
        result = await self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_(None),
                RefreshToken.expires_at > now,
            )
            .values(revoked_at=now)
            .returning(RefreshToken.user_id, RefreshToken.family_id)
        )
        row = result.one_or_none()
        if row is None:
            await self.db.rollback()
            await self._revoke_family_on_reuse(token_hash, now)
            raise AuthError("Invalid or expired refresh token")
        user_id, family_id = row
        new_refresh = self._new_refresh_token(user_id, family_id, client)
        await self.db.commit()
        access = create_access_token(self.settings, user_id)
        return Session(user_id=user_id, access_token=access, refresh_token=new_refresh)

    async def _revoke_family_on_reuse(self, token_hash: str, now: datetime) -> None:
        reused = await self.db.execute(
            select(RefreshToken.user_id, RefreshToken.family_id).where(
                RefreshToken.token_hash == token_hash,
                RefreshToken.revoked_at.is_not(None),
                RefreshToken.expires_at > now,
            )
        )
        row = reused.one_or_none()
        if row is None:
            return
        user_id, family_id = row
        await self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.family_id == family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
        await self.db.commit()
        logger.warning(
            "refresh token reuse detected; revoked session family for user %s",
            user_id,
        )

    async def revoke_refresh_token(self, refresh_token: str) -> None:
        await self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.token_hash == hash_refresh_token(refresh_token),
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=utcnow())
        )


async def purge_expired_auth_rows(db: AsyncSession) -> None:
    """Delete expired refresh tokens and passkey challenges.

    Revoked-but-unexpired refresh tokens are deliberately kept: they are what
    lets :meth:`AuthService.refresh` recognise a replayed token.
    """
    now = utcnow()
    await db.execute(delete(RefreshToken).where(RefreshToken.expires_at <= now))
    await db.execute(
        delete(WebAuthnChallenge).where(WebAuthnChallenge.expires_at <= now)
    )
