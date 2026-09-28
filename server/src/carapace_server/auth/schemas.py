"""Request and response bodies for /v1/auth."""

from __future__ import annotations

import re
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

PASSWORD_MIN_LENGTH = 12
PASSWORD_MAX_LENGTH = 128
SETUP_TOKEN_MAX_LENGTH = 256
_PASSWORD_RULES = (
    (r"[A-Z]", "an uppercase letter"),
    (r"[a-z]", "a lowercase letter"),
    (r"\d", "a digit"),
    (r"[^A-Za-z0-9]", "a special character"),
)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RegisterRequest(_Strict):
    email: EmailStr
    password: str = Field(
        min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH
    )
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    # Required for the first account unless the server allows signup.
    setup_token: str | None = Field(
        default=None, min_length=1, max_length=SETUP_TOKEN_MAX_LENGTH
    )

    @field_validator("password")
    @classmethod
    def _strong_password(cls, value: str) -> str:
        for pattern, label in _PASSWORD_RULES:
            if not re.search(pattern, value):
                raise ValueError(f"password must contain {label}")
        return value


class LoginRequest(_Strict):
    email: EmailStr
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class PasskeyOptionsRequest(_Strict):
    email: EmailStr


class PasskeyOptionsResponse(BaseModel):
    options: dict[str, Any]


class PasskeyRegisterRequest(_Strict):
    email: EmailStr
    display_name: str | None = Field(default=None, min_length=1, max_length=100)
    # PublicKeyCredential JSON from navigator.credentials.create().
    credential: dict[str, Any]
    setup_token: str | None = Field(
        default=None, min_length=1, max_length=SETUP_TOKEN_MAX_LENGTH
    )


class PasskeyLoginRequest(_Strict):
    email: EmailStr
    # PublicKeyCredential JSON from navigator.credentials.get().
    credential: dict[str, Any]


class RefreshRequest(_Strict):
    refresh_token: str = Field(min_length=1, max_length=256)


class LogoutRequest(_Strict):
    refresh_token: str = Field(min_length=1, max_length=256)
    # Optional: also revoke this access token immediately.
    access_token: str | None = Field(default=None, min_length=1, max_length=4096)


class TokenResponse(BaseModel):
    user_id: uuid.UUID
    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - OAuth token type, not a secret
    expires_in: int


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    display_name: str | None
    has_password: bool
    has_passkey: bool
    created_at: datetime
    last_login_at: datetime | None
