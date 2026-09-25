"""FastAPI dependencies for bearer-token authentication."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from carapace_server.auth.models import User
from carapace_server.auth.tokens import (
    InvalidTokenError,
    decode_access_token,
    is_blacklisted,
)
from carapace_server.config import Settings
from carapace_server.db import DbSession

_bearer = HTTPBearer(auto_error=False)


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings


AppSettings = Annotated[Settings, Depends(get_app_settings)]


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)],
    db: DbSession,
    settings: AppSettings,
) -> User:
    if credentials is None:
        raise _unauthorized()
    try:
        claims = decode_access_token(settings, credentials.credentials)
    except InvalidTokenError:
        raise _unauthorized() from None
    if await is_blacklisted(db, claims.jti):
        raise _unauthorized()
    user = await db.get(User, claims.user_id)
    if user is None:
        raise _unauthorized()
    return user


CurrentUser = Annotated[User, Depends(get_current_user)]
