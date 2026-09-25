"""/v1/auth routes. Error messages are deliberately generic."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from carapace_server.auth import schemas
from carapace_server.auth.deps import AppSettings, CurrentUser
from carapace_server.auth.service import AuthError, AuthService, ClientInfo, Session
from carapace_server.auth.tokens import (
    InvalidTokenError,
    blacklist_token,
    decode_access_token,
)
from carapace_server.db import DbSession
from carapace_server.ratelimit import limiter

router = APIRouter(prefix="/v1/auth", tags=["auth"])


def get_auth_service(db: DbSession, settings: AppSettings) -> AuthService:
    return AuthService(db, settings)


Service = Annotated[AuthService, Depends(get_auth_service)]


def _client(request: Request) -> ClientInfo:
    return ClientInfo(
        user_agent=request.headers.get("user-agent"),
        ip_address=request.client.host if request.client else None,
    )


def _tokens(session: Session, settings: AppSettings) -> schemas.TokenResponse:
    return schemas.TokenResponse(
        user_id=session.user_id,
        access_token=session.access_token,
        refresh_token=session.refresh_token,
        expires_in=settings.access_token_minutes * 60,
    )


def _fail(code: int, detail: str) -> HTTPException:
    return HTTPException(status_code=code, detail=detail)


@router.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def register(
    request: Request,
    body: schemas.RegisterRequest,
    service: Service,
    settings: AppSettings,
) -> schemas.TokenResponse:
    try:
        session = await service.register_with_password(
            body.email, body.password, body.display_name, _client(request)
        )
    except AuthError:
        raise _fail(status.HTTP_400_BAD_REQUEST, "Registration failed") from None
    return _tokens(session, settings)


@router.post("/login")
@limiter.limit("10/minute")
async def login(
    request: Request,
    body: schemas.LoginRequest,
    service: Service,
    settings: AppSettings,
) -> schemas.TokenResponse:
    try:
        session = await service.login_with_password(
            body.email, body.password, _client(request)
        )
    except AuthError:
        raise _fail(status.HTTP_401_UNAUTHORIZED, "Invalid credentials") from None
    return _tokens(session, settings)


@router.post("/passkey/register/options")
@limiter.limit("5/minute")
async def passkey_register_options(
    request: Request, body: schemas.PasskeyOptionsRequest, service: Service
) -> schemas.PasskeyOptionsResponse:
    try:
        options = await service.registration_options(body.email)
    except AuthError:
        raise _fail(status.HTTP_400_BAD_REQUEST, "Unable to process request") from None
    return schemas.PasskeyOptionsResponse(options=options)


@router.post("/passkey/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/minute")
async def passkey_register(
    request: Request,
    body: schemas.PasskeyRegisterRequest,
    service: Service,
    settings: AppSettings,
) -> schemas.TokenResponse:
    try:
        session = await service.register_with_passkey(
            body.email, body.display_name, body.credential, _client(request)
        )
    except AuthError:
        raise _fail(status.HTTP_400_BAD_REQUEST, "Registration failed") from None
    return _tokens(session, settings)


@router.post("/passkey/login/options")
@limiter.limit("10/minute")
async def passkey_login_options(
    request: Request, body: schemas.PasskeyOptionsRequest, service: Service
) -> schemas.PasskeyOptionsResponse:
    options = await service.authentication_options(body.email)
    return schemas.PasskeyOptionsResponse(options=options)


@router.post("/passkey/login")
@limiter.limit("10/minute")
async def passkey_login(
    request: Request,
    body: schemas.PasskeyLoginRequest,
    service: Service,
    settings: AppSettings,
) -> schemas.TokenResponse:
    try:
        session = await service.login_with_passkey(
            body.email, body.credential, _client(request)
        )
    except AuthError:
        raise _fail(status.HTTP_401_UNAUTHORIZED, "Invalid credentials") from None
    return _tokens(session, settings)


@router.post("/refresh")
@limiter.limit("60/minute")
async def refresh(
    request: Request,
    body: schemas.RefreshRequest,
    service: Service,
    settings: AppSettings,
) -> schemas.TokenResponse:
    try:
        session = await service.refresh(body.refresh_token, _client(request))
    except AuthError:
        raise _fail(
            status.HTTP_401_UNAUTHORIZED, "Invalid or expired refresh token"
        ) from None
    return _tokens(session, settings)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("10/minute")
async def logout(
    request: Request,
    body: schemas.LogoutRequest,
    service: Service,
    db: DbSession,
    settings: AppSettings,
) -> None:
    """Revoke the refresh token and, if given, blacklist the access token.

    Expired access tokens are accepted here (signature still verified) so a
    client can always log out cleanly.
    """
    await service.revoke_refresh_token(body.refresh_token)
    if body.access_token:
        try:
            claims = decode_access_token(settings, body.access_token, verify_exp=False)
        except InvalidTokenError:
            claims = None
        if claims is not None:
            await blacklist_token(db, claims)
    await db.commit()


@router.get("/me")
async def me(user: CurrentUser) -> schemas.UserResponse:
    return schemas.UserResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        has_password=user.password_hash is not None,
        has_passkey=user.passkey_credential_id is not None,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )
