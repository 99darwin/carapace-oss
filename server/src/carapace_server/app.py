"""FastAPI application factory.

Run with ``uvicorn carapace_server.app:create_app --factory``.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable

from fastapi import FastAPI, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from carapace_server.apikeys.router import router as api_keys_router
from carapace_server.attestation import AttestationVerifier
from carapace_server.auth.router import router as auth_router
from carapace_server.auth.service import dummy_password_hash, purge_expired_auth_rows
from carapace_server.auth.tokens import purge_expired_blacklist
from carapace_server.config import Settings, get_settings
from carapace_server.db import create_engine, create_sessionmaker
from carapace_server.internal.router import router as internal_router
from carapace_server.ownerkeys.router import router as owner_keys_router
from carapace_server.ratelimit import limiter
from carapace_server.receipts.router import router as receipts_router
from carapace_server.store.router import router as secrets_router

logger = logging.getLogger(__name__)

Purger = Callable[[AsyncSession], Awaitable[None]]
PURGERS: tuple[Purger, ...] = (purge_expired_auth_rows, purge_expired_blacklist)


async def run_cleanup(sessionmaker: async_sessionmaker[AsyncSession]) -> None:
    """Delete expired sessions, challenges and blacklist rows."""
    async with sessionmaker() as db:
        for purge in PURGERS:
            await purge(db)
        await db.commit()


async def _cleanup_loop(
    sessionmaker: async_sessionmaker[AsyncSession], interval_seconds: int
) -> None:
    while True:
        try:
            await run_cleanup(sessionmaker)
        except Exception:
            logger.exception("periodic cleanup failed")
        await asyncio.sleep(interval_seconds)


@contextlib.asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    engine = create_engine(settings.database_url)
    app.state.sessionmaker = create_sessionmaker(engine)
    # Pay the dummy-hash cost now rather than on the first failed login.
    await asyncio.to_thread(dummy_password_hash, settings.bcrypt_rounds)
    cleanup = asyncio.create_task(
        _cleanup_loop(app.state.sessionmaker, settings.cleanup_interval_seconds)
    )
    try:
        yield
    finally:
        cleanup.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await cleanup
        await engine.dispose()


async def _validation_error(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    """422 without echoing the rejected input.

    FastAPI's default handler returns each offending value, which would
    reflect passwords back and can hold text that is not valid UTF-8.
    """
    errors = [
        {"type": e.get("type"), "loc": e.get("loc"), "msg": e.get("msg")}
        for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content={"detail": jsonable_encoder(errors)},
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    docs_url = "/docs" if settings.mode == "dev" else None
    app = FastAPI(
        title="Carapace server",
        lifespan=_lifespan,
        docs_url=docs_url,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_url else None,
    )
    app.state.settings = settings
    limiter.enabled = settings.rate_limit_enabled
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_exception_handler(RequestValidationError, _validation_error)
    app.state.attestation_verifier = AttestationVerifier(settings)
    routers = (
        auth_router,
        owner_keys_router,
        secrets_router,
        api_keys_router,
        receipts_router,
        internal_router,
    )
    for router in routers:
        app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    return app
