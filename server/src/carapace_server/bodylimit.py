"""Cap request bodies before any route buffers or parses one.

FastAPI reads the whole body into memory and then parses it as JSON, and
neither it nor uvicorn bounds the size. Without a cap, one request with a
multi-gigabyte body (or a chunked body with no ``Content-Length``) ties up
memory and CPU before any validator runs. This is a pure ASGI middleware so
the cap also covers bodies read by dependencies, such as the ``/internal``
request-signature check.
"""

from __future__ import annotations

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

TOO_LARGE_DETAIL = "Request body too large"


class RequestBodyTooLarge(HTTPException):
    """Raised from ``receive`` once the body exceeds the cap.

    An ``HTTPException`` because FastAPI turns any other error raised while
    it reads a body into a generic 400; this one it re-raises, so the
    app's normal handler answers 413.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail=TOO_LARGE_DETAIL)


class BodySizeLimitMiddleware:
    """Reject requests whose body exceeds ``max_bytes`` with 413.

    A ``Content-Length`` above the cap is refused before the body is read.
    Bodies without one (chunked) are counted as they stream, so the app
    never buffers more than ``max_bytes`` plus one chunk.
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive")
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        if _declared_length(scope) > self.max_bytes:
            await _too_large(scope, receive, send)
            return

        received = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise RequestBodyTooLarge
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except RequestBodyTooLarge:
            # Only reached when the body was read outside the app's own
            # exception handling; otherwise the app has already answered.
            if response_started:
                raise
            await _too_large(scope, receive, send)


def _declared_length(scope: Scope) -> int:
    value = Headers(scope=scope).get("content-length", "")
    return int(value) if value.isdigit() else 0


async def _too_large(scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse(status_code=413, content={"detail": TOO_LARGE_DETAIL})
    await response(scope, receive, send)
