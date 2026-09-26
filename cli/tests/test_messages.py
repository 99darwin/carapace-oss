"""User-facing messages: server error details and the audit summary."""

from __future__ import annotations

import httpx
import pytest

from carapace_cli.audit import AuditReport
from carapace_cli.errors import ServerError
from carapace_cli.session import MAX_DETAIL_CHARS, authenticate, raise_for_status

SECRET = "Hunter2-Hunter2!"  # a test value that must never be echoed


def server_error(status: int, **body: object) -> ServerError:
    response = httpx.Response(status, json=body)
    with pytest.raises(ServerError) as caught:
        raise_for_status(response)
    return caught.value


def test_validation_details_name_the_field_and_rule() -> None:
    error = server_error(
        422,
        detail=[
            {
                "type": "value_error",
                "loc": ["body", "password"],
                "msg": "Value error, password must contain a digit",
                "input": SECRET,
                "ctx": {"error": SECRET},
            },
            {"type": "missing", "loc": ["body", "email"], "msg": "Field required"},
        ],
    )
    assert error.status == 422
    assert str(error) == (
        "server returned 422: body.password: Value error, password must "
        "contain a digit; body.email: Field required"
    )
    assert SECRET not in str(error)


def test_register_422_surfaces_the_detail() -> None:
    def reject(request: httpx.Request) -> httpx.Response:
        body = {"detail": [{"loc": ["body", "password"], "msg": "too short"}]}
        return httpx.Response(422, json=body)

    with pytest.raises(ServerError, match="body.password: too short"):
        authenticate(
            "https://server.test",
            "a@example.com",
            SECRET,
            register=True,
            transport=httpx.MockTransport(reject),
        )


def test_details_are_stripped_of_control_characters_and_truncated() -> None:
    error = server_error(
        422, detail=[{"loc": ["body", "x\x1b[31m"], "msg": "bad\r\n" + "y" * 500}]
    )
    assert "\x1b" not in error.detail and "\r" not in error.detail
    assert "\n" not in error.detail
    assert len(error.detail) == MAX_DETAIL_CHARS
    assert error.detail.endswith("...")
    plain = server_error(400, detail="no\x07 bell\x9b")
    assert plain.detail == "no? bell?"


@pytest.mark.parametrize(
    "detail",
    [None, 42, {"msg": "x"}, [], [{"loc": ["body"], "input": SECRET}], ["text"]],
)
def test_unusable_details_fall_back_to_the_reason(detail: object) -> None:
    error = server_error(422, detail=detail)
    assert error.detail == "Unprocessable Entity"
    assert SECRET not in str(error)


@pytest.mark.parametrize(
    ("report", "expected"),
    [
        (
            AuditReport(receipts=2, boots=1),
            "OK: 2 receipts from 1 attested boot verified, 0 gaps",
        ),
        (
            AuditReport(receipts=1, boots=2, gaps=1),
            "OK: 1 receipt from 2 attested boots verified, 1 gap "
            "(other owners' receipts, or withheld)",
        ),
        (
            AuditReport(receipts=0, boots=0, gaps=3, failures=["x"]),
            "FAILED: 0 receipts from 0 attested boots verified, 3 gaps "
            "(other owners' receipts, or withheld)",
        ),
    ],
)
def test_audit_summary_is_pluralised(report: AuditReport, expected: str) -> None:
    assert report.summary() == expected
